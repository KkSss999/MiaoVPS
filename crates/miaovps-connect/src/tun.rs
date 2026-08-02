//! macOS TUN 接口管理 — 创建 utun、分配 IP、设置 MTU
//!
//! 使用 tun crate 在 macOS 上创建 UTUN 虚拟网卡。
//!
//! ## macOS utun 的两个关键约束
//!
//! 1. **4 字节地址族头**：每个 IP 包前有 4 字节 AF 头 (AF_INET = 2, AF_INET6 = 30)。
//!    读取时跳过，写入时必须附加。
//!
//! 2. **写入必须是单次 write**：utun 是字符设备，每次 `write()` 系统调用就是一个
//!    独立数据包。AF 头和 IP 包必须拼接到同一个缓冲区一次写出，
//!    分两次 `write_all` 会被内核当成两个畸形包丢弃。
//!
//! ## POINTOPOINT 语义
//!
//! utun 是点对点接口。`set_alias(addr, dst, mask)` 的第二个参数在 BSD
//! `SIOCAIFADDR` 语义下是**对端地址**（不是广播地址）。必须传 VPN 网关
//! (如 10.66.66.1)，传 255.255.255.255 会导致内核无法为对端建立路由，
//! 表现为 ping 网关不通。

use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, RawFd};
use std::time::Duration;
use tun::platform::macos::Device;
use tun::platform::posix::{Reader, Writer};
use tun::Device as _;

use crate::error::ConnectError;

/// macOS utun 的地址族头长度
const AF_HEADER_LEN: usize = 4;
/// 单个包缓冲区大小（MTU 1380 + AF 头 + 余量）
const PKT_BUF: usize = 2048;

/// TUN 接口配置
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// 本地 VPN 地址 (如 10.66.66.2)
    pub address: Ipv4Addr,
    /// 对端 VPN 地址 / 网关 (如 10.66.66.1)
    pub peer: Ipv4Addr,
    /// 子网掩码 (如 255.255.255.0)
    pub netmask: Ipv4Addr,
    /// MTU — 必须与服务端 wg0 MTU 一致，否则大包被静默丢弃
    pub mtu: u16,
}

impl TunConfig {
    /// 从字符串构造，mtu 默认 1380（与 provisioner 默认值一致）
    pub fn parse(address: &str, peer: &str, netmask: &str, mtu: u16) -> Result<Self, ConnectError> {
        Ok(Self {
            address: address
                .parse()
                .map_err(|e| ConnectError::TunError(format!("无效本地 IP '{address}': {e}")))?,
            peer: peer
                .parse()
                .map_err(|e| ConnectError::TunError(format!("无效对端 IP '{peer}': {e}")))?,
            netmask: netmask
                .parse()
                .map_err(|e| ConnectError::TunError(format!("无效掩码 '{netmask}': {e}")))?,
            mtu,
        })
    }
}

/// macOS TUN 接口
pub struct TunInterface {
    reader: Reader,
    writer: Writer,
    name: String,
    raw_fd: RawFd,
    mtu: u16,
}

impl TunInterface {
    /// 创建 TUN 接口、分配 IP、设置对端地址和 MTU
    ///
    /// 需要 root 权限。接口保持**阻塞**模式 — 数据平面使用双线程
    /// (见 `native::NativeTunnel`)，阻塞读避免忙轮询。
    pub fn create(config: &TunConfig) -> Result<Self, ConnectError> {
        // 地址必须通过 Configuration 传入。`Device::new` 内部会调用一次
        // `set_alias`，缺省值是 10.0.0.1 → 10.0.0.255；事后再调 set_alias
        // 是**追加**第二个地址，会在接口上留下一个多余的 10.0.0.1 和一条
        // 10.0.0.255 主机路由（局域网用 10.0.0.x 时会劫走广播地址）。
        let mut cfg = tun::configure();
        cfg.layer(tun::Layer::L3)
            .address(config.address)
            // destination 对 POINTOPOINT 接口是对端地址 — 见模块文档
            .destination(config.peer)
            .netmask(config.netmask)
            .mtu(config.mtu as i32)
            .up();

        let device = Device::new(&cfg)
            .map_err(|e| ConnectError::TunError(format!("无法创建 TUN 接口 (需要 root): {e}")))?;

        let name = device
            .name()
            .map_err(|e| ConnectError::TunError(format!("获取接口名失败: {e}")))?;

        // 确认 MTU 真的生效 — 与服务端不一致会让大包被静默丢弃，
        // 这种故障很难从现象反推，宁可在这里直接失败
        let actual_mtu = device
            .mtu()
            .map_err(|e| ConnectError::TunError(format!("读取 MTU 失败: {e}")))?;
        if actual_mtu != config.mtu as i32 {
            return Err(ConnectError::TunError(format!(
                "{name} MTU 未生效: 期望 {}, 实际 {actual_mtu}",
                config.mtu
            )));
        }

        let raw_fd = device.as_raw_fd();
        let (reader, writer) = device.split();

        tracing::info!(
            "[TUN] {} 就绪 — {} → {} mask {} mtu {}",
            name,
            config.address,
            config.peer,
            config.netmask,
            config.mtu
        );

        Ok(Self {
            reader,
            writer,
            name,
            raw_fd,
            mtu: config.mtu,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn raw_fd(&self) -> RawFd {
        self.raw_fd
    }

    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// 拆分为独立的读写半边，供数据平面双线程使用
    pub fn into_split(self) -> (TunReader, TunWriter) {
        (
            TunReader {
                reader: self.reader,
                raw_fd: self.raw_fd,
            },
            TunWriter {
                writer: self.writer,
            },
        )
    }
}

/// TUN 读半边 — 移动到「TUN → UDP」线程
pub struct TunReader {
    reader: Reader,
    raw_fd: RawFd,
}

impl TunReader {
    /// 等待数据可读，最多 `timeout`。返回 `false` 表示超时无数据。
    ///
    /// 关闭隧道时必须能中断读取。直接 `read()` 会一直阻塞到有包进来，
    /// 而 fd 由本结构持有、要等线程退出才关闭 —— 空闲隧道上
    /// `join()` 会和 `read()` 互等，死锁。先 poll 再读避免这个环。
    pub fn wait_readable(&self, timeout: Duration) -> io::Result<bool> {
        let mut pfd = libc::pollfd {
            fd: self.raw_fd,
            events: libc::POLLIN,
            revents: 0,
        };

        // Safety: pfd 是本地有效的 pollfd，nfds=1 与之匹配
        let rc =
            unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, timeout.as_millis() as i32) };

        match rc {
            -1 => {
                let err = io::Error::last_os_error();
                // 信号打断不是故障，让调用方重试
                if err.kind() == io::ErrorKind::Interrupted {
                    Ok(false)
                } else {
                    Err(err)
                }
            }
            0 => Ok(false), // 超时
            _ => Ok(pfd.revents & libc::POLLIN != 0),
        }
    }

    /// 读取一个 IP 包，跳过 macOS 4 字节 AF 头
    ///
    /// 调用前应先用 `wait_readable` 确认有数据，否则会阻塞。
    pub fn read_packet(&mut self) -> io::Result<Vec<u8>> {
        let mut buf = [0u8; PKT_BUF];
        let n = self.reader.read(&mut buf)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "TUN 已关闭"));
        }
        Ok(strip_af_header(&buf[..n]).to_vec())
    }
}

/// TUN 写半边 — 移动到「UDP → TUN」线程
pub struct TunWriter {
    writer: Writer,
}

impl TunWriter {
    /// 写入一个 IP 包，附加 4 字节 AF 头
    ///
    /// AF 头和包体拼接后**一次** write — utun 每次 write 就是一个数据包。
    pub fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        if packet.is_empty() {
            return Ok(());
        }
        let mut framed = Vec::with_capacity(AF_HEADER_LEN + packet.len());
        framed.extend_from_slice(&af_for(packet).to_be_bytes());
        framed.extend_from_slice(packet);
        self.writer.write_all(&framed)
    }
}

/// 根据 IP 版本返回地址族常量
fn af_for(packet: &[u8]) -> u32 {
    match packet.first().map(|b| b >> 4) {
        Some(6) => libc::AF_INET6 as u32,
        _ => libc::AF_INET as u32,
    }
}

/// 剥离 macOS utun 的 4 字节地址族头
///
/// 真实 IPv4 包首字节是 0x45，作为 BE u32 读出来是 0x45000000+，
/// 不会与 AF_INET(2)/AF_INET6(30) 混淆，所以这个判断是安全的。
fn strip_af_header(buf: &[u8]) -> &[u8] {
    if buf.len() < AF_HEADER_LEN {
        return buf;
    }
    let af = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if af == libc::AF_INET as u32 || af == libc::AF_INET6 as u32 {
        &buf[AF_HEADER_LEN..]
    } else {
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_af_inet_header() {
        // AF_INET(2) + IPv4 包头起始
        let framed = [0, 0, 0, 2, 0x45, 0x00, 0x00, 0x54];
        assert_eq!(strip_af_header(&framed), &[0x45, 0x00, 0x00, 0x54]);
    }

    #[test]
    fn leaves_headerless_packet_untouched() {
        // 裸 IPv4 包 — 不应被误剥离
        let raw = [0x45, 0x00, 0x00, 0x54, 0x01, 0x02];
        assert_eq!(strip_af_header(&raw), &raw);
    }

    #[test]
    fn detects_address_family_from_version() {
        assert_eq!(af_for(&[0x45]), libc::AF_INET as u32);
        assert_eq!(af_for(&[0x60]), libc::AF_INET6 as u32);
    }

    #[test]
    fn parse_rejects_bad_address() {
        assert!(TunConfig::parse("nope", "10.66.66.1", "255.255.255.0", 1380).is_err());
        assert!(TunConfig::parse("10.66.66.2", "10.66.66.1", "255.255.255.0", 1380).is_ok());
    }
}
