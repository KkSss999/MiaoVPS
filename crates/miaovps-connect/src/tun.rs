//! macOS TUN 接口管理 — 创建 utun、分配 IP、设置 MTU
//!
//! 使用 tun crate 在 macOS 上创建 UTUN 虚拟网卡。
//! macOS 的 tun 读取的每个 IP 包前有 4 字节地址族头 (AF_INET = 2)。

use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, RawFd};
use tun::Device as _;
use tun::platform::macos::Device;
use tun::platform::posix::{Reader, Writer};

use crate::error::ConnectError;

/// macOS TUN 接口
pub struct TunInterface {
    reader: Reader,
    writer: Writer,
    name: String,
    raw_fd: RawFd,
}

impl TunInterface {
    /// 创建 TUN 接口并分配 IP 地址
    pub fn create(address: &str, netmask: &str) -> Result<Self, ConnectError> {
        let mut config = tun::configure();
        config.layer(tun::Layer::L3);

        let mut device = Device::new(&config).map_err(|e| {
            ConnectError::TunError(format!("无法创建 TUN 接口: {e}"))
        })?;

        let name = device.name().map_err(|e| {
            ConnectError::TunError(format!("获取接口名失败: {e}"))
        })?;

        let addr: Ipv4Addr = address.parse().map_err(|e| {
            ConnectError::TunError(format!("无效 IP: {e}"))
        })?;
        let mask: Ipv4Addr = netmask.parse().map_err(|e| {
            ConnectError::TunError(format!("无效掩码: {e}"))
        })?;

        device
            .set_alias(addr, Ipv4Addr::new(255, 255, 255, 255), mask)
            .map_err(|e| ConnectError::TunError(format!("设置 IP 失败: {e}")))?;

        let raw_fd = device.as_raw_fd();
        let (reader, writer) = device.split();

        tracing::info!("[TUN] 创建 {} — IP: {}/{}", name, address, netmask);

        Ok(Self { reader, writer, name, raw_fd })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn raw_fd(&self) -> RawFd {
        self.raw_fd
    }

    /// 从 TUN 读取一个 IP 包（阻塞），跳过 macOS 4 字节 AF_INET 头
    pub fn read_packet(&mut self) -> io::Result<Vec<u8>> {
        let mut buf = [0u8; 2048];
        let n = self.reader.read(&mut buf)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "TUN closed"));
        }
        // macOS: 前 4 字节是地址族 (AF_INET=2, AF_INET6=30)
        if n >= 4 {
            let af = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
            if af == 2 || af == 30 {
                Ok(buf[4..n].to_vec())
            } else {
                Ok(buf[..n].to_vec())
            }
        } else {
            Ok(buf[..n].to_vec())
        }
    }

    /// 写入 IP 包到 TUN（阻塞），添加 4 字节 AF_INET 头
    pub fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        if packet.is_empty() {
            return Ok(());
        }
        let af: u32 = if packet[0] >> 4 == 4 { 2 } else { 30 };
        let header = af.to_be_bytes();
        self.writer.write_all(&header)?;
        self.writer.write_all(packet)?;
        Ok(())
    }
}
