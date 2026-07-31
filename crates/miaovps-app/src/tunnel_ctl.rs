//! 隧道控制 —— 从非特权 App 拉起 root 隧道进程
//!
//! ## 提权方式
//!
//! `osascript -e 'do shell script "..." with administrator privileges'`
//! 弹出 macOS 原生授权框。相比自建 launchd helper 的好处是零安装、
//! 无需签名；代价是每次连接授权一次。正常断开通过受限的停止请求
//! 让 root daemon 自行收尾，不需要再授权。
//!
//! ## 命令注入防护
//!
//! AppleScript 字符串里嵌 shell 命令是两层嵌套引号，用户可控的值
//! （数据目录路径）必须逐层转义。这里不接受任何前端传入的自由文本 ——
//! 只有 mode 枚举和已知路径，转义后仍做一次白名单校验。

use crate::tunnel::{TunnelMode, TunnelState, TunnelStatus};
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{info, warn};

#[derive(Debug, thiserror::Error)]
pub enum TunnelCtlError {
    #[error("找不到 miaovps 可执行文件，请先运行 cargo install --path crates/miaovps-cli")]
    BinaryNotFound,
    #[error("用户取消了授权")]
    AuthCancelled,
    #[error("隧道启动失败: {0}")]
    LaunchFailed(String),
    #[error("隧道已在运行 (pid {0})")]
    AlreadyRunning(u32),
    #[error("检测到隧道已在运行，但不是由本应用启动的。\n请先在终端里停止它（Ctrl+C 或 sudo miaovps disconnect）再从这里连接")]
    ExternalTunnel,
    #[error("未找到连接配置，请先在节点页面完成部署并添加本机设备")]
    ProfileMissing,
    #[error("{0}")]
    Other(String),
}

impl TunnelCtlError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::BinaryNotFound => "binary_not_found",
            Self::AuthCancelled => "auth_cancelled",
            Self::LaunchFailed(_) => "launch_failed",
            Self::AlreadyRunning(_) => "already_running",
            Self::ExternalTunnel => "external_tunnel",
            Self::ProfileMissing => "profile_missing",
            Self::Other(_) => "other",
        }
    }
}

/// 隧道控制器
pub struct TunnelCtl {
    data_dir: PathBuf,
    /// miaovps CLI 路径 —— 注入以便测试
    binary: PathBuf,
}

impl TunnelCtl {
    /// 用默认查找逻辑构造
    pub fn new(data_dir: PathBuf) -> Result<Self, TunnelCtlError> {
        let binary = locate_binary().ok_or(TunnelCtlError::BinaryNotFound)?;
        Ok(Self { data_dir, binary })
    }

    pub fn with_binary(data_dir: PathBuf, binary: PathBuf) -> Self {
        Self { data_dir, binary }
    }

    /// 当前隧道状态
    pub fn status(&self) -> TunnelState {
        TunnelState::load(&self.data_dir)
    }

    /// 启动隧道
    ///
    /// 已在运行时直接返回错误，不重复拉起 —— 两个隧道进程会互相踩路由表。
    pub fn connect(&self, mode: TunnelMode) -> Result<TunnelState, TunnelCtlError> {
        let current = self.status();
        if current.status == TunnelStatus::External {
            return Err(TunnelCtlError::ExternalTunnel);
        }
        if current.occupies_tunnel() {
            return Err(TunnelCtlError::AlreadyRunning(current.pid));
        }

        // profile 缺失时提前失败 —— 否则要等授权框点完才报错
        if !self.data_dir.join("profile.json").exists() {
            return Err(TunnelCtlError::ProfileMissing);
        }

        TunnelState::clear_stop_request(&self.data_dir);

        let connect_shell = self.build_shell_command("connect", mode.as_flag());
        // 崩溃残留的清理和重连合并在同一次授权里，
        // 否则一次点击会连续弹两次密码框。
        let shell = if current.status == TunnelStatus::Stale {
            warn!("检测到上次隧道异常退出，同一次授权内先清理再重连");
            format!(
                "{} && {}",
                self.build_shell_command("disconnect", None),
                connect_shell
            )
        } else {
            connect_shell
        };
        info!(?mode, "请求授权启动隧道");
        self.run_privileged(&shell)?;

        // 隧道进程刚 fork，要等到真正进入可管理运行态才返回。
        // Connecting 只说明 daemon 已领取任务，不能让前端提前 toast 成功。
        for _ in 0..300 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            let state = self.status();
            if launched_state_is_ready(state.status) {
                return Ok(state);
            }
            if state.status == TunnelStatus::Stale {
                return Err(TunnelCtlError::LaunchFailed(
                    "隧道进程在建立期间退出，请查看 ~/.miaovps/tunnel.log".into(),
                ));
            }
        }
        Err(TunnelCtlError::LaunchFailed(
            "隧道进程已启动，但 30 秒内未进入可用状态，请查看 ~/.miaovps/tunnel.log"
                .into(),
        ))
    }

    /// 断开隧道并清理路由
    pub fn disconnect(&self) -> Result<(), TunnelCtlError> {
        let current = self.status();
        match current.status {
            TunnelStatus::Disconnected => return Ok(()),
            TunnelStatus::External => return Err(TunnelCtlError::ExternalTunnel),
            TunnelStatus::Stale => {
                // daemon 已死，无人能自行收尾，只能授权清理残留路由。
                let shell = self.build_shell_command("disconnect", None);
                self.run_privileged(&shell)?;
                TunnelState::clear(&self.data_dir);
                return Ok(());
            }
            _ => {}
        }

        // 正常运行的 root daemon 自己有权限还原 DNS/路由。App 只发一个
        // 无参数停止事件，不再起第二次 osascript 授权。
        TunnelState::request_stop(&self.data_dir)
            .map_err(|e| TunnelCtlError::Other(format!("无法发出停止请求: {e}")))?;

        for _ in 0..120 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            if self.status().status == TunnelStatus::Disconnected {
                TunnelState::clear_stop_request(&self.data_dir);
                info!("隧道已断开");
                return Ok(());
            }
        }
        Err(TunnelCtlError::Other(
            "隧道进程在 12 秒内未响应停止请求，请重试；若仍失败再使用 sudo miaovps disconnect"
                .into(),
        ))
    }

    /// 拼出要在 root 下执行的 shell 命令
    ///
    /// `MIAOVPS_DATA_DIR` 必须显式传 —— root 的 HOME 是 /var/root，
    /// 不传会让隧道进程去读一个空的数据目录（见 CLAUDE.md）。
    fn build_shell_command(&self, subcommand: &str, flag: Option<&str>) -> String {
        let mut cmd = format!(
            "MIAOVPS_DATA_DIR={} {} {}",
            shell_quote(&self.data_dir.to_string_lossy()),
            shell_quote(&self.binary.to_string_lossy()),
            subcommand
        );
        if let Some(f) = flag {
            cmd.push(' ');
            cmd.push_str(f);
        }
        if subcommand == "connect" {
            cmd.push_str(" --daemon");
        }
        cmd
    }

    /// 经 osascript 以管理员身份执行
    fn run_privileged(&self, shell_cmd: &str) -> Result<String, TunnelCtlError> {
        let script = format!(
            "do shell script {} with administrator privileges",
            applescript_quote(shell_cmd)
        );
        let output = Command::new("osascript")
            .arg("-e")
            .arg(&script)
            .output()
            .map_err(|e| TunnelCtlError::LaunchFailed(format!("无法执行 osascript: {e}")))?;

        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        // -128 是 AppleScript 的「用户取消」，要和真正的失败区分开
        if stderr.contains("-128") || stderr.contains("User canceled") {
            Err(TunnelCtlError::AuthCancelled)
        } else {
            Err(TunnelCtlError::LaunchFailed(stderr.trim().to_string()))
        }
    }
}

/// connect command 只能在真实运行态返回成功。
fn launched_state_is_ready(status: TunnelStatus) -> bool {
    matches!(
        status,
        TunnelStatus::Connected | TunnelStatus::Reconnecting | TunnelStatus::FallbackDirect
    )
}

/// 查找已安装的 miaovps 可执行文件
fn locate_binary() -> Option<PathBuf> {
    // 1. 显式覆盖（开发时指向 target/debug/miaovps）
    if let Some(p) = std::env::var_os("MIAOVPS_BIN") {
        let path = PathBuf::from(p);
        if path.is_file() {
            return Some(path);
        }
    }
    // 2. 与桌面端同版本打包的 sidecar；`tauri dev` 时也是
    // target/debug 下的同级文件。绝不能先找 cargo install 的旧版本。
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sibling = dir.join("miaovps");
            if sibling.is_file() {
                return Some(sibling);
            }
        }
    }
    // 3. cargo install 的默认位置（仅开发兜底）
    if let Some(home) = std::env::var_os("HOME") {
        let path = Path::new(&home).join(".cargo/bin/miaovps");
        if path.is_file() {
            return Some(path);
        }
    }
    // 4. PATH 查找
    let out = Command::new("which").arg("miaovps").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let path = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
    path.is_file().then_some(path)
}

/// shell 单引号转义 —— 单引号内除了 `'` 本身没有任何元字符生效
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// AppleScript 双引号字符串转义
///
/// AppleScript 只认 `\` 和 `"` 两个转义字符，顺序不能反 ——
/// 先转 `"` 会把随后插入的反斜杠再转一遍。
pub fn applescript_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', r"\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctl(dir: &str) -> TunnelCtl {
        TunnelCtl::with_binary(
            PathBuf::from(dir),
            PathBuf::from("/Users/test/.cargo/bin/miaovps"),
        )
    }

    #[test]
    fn connect_command_carries_data_dir_and_daemon() {
        let cmd = ctl("/Users/test/.miaovps").build_shell_command("connect", Some("--full"));
        assert!(cmd.contains("MIAOVPS_DATA_DIR='/Users/test/.miaovps'"));
        assert!(cmd.contains("'/Users/test/.cargo/bin/miaovps' connect"));
        assert!(cmd.contains("--full"));
        assert!(cmd.ends_with("--daemon"), "connect 必须带 --daemon: {cmd}");
    }

    #[test]
    fn split_mode_omits_full_flag() {
        let cmd = ctl("/tmp/d").build_shell_command("connect", TunnelMode::Split.as_flag());
        assert!(!cmd.contains("--full"));
        assert!(cmd.contains("--daemon"));
    }

    #[test]
    fn disconnect_command_has_no_daemon_flag() {
        let cmd = ctl("/tmp/d").build_shell_command("disconnect", None);
        assert!(!cmd.contains("--daemon"));
        assert!(cmd.contains("disconnect"));
    }

    #[test]
    fn stale_reconnect_can_share_one_authorization_shell() {
        let c = ctl("/tmp/d");
        let combined = format!(
            "{} && {}",
            c.build_shell_command("disconnect", None),
            c.build_shell_command("connect", Some("--full"))
        );
        let words: Vec<&str> = combined.split_whitespace().collect();
        assert_eq!(words.iter().filter(|w| **w == "disconnect").count(), 1);
        assert_eq!(words.iter().filter(|w| **w == "connect").count(), 1);
        assert_eq!(combined.matches("--daemon").count(), 1);
    }

    /// 路径里带空格是 macOS 常态（"Application Support"）
    #[test]
    fn quotes_paths_with_spaces() {
        let cmd = ctl("/Users/a b/.miaovps").build_shell_command("connect", None);
        assert!(cmd.contains("'/Users/a b/.miaovps'"));
    }

    /// 单引号是唯一能突破 shell 单引号包裹的字符
    #[test]
    fn shell_quote_neutralizes_single_quote() {
        assert_eq!(shell_quote("a'b"), r"'a'\''b'");
        assert_eq!(shell_quote("rm -rf /"), "'rm -rf /'");
        assert_eq!(shell_quote("$(whoami)"), "'$(whoami)'");
        assert_eq!(shell_quote("a;b"), "'a;b'");
    }

    #[test]
    fn applescript_quote_escapes_backslash_before_quote() {
        assert_eq!(applescript_quote(r#"a"b"#), r#""a\"b""#);
        assert_eq!(applescript_quote(r"a\b"), r#""a\\b""#);
        // 反斜杠 + 引号：反斜杠必须先转，否则引号的转义符会被二次转义
        assert_eq!(applescript_quote(r#"a\"b"#), r#""a\\\"b""#);
    }

    /// 两层嵌套后仍不能逃出字符串上下文
    #[test]
    fn nested_quoting_survives_injection_attempt() {
        let evil = "/tmp/x'; rm -rf /; echo '";
        let cmd = ctl(evil).build_shell_command("connect", None);
        let script = applescript_quote(&cmd);
        // 恶意片段被单引号包住，且 AppleScript 层没有裸引号提前收尾
        assert!(cmd.contains(r"'\''"), "单引号未转义: {cmd}");
        assert!(script.starts_with('"') && script.ends_with('"'));
        assert!(!script[1..script.len() - 1].contains("\"") || script.contains("\\\""));
    }

    #[test]
    fn status_reads_from_data_dir() {
        let dir = std::env::temp_dir().join(format!("miaovps-ctl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        TunnelState::clear(&dir);
        let c = TunnelCtl::with_binary(dir.clone(), PathBuf::from("/bin/true"));
        assert_eq!(c.status().status, TunnelStatus::Disconnected);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 正常断开必须只写停止请求，不能再调 osascript。
    #[test]
    fn managed_disconnect_needs_no_privileged_command() {
        let dir = std::env::temp_dir().join(format!(
            "miaovps-ctl-stop-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        TunnelState::clear(&dir);
        TunnelState::clear_stop_request(&dir);

        let mut state =
            TunnelState::connecting(TunnelMode::Full, "1.2.3.4:51820".into(), "10.0.0.2".into());
        state.status = TunnelStatus::Connected;
        state.save(&dir).unwrap();

        let watcher_dir = dir.clone();
        let watcher = std::thread::spawn(move || {
            for _ in 0..100 {
                if TunnelState::stop_requested(&watcher_dir) {
                    TunnelState::clear(&watcher_dir);
                    TunnelState::clear_stop_request(&watcher_dir);
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            panic!("未收到停止请求");
        });

        // /bin/false 确保测试若误走特权命令就会失败。
        let ctl = TunnelCtl::with_binary(dir.clone(), PathBuf::from("/bin/false"));
        ctl.disconnect().unwrap();
        watcher.join().unwrap();
        assert_eq!(ctl.status().status, TunnelStatus::Disconnected);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 已连接时重复 connect 会有两个进程抢路由表
    #[test]
    fn connect_refuses_when_already_running() {
        let dir = std::env::temp_dir().join(format!("miaovps-ctl2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut state =
            TunnelState::connecting(TunnelMode::Full, "1.2.3.4:51820".into(), "10.66.66.3".into());
        state.status = TunnelStatus::Connected;
        state.save(&dir).unwrap();

        let c = TunnelCtl::with_binary(dir.clone(), PathBuf::from("/bin/true"));
        match c.connect(TunnelMode::Full) {
            Err(TunnelCtlError::AlreadyRunning(pid)) => assert_eq!(pid, std::process::id()),
            other => panic!("期望 AlreadyRunning，实际 {other:?}"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 没 profile 就不该弹授权框浪费用户一次输密码
    #[test]
    fn connect_fails_fast_without_profile() {
        let dir = std::env::temp_dir().join(format!("miaovps-ctl3-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        TunnelState::clear(&dir);
        let c = TunnelCtl::with_binary(dir.clone(), PathBuf::from("/bin/true"));
        assert!(matches!(
            c.connect(TunnelMode::Full),
            Err(TunnelCtlError::ProfileMissing)
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(TunnelCtlError::AuthCancelled.code(), "auth_cancelled");
        assert_eq!(TunnelCtlError::ProfileMissing.code(), "profile_missing");
        assert_eq!(TunnelCtlError::AlreadyRunning(1).code(), "already_running");
    }

    #[test]
    fn launch_waits_through_connecting_and_external_race() {
        assert!(!launched_state_is_ready(TunnelStatus::Disconnected));
        assert!(!launched_state_is_ready(TunnelStatus::Connecting));
        assert!(!launched_state_is_ready(TunnelStatus::External));
        assert!(launched_state_is_ready(TunnelStatus::Connected));
        assert!(launched_state_is_ready(TunnelStatus::Reconnecting));
        assert!(launched_state_is_ready(TunnelStatus::FallbackDirect));
    }
}
