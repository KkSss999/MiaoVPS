//! 服务器部署与配置
//!
//! 通过 SSH 远程管理 VPS：环境检测、WireGuard 安装、配置、Peer 管理。
//! 不在服务器安装长期 Agent。

pub mod detect;
pub mod deploy;
pub mod error;

pub use detect::*;
pub use deploy::*;
pub use error::*;
