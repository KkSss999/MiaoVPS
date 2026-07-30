//! 应用服务层 — Tauri IPC 边界
//!
//! CLI 与 Tauri 前端共用的业务逻辑层。
//! 所有公开方法的入参和返回值均实现 serde::Serialize/Deserialize，
//! 可直接作为 Tauri IPC 命令的参数和返回类型。

pub mod credentials;
pub mod service;
pub mod session;
pub mod tunnel;
pub mod tunnel_ctl;

pub use service::AppService;
pub use session::{ErrorDto, ServiceError};
pub use tunnel::{TunnelMode, TunnelState, TunnelStatus};
pub use tunnel_ctl::{TunnelCtl, TunnelCtlError};
