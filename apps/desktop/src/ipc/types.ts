/**
 * Rust DTO 的 TypeScript 镜像
 *
 * 这些类型必须与 crates/miaovps-core、miaovps-provisioner、miaovps-app
 * 的 serde 表示逐字段对齐。Rust 侧枚举都带 #[serde(rename_all = "snake_case")]，
 * 所以这里用 snake_case 字面量联合类型。
 *
 * 改 Rust 结构时必须同步改这里 —— 没有代码生成，靠约定。
 */

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  错误
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/** miaovps_app::session::ErrorDto */
export interface ErrorDto {
  code: string
  message: string
}

/** 已知错误码 —— 前端按码分支，不要匹配 message 文案 */
export type ErrorCode =
  | 'app_error'
  | 'ssh_error'
  | 'credential_error'
  | 'storage_error'
  | 'server_not_found'
  | 'device_not_found'
  | 'wg_node_not_found'
  | 'binary_not_found'
  | 'auth_cancelled'
  | 'launch_failed'
  | 'already_running'
  | 'external_tunnel'
  | 'profile_missing'
  | 'other'

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Server
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/** miaovps_core::SshAuthType */
export type SshAuthType = 'password' | 'private_key' | 'ssh_agent'

/** miaovps_core::ServerStatus */
export type ServerStatus =
  | 'added'
  | 'detecting'
  | 'ready'
  | 'deploying'
  | 'online'
  | 'offline'
  | 'config_broken'
  | 'needs_attention'

/** miaovps_core::Server */
export interface Server {
  id: string
  name: string
  host: string
  ssh_port: number
  ssh_user: string
  auth_type: SshAuthType
  credential_ref: string | null
  os_name: string | null
  os_version: string | null
  architecture: string | null
  public_ipv4: string | null
  status: ServerStatus
  created_at: number
  updated_at: number
}

/** miaovps_core::WireGuardNode */
export interface WireGuardNode {
  server_id: string
  interface_name: string
  listen_port: number
  vpn_cidr: string
  server_public_key: string
  dns: string[]
  mtu: number | null
  ipv6_enabled: boolean
  service_status: string
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  环境检测
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/** miaovps_provisioner::DetectKey */
export type DetectKey =
  | 'os'
  | 'arch'
  | 'privilege'
  | 'public_ipv4'
  | 'wire_guard'
  | 'systemd'
  | 'ip_forward'
  | 'firewall'
  | 'udp_port'
  | 'disk'
  | 'memory'

/** miaovps_provisioner::DetectStatus */
export type DetectStatus = 'Pass' | 'Warning' | 'Blocked'

/** miaovps_provisioner::DetectItem */
export interface DetectItem {
  key: DetectKey
  name: string
  status: DetectStatus
  message: string
  suggestion: string | null
}

/** miaovps_provisioner::ServerReport */
export interface ServerReport {
  server_id: string
  items: DetectItem[]
  all_passed: boolean
  blocked: boolean
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  部署
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/** miaovps_core::DeploymentStep —— 9 步，顺序即部署顺序 */
export type DeploymentStep =
  | 'Detect'
  | 'Backup'
  | 'Install'
  | 'GenerateKeys'
  | 'WriteConfig'
  | 'ConfigureRouting'
  | 'StartService'
  | 'VerifyHandshake'
  | 'Complete'

/** 部署步骤的中文标签 —— 与 Rust 的 DeploymentStep::label() 一致 */
export const STEP_LABELS: Record<DeploymentStep, string> = {
  Detect: '环境检测',
  Backup: '备份现有配置',
  Install: '安装 WireGuard',
  GenerateKeys: '生成密钥',
  WriteConfig: '写入配置',
  ConfigureRouting: '配置路由与 NAT',
  StartService: '启动 WireGuard 服务',
  VerifyHandshake: '验证握手',
  Complete: '完成',
}

/** 部署步骤的固定顺序 —— UI 按此渲染，不依赖事件到达顺序 */
export const STEP_ORDER: DeploymentStep[] = [
  'Detect',
  'Backup',
  'Install',
  'GenerateKeys',
  'WriteConfig',
  'ConfigureRouting',
  'StartService',
  'VerifyHandshake',
  'Complete',
]

/**
 * miaovps_provisioner::StepResult
 *
 * Rust 侧是带数据的枚举，serde 默认外部标签表示：
 *   Pending / Running / Success 是裸字符串，
 *   Warning(String) / Failed(String) 是 { "Warning": "..." }
 */
export type StepResult =
  | 'Pending'
  | 'Running'
  | 'Success'
  | { Warning: string }
  | { Failed: string }

export type StepResultKind = 'pending' | 'running' | 'success' | 'warning' | 'failed'

/** 把 StepResult 归一成 kind + 详情，避免 UI 里到处做类型窄化 */
export function parseStepResult(r: StepResult | undefined): {
  kind: StepResultKind
  detail: string | null
} {
  if (r === undefined) return { kind: 'pending', detail: null }
  if (r === 'Pending') return { kind: 'pending', detail: null }
  if (r === 'Running') return { kind: 'running', detail: null }
  if (r === 'Success') return { kind: 'success', detail: null }
  if ('Warning' in r) return { kind: 'warning', detail: r.Warning }
  if ('Failed' in r) return { kind: 'failed', detail: r.Failed }
  return { kind: 'pending', detail: null }
}

/** miaovps_core::DeploymentStatus */
export type DeploymentStatus = 'pending' | 'in_progress' | 'success' | 'failed' | 'rolled_back'

/** miaovps_provisioner::DeploymentProgress */
export interface DeploymentProgress {
  server_id: string
  status: DeploymentStatus
  current_step: DeploymentStep | null
  steps: Partial<Record<DeploymentStep, StepResult>>
  server_public_key: string | null
  started_at: number
  finished_at: number | null
}

/** miaovps_provisioner::StepEvent —— 经 emit("deploy-progress") 推送 */
export interface StepEvent {
  step: DeploymentStep
  result: StepResult
}

/** miaovps_provisioner::DeploymentOptions */
export interface DeploymentOptions {
  wireguard_port: number
  vpn_cidr: string
  dns: string[]
  mtu: number | null
  ipv6_enabled: boolean
  routing_policy: string
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Device
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/** miaovps_core::DeviceType */
export type DeviceType = 'mac' | 'windows' | 'i_phone' | 'android' | 'linux' | 'other'

/** miaovps_core::DeviceStatus */
export type DeviceStatus = 'online' | 'recently_active' | 'offline' | 'never_connected' | 'disabled'

/** miaovps_core::Device */
export interface Device {
  id: string
  server_id: string
  name: string
  device_type: DeviceType
  public_key: string
  private_key_ref: string | null
  vpn_address: string
  enabled: boolean
  latest_handshake_at: number | null
  rx_bytes: number
  tx_bytes: number
  created_at: number
}

export const DEVICE_TYPE_LABELS: Record<DeviceType, string> = {
  mac: 'Mac',
  windows: 'Windows',
  i_phone: 'iPhone',
  android: 'Android',
  linux: 'Linux',
  other: '其他',
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  本机隧道
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/** miaovps_app::tunnel::TunnelStatus */
export type TunnelStatus =
  | 'disconnected'
  | 'connecting'
  | 'connected'
  | 'reconnecting'
  /** Full Tunnel 断线回落 —— 流量不经 VPN */
  | 'fallback_direct'
  /** 状态文件在但进程已消失 —— 路由可能还是被改写的 */
  | 'stale'
  /** 隧道在跑但不是本 App 启动的（终端里的前台 connect） */
  | 'external'

/** miaovps_app::tunnel::TunnelMode */
export type TunnelMode = 'split' | 'full'

/** miaovps_app::tunnel::TunnelState */
export interface TunnelState {
  status: TunnelStatus
  mode: TunnelMode
  pid: number
  server_endpoint: string
  client_ip: string
  started_at: number
  updated_at: number
  tx_bytes: number
  rx_bytes: number
  /** 可疑解密错误 —— 非零才代表异常 */
  decrypt_errors: number
  /** 会话轮换丢包 —— 每 120s rekey 的正常产物，不是故障 */
  session_churn: number
  reconnects: number
  session_alive: boolean
  last_error: string | null
}

/** 本机连接配置概要（不含私钥） */
export interface ProfileSummary {
  exists: boolean
  server_endpoint: string
  client_ip: string
  peer_ip: string
  client_public_key: string
  mtu: number
  dns: string[]
  /** 公私钥是否自洽 —— 不自洽时握手一定失败 */
  key_consistent: boolean
}

/** 应用信息 */
export interface AppInfo {
  version: string
  data_dir: string
  /** miaovps CLI 是否已安装（隧道控制依赖它） */
  cli_available: boolean
  cli_path: string | null
}
