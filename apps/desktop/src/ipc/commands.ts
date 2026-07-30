/**
 * Tauri command 封装
 *
 * 唯一与 Rust 后端通信的地方。所有 invoke 调用都收敛在这里，
 * 组件只用类型化的函数 —— 改命令名不必满仓库搜字符串。
 */

import { invoke } from '@tauri-apps/api/core'
import type {
  AppInfo,
  DeploymentOptions,
  DeploymentProgress,
  Device,
  DeviceType,
  ErrorDto,
  ProfileSummary,
  Server,
  ServerReport,
  SshAuthType,
  TunnelMode,
  TunnelState,
  WireGuardNode,
} from './types'

/**
 * 前端统一错误类型
 *
 * Tauri 把 command 的 Err 原样序列化过来，所以 catch 到的是 ErrorDto
 * 而不是 Error 实例。这里包一层，让 UI 能用 instanceof 判断。
 */
export class IpcError extends Error {
  readonly code: string

  constructor(dto: ErrorDto) {
    super(dto.message)
    this.name = 'IpcError'
    this.code = dto.code
  }
}

/** 判断未知错误是否是已知错误码 */
export function isIpcError(e: unknown, code?: string): e is IpcError {
  if (!(e instanceof IpcError)) return false
  return code === undefined || e.code === code
}

/**
 * 包一层 invoke：把 Rust 的 ErrorDto 转成 IpcError
 *
 * Tauri 的 reject 值可能是 ErrorDto、字符串（panic 信息），
 * 甚至是网络层错误，三种都要能得到一个可读的 message。
 */
async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(cmd, args)
  } catch (raw) {
    if (raw && typeof raw === 'object' && 'code' in raw && 'message' in raw) {
      throw new IpcError(raw as ErrorDto)
    }
    throw new IpcError({
      code: 'other',
      message: typeof raw === 'string' ? raw : `未知错误: ${String(raw)}`,
    })
  }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Server
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

export function listServers(): Promise<Server[]> {
  return call('list_servers')
}

export interface AddServerInput {
  name: string
  host: string
  port: number
  user: string
  authType: SshAuthType
  /** 密码认证时填 */
  password?: string
  /** 私钥认证时填 */
  keyPath?: string
  passphrase?: string
}

export function addServer(input: AddServerInput): Promise<Server> {
  return call('add_server', {
    name: input.name,
    host: input.host,
    port: input.port,
    user: input.user,
    authType: input.authType,
    password: input.password ?? null,
    keyPath: input.keyPath ?? null,
    passphrase: input.passphrase ?? null,
  })
}

export function removeServer(serverId: string): Promise<void> {
  return call('remove_server', { serverId })
}

export function inspectServer(serverId: string): Promise<ServerReport> {
  return call('inspect_server', { serverId })
}

/**
 * 部署 WireGuard
 *
 * 进度经 `deploy-progress` 事件推送，见 events.ts。
 * 这个 Promise 要跑几十秒才 resolve。
 */
export function deployServer(
  serverId: string,
  options?: DeploymentOptions | null,
): Promise<DeploymentProgress> {
  return call('deploy_server', { serverId, options: options ?? null })
}

/** 远端 `wg show wg0` 的原始输出 */
export function serverStatus(serverId: string): Promise<string> {
  return call('server_status', { serverId })
}

export function getWgNode(serverId: string): Promise<WireGuardNode | null> {
  return call('get_wg_node', { serverId })
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Device
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

export function listDevices(serverId: string): Promise<Device[]> {
  return call('list_devices', { serverId })
}

export interface AddDeviceResult {
  device: Device
  /** 完整 WireGuard 客户端配置（含私钥，不要落日志） */
  config: string
}

export function addDevice(
  serverId: string,
  name: string,
  deviceType: DeviceType,
): Promise<AddDeviceResult> {
  return call('add_device', { serverId, name, deviceType })
}

export function removeDevice(deviceId: string): Promise<void> {
  return call('remove_device', { deviceId })
}

export function exportConfig(deviceId: string): Promise<string> {
  return call('export_config', { deviceId })
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  本机隧道
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

export function tunnelStatus(): Promise<TunnelState> {
  return call('tunnel_status')
}

/** 弹系统授权框拉起 root 隧道进程 */
export function tunnelConnect(mode: TunnelMode): Promise<TunnelState> {
  return call('tunnel_connect', { mode })
}

export function tunnelDisconnect(): Promise<void> {
  return call('tunnel_disconnect')
}

/** 本机连接配置概要 */
export function profileSummary(): Promise<ProfileSummary> {
  return call('profile_summary')
}

/**
 * 用某台设备的配置初始化本机 profile
 *
 * 把设备的私钥/地址/服务器公钥写进 profile.json，
 * 之后 tunnel_connect 才能工作。
 */
export function useDeviceAsLocal(deviceId: string): Promise<ProfileSummary> {
  return call('use_device_as_local', { deviceId })
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  杂项
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

export function appInfo(): Promise<AppInfo> {
  return call('app_info')
}

/** 把配置写到用户选定的路径 */
export function saveConfigFile(path: string, contents: string): Promise<void> {
  return call('save_config_file', { path, contents })
}
