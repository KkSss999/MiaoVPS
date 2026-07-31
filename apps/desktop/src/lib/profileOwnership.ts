/**
 * profile.json 是 CLI 与桌面端共用的隧道配置；只有 endpoint 能在当前
 * `servers` 表中反查到，桌面端才把它当作受管节点。这样旧 CLI 配置、
 * 手工配置或已删除节点的残留文件不会凭空成为 VPS。
 */

import type { ProfileSummary, Server } from '@/ipc/types'

export function serverForProfile(
  servers: Server[] | undefined,
  profile: ProfileSummary | undefined,
): Server | null {
  if (!profile?.exists || !servers?.length) return null

  const host = endpointHost(profile.server_endpoint)
  if (!host) return null

  return servers.find((server) => server.host === host || server.public_ipv4 === host) ?? null
}

function endpointHost(endpoint: string): string | null {
  const trimmed = endpoint.trim()
  if (!trimmed) return null

  // 允许未来 profile 使用标准的 [IPv6]:port 形式；当前 IPv4/域名保持原样。
  if (trimmed.startsWith('[')) {
    const end = trimmed.indexOf(']')
    return end > 1 ? trimmed.slice(1, end) : null
  }

  return trimmed.split(':', 1)[0] || null
}
