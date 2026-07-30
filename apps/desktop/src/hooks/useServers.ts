/** 服务器与设备的数据钩子 —— TanStack Query 管缓存和失效 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import * as api from '@/ipc/commands'
import type { DeploymentOptions, DeviceType } from '@/ipc/types'

export const qk = {
  servers: ['servers'] as const,
  devices: (serverId: string) => ['devices', serverId] as const,
  wgNode: (serverId: string) => ['wgNode', serverId] as const,
  serverStatus: (serverId: string) => ['serverStatus', serverId] as const,
  tunnel: ['tunnel'] as const,
  profile: ['profile'] as const,
  appInfo: ['appInfo'] as const,
}

export function useServers() {
  return useQuery({
    queryKey: qk.servers,
    queryFn: api.listServers,
  })
}

export function useDevices(serverId: string | null) {
  return useQuery({
    queryKey: qk.devices(serverId ?? ''),
    queryFn: () => api.listDevices(serverId!),
    enabled: !!serverId,
  })
}

export function useWgNode(serverId: string | null) {
  return useQuery({
    queryKey: qk.wgNode(serverId ?? ''),
    queryFn: () => api.getWgNode(serverId!),
    enabled: !!serverId,
  })
}

/** 远端 wg 状态 —— 每次都要走 SSH，不自动轮询 */
export function useServerStatus(serverId: string | null, enabled: boolean) {
  return useQuery({
    queryKey: qk.serverStatus(serverId ?? ''),
    queryFn: () => api.serverStatus(serverId!),
    enabled: !!serverId && enabled,
    staleTime: 15_000,
    retry: false,
  })
}

export function useAddServer() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: api.addServer,
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.servers }),
  })
}

export function useRemoveServer() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: api.removeServer,
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.servers }),
  })
}

/** 环境检测 —— 会把 os/arch/ip 写回 Server 记录，所以要失效服务器列表 */
export function useInspectServer() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: api.inspectServer,
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.servers }),
  })
}

export function useAddDevice(serverId: string | null) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (input: { name: string; deviceType: DeviceType }) =>
      api.addDevice(serverId!, input.name, input.deviceType),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.devices(serverId ?? '') })
    },
  })
}

export function useRemoveDevice(serverId: string | null) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: api.removeDevice,
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.devices(serverId ?? '') }),
  })
}

export function useDeployServer() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (input: { serverId: string; options?: DeploymentOptions | null }) =>
      api.deployServer(input.serverId, input.options ?? null),
    onSuccess: (_, input) => {
      qc.invalidateQueries({ queryKey: qk.servers })
      qc.invalidateQueries({ queryKey: qk.wgNode(input.serverId) })
    },
  })
}
