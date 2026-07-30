/**
 * 本机隧道状态钩子
 *
 * 隧道进程每 5s 刷一次状态文件，所以前端 2s 轮询已经足够及时，
 * 再快只是重复读同一份内容。
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useRef, useState } from 'react'
import * as api from '@/ipc/commands'
import type { TunnelMode, TunnelState } from '@/ipc/types'
import { qk } from './useServers'

const POLL_MS = 2000

export function useTunnel() {
  return useQuery({
    queryKey: qk.tunnel,
    queryFn: api.tunnelStatus,
    refetchInterval: POLL_MS,
    // 窗口没聚焦也要继续轮询 —— 用户可能在别的窗口等着看连上没
    refetchIntervalInBackground: true,
  })
}

export function useProfile() {
  return useQuery({
    queryKey: qk.profile,
    queryFn: api.profileSummary,
  })
}

export function useAppInfo() {
  return useQuery({
    queryKey: qk.appInfo,
    queryFn: api.appInfo,
    staleTime: Infinity,
  })
}

export function useTunnelConnect() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (mode: TunnelMode) => api.tunnelConnect(mode),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.tunnel }),
  })
}

export function useTunnelDisconnect() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: api.tunnelDisconnect,
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.tunnel }),
  })
}

/** 把某台设备设为本机连接配置 */
export function useUseDeviceAsLocal() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: api.useDeviceAsLocal,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.profile })
      qc.invalidateQueries({ queryKey: qk.tunnel })
    },
  })
}

/**
 * 由累计流量推算瞬时速率
 *
 * 后端只给累计 tx/rx（boringtun 的统计就是累计值），速率必须前端差分。
 * 用状态文件的 updated_at 而不是本地时钟做分母 —— 隧道进程刷新间隔
 * 未必精确等于前端轮询间隔，用本地时钟会把速率算偏。
 */
export function useThroughput(state: TunnelState | undefined) {
  const prev = useRef<{ tx: number; rx: number; at: number } | null>(null)
  const [rate, setRate] = useState({ up: 0, down: 0 })
  const [history, setHistory] = useState<{ up: number; down: number }[]>([])

  useEffect(() => {
    if (!state || state.status === 'disconnected' || state.status === 'stale') {
      prev.current = null
      setRate({ up: 0, down: 0 })
      return
    }

    const cur = { tx: state.tx_bytes, rx: state.rx_bytes, at: state.updated_at }
    const last = prev.current

    // 同一份快照重复读到（前端轮询快于隧道刷新）时不更新，
    // 否则 dt=0 会把速率算成 Infinity
    if (last && cur.at > last.at) {
      const dt = cur.at - last.at
      const up = Math.max(0, (cur.tx - last.tx) / dt)
      const down = Math.max(0, (cur.rx - last.rx) / dt)
      setRate({ up, down })
      // sparkline 只留最近 12 个点，与原型的折线点数一致
      setHistory((h) => [...h.slice(-11), { up, down }])
      prev.current = cur
    } else if (!last) {
      prev.current = cur
    }
  }, [state])

  return { rate, history }
}
