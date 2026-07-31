/** 应用骨架 —— 顶部导航 + 路由出口 */

import { useEffect, useMemo } from 'react'
import { Route, Routes, useNavigate } from 'react-router-dom'
import { listen } from '@tauri-apps/api/event'
import { TopNav } from '@/components/TopNav'
import { HomePage } from '@/pages/HomePage'
import { NodesPage } from '@/pages/NodesPage'
import { DevicesPage } from '@/pages/DevicesPage'
import { SettingsPage } from '@/pages/SettingsPage'
import { useProfile, useTunnel } from '@/hooks/useTunnel'
import { useServers } from '@/hooks/useServers'
import * as api from '@/ipc/commands'
import { serverForProfile } from '@/lib/profileOwnership'

export function App() {
  const navigate = useNavigate()
  const { data: tunnel } = useTunnel()
  const { data: profile } = useProfile()
  const { data: servers } = useServers()

  // 顶栏显示当前隧道对应的节点名 —— profile 只有 endpoint，要反查
  const nodeName = useMemo(() => {
    return serverForProfile(servers, profile)?.name ?? null
  }, [profile, servers])

  // 菜单栏不接受 WebView 传来的状态，而是由 Rust 重读数据库、profile 与
  // 隧道状态。前端仅在这些查询变化时请求一次刷新。
  useEffect(() => {
    void api.refreshTrayMenu().catch(() => undefined)
  }, [servers, profile, tunnel?.status, tunnel?.updated_at])

  // 从菜单栏选节点后，唤醒窗口并把用户带到真实节点卡片；不暗中改 profile。
  useEffect(() => {
    let unlisten: (() => void) | undefined
    void listen<string>('tray-select-server', (event) => {
      navigate('/nodes', { state: { traySelectedServerId: event.payload } })
    }).then((stop) => {
      unlisten = stop
    })
    return () => unlisten?.()
  }, [navigate])

  return (
    <div className="app">
      <TopNav tunnel={tunnel} nodeName={nodeName} />
      <div className="main">
        <div className="page">
          <Routes>
            <Route path="/" element={<HomePage />} />
            <Route path="/nodes" element={<NodesPage />} />
            <Route path="/devices" element={<DevicesPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            {/* 未知路径回首页，避免白屏 */}
            <Route path="*" element={<HomePage />} />
          </Routes>
        </div>
      </div>
    </div>
  )
}
