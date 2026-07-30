/** 应用骨架 —— 顶部导航 + 路由出口 */

import { useMemo } from 'react'
import { Route, Routes } from 'react-router-dom'
import { TopNav } from '@/components/TopNav'
import { HomePage } from '@/pages/HomePage'
import { NodesPage } from '@/pages/NodesPage'
import { DevicesPage } from '@/pages/DevicesPage'
import { SettingsPage } from '@/pages/SettingsPage'
import { useProfile, useTunnel } from '@/hooks/useTunnel'
import { useServers } from '@/hooks/useServers'

export function App() {
  const { data: tunnel } = useTunnel()
  const { data: profile } = useProfile()
  const { data: servers } = useServers()

  // 顶栏显示当前隧道对应的节点名 —— profile 只有 endpoint，要反查
  const nodeName = useMemo(() => {
    if (!profile?.exists || !servers) return null
    const host = profile.server_endpoint.split(':')[0]
    return servers.find((s) => s.public_ipv4 === host || s.host === host)?.name ?? host ?? null
  }, [profile, servers])

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
