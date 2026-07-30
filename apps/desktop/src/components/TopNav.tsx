/**
 * 顶部导航 —— 无侧边栏，pill 高亮当前项（brand-spec 姿态规则 1）
 *
 * 右侧节点胶囊显示当前隧道状态，是全局唯一的常驻状态指示。
 */

import { NavLink } from 'react-router-dom'
import { DevicesIcon, HomeIcon, NodesIcon, SettingsIcon } from './Icons'
import type { TunnelState } from '@/ipc/types'
import logo from '@/assets/logo-mark.png'

const NAV = [
  { to: '/', label: '首页', Icon: HomeIcon },
  { to: '/nodes', label: '节点', Icon: NodesIcon },
  { to: '/devices', label: '设备', Icon: DevicesIcon },
  { to: '/settings', label: '设置', Icon: SettingsIcon },
]

interface Props {
  tunnel: TunnelState | undefined
  nodeName: string | null
}

export function TopNav({ tunnel, nodeName }: Props) {
  const { dotClass, text } = nodeIndicator(tunnel, nodeName)

  return (
    <header className="topnav">
      <div className="brand">
        <img src={logo} alt="" />
        <span>MiaoVPS</span>
      </div>

      <nav className="topnav-nav" aria-label="主导航">
        {NAV.map(({ to, label, Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
          >
            <Icon />
            <span className="nav-label">{label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="topnav-right">
        <div className="topnav-node" title={text}>
          <span className={`dot ${dotClass}`} aria-hidden />
          <span className="meta truncate" style={{ color: 'var(--fg)', maxWidth: 200 }}>
            {text}
          </span>
        </div>
      </div>
    </header>
  )
}

/** 状态点 + 文字双重编码 —— 不靠颜色单独区分状态 */
function nodeIndicator(
  tunnel: TunnelState | undefined,
  nodeName: string | null,
): { dotClass: string; text: string } {
  const name = nodeName ?? '未配置节点'
  switch (tunnel?.status) {
    case 'connected':
      return { dotClass: '', text: `${name} · 已连接` }
    case 'connecting':
      return { dotClass: '', text: `${name} · 连接中` }
    case 'reconnecting':
      return { dotClass: 'err', text: `${name} · 重连中` }
    case 'fallback_direct':
      return { dotClass: 'err', text: `${name} · 已回落直连` }
    case 'stale':
      return { dotClass: 'err', text: `${name} · 异常退出` }
    case 'external':
      return { dotClass: '', text: `${name} · 已连接（终端）` }
    default:
      return { dotClass: 'off', text: `${name} · 未连接` }
  }
}
