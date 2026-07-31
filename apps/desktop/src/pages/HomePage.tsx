/**
 * 首页 —— 连接状态 + 实时速率 + 节点概况
 *
 * 对齐原型 desktop.html 的 #page-home：hero 卡、双速率卡、节点资源卡。
 * 原型的 CPU/内存/磁盘是静态占位（需要 telemetry 才有真实值），
 * 这里替换成有真实数据支撑的隧道指标。
 */

import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { Pill, type PillTone } from '@/components/Pill'
import { Sparkline } from '@/components/Sparkline'
import { Alert, SkeletonCard } from '@/components/States'
import { SignalIcon } from '@/components/Icons'
import { useToast } from '@/components/Toast'
import { useProfile, useThroughput, useTunnel, useTunnelConnect, useTunnelDisconnect } from '@/hooks/useTunnel'
import { useServers } from '@/hooks/useServers'
import { isIpcError } from '@/ipc/commands'
import type { TunnelMode, TunnelState, TunnelStatus } from '@/ipc/types'
import { formatBytes, formatDuration, formatRate } from '@/lib/format'
import { serverForProfile } from '@/lib/profileOwnership'

export function HomePage() {
  const toast = useToast()
  const { data: tunnel, isLoading } = useTunnel()
  const { data: profile } = useProfile()
  const { data: servers } = useServers()
  const connect = useTunnelConnect()
  const disconnect = useTunnelDisconnect()
  const { rate, history } = useThroughput(tunnel)
  const [mode, setMode] = useState<TunnelMode>('full')

  const busy = connect.isPending || disconnect.isPending
  const view = useMemo(() => describeStatus(tunnel?.status), [tunnel?.status])

  // profile 必须能反查到当前数据库中的节点，才允许作为桌面端本机连接使用。
  const managedServer = useMemo(() => serverForProfile(servers, profile), [profile, servers])

  async function onConnect() {
    try {
      await connect.mutateAsync(mode)
      toast.success(mode === 'full' ? '已建立全局隧道' : '已建立分流隧道')
    } catch (e) {
      // 用户主动取消授权不是错误，不该弹红条
      if (isIpcError(e, 'auth_cancelled')) return
      toast.error(e instanceof Error ? e.message : '连接失败')
    }
  }

  async function onDisconnect() {
    try {
      await disconnect.mutateAsync()
      toast.success('已断开并清理路由')
    } catch (e) {
      if (isIpcError(e, 'auth_cancelled')) return
      toast.error(e instanceof Error ? e.message : '断开失败')
    }
  }

  if (isLoading) {
    return (
      <div className="page-inner">
        <SkeletonCard lines={4} />
        <SkeletonCard lines={2} />
      </div>
    )
  }

  const connected = tunnel?.status === 'connected'
  const hasProfile = profile?.exists === true
  const hasManagedProfile = hasProfile && managedServer !== null

  return (
    <div className="page-inner">
      {/* ── 未受保护警示：必须在最上方，用户不能漏看 ── */}
      {tunnel?.status === 'fallback_direct' && (
        <Alert tone="err" title="流量未经 VPN">
          隧道断开超过 30 秒，已自动回落直连以保持网络可用。当前没有隐私保护，
          隧道恢复后会自动重新接管。
        </Alert>
      )}
      {tunnel?.status === 'stale' && (
        <Alert tone="err" title="隧道进程异常退出">
          路由和 DNS 可能仍是被改写的状态。点「断开连接」执行一次清理即可恢复。
        </Alert>
      )}
      {tunnel?.status === 'external' && (
        <Alert tone="warn" title="隧道由终端启动">
          检测到 {tunnel.client_ip} 已绑在 utun 上，但不是本应用启动的，
          所以看不到流量统计。要在这里管理连接，先在终端 Ctrl+C 停掉它。
        </Alert>
      )}
      {!hasManagedProfile && (
        <Alert tone={hasProfile ? 'warn' : 'info'} title={hasProfile ? '发现未关联的旧本机配置' : '尚未配置本机连接'}>
          {hasProfile
            ? '这份 profile.json 不属于当前节点列表，因此不会被当作 VPS 或用于一键连接。请在设备页面选择当前节点的设备并设为本机连接。'
            : <>先在<Link to="/nodes" style={{ textDecoration: 'underline' }}>节点</Link>页面部署 VPS，
              再到<Link to="/devices" style={{ textDecoration: 'underline' }}>设备</Link>页面添加本机设备并设为本机连接。</>}
        </Alert>
      )}
      {hasManagedProfile && !profile.key_consistent && (
        <Alert tone="err" title="本机密钥不自洽">
          profile 中记录的公钥与私钥不匹配，握手会被服务端静默丢弃。
          请到设备页面重新设置本机连接。
        </Alert>
      )}

      {/* ── 连接 hero ── */}
      <section className={`card hero-card ${view.heroClass}`}>
        <div className="hero-row">
          <div className="hero-ring">
            <SignalIcon />
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="row" style={{ gap: 10, marginBottom: 3 }}>
              <h2 style={{ fontSize: 20 }} className="truncate">
                {managedServer?.name ?? '未配置节点'}
              </h2>
              <Pill tone={view.tone}>{view.label}</Pill>
              {tunnel?.mode && connected && (
                <span className="tag">{tunnel.mode === 'full' ? '全局' : '分流'}</span>
              )}
            </div>
            <p className="num selectable" style={{ color: 'var(--muted)', fontSize: 13 }}>
              {hasManagedProfile
                ? `${profile.server_endpoint} · ${profile.client_ip} · MTU ${profile.mtu}`
                : '添加节点后可一键连接'}
            </p>
          </div>

          {tunnel?.status === 'external' ? (
            // 外部隧道不是本 App 起的，disconnect 会去 kill 一个我们没记录 pid
            // 的进程 —— 交给用户在终端处理更可预期
            <button className="btn btn-secondary" disabled title="请在终端停止">
              终端管理中
            </button>
          ) : connected || tunnel?.status === 'reconnecting' || tunnel?.status === 'fallback_direct' ? (
            <button className="btn btn-danger" onClick={onDisconnect} disabled={busy}>
              {disconnect.isPending && <span className="spinner" aria-hidden />}
              断开连接
            </button>
          ) : (
            <div className="row" style={{ gap: 8 }}>
              <div className="segmented" role="group" aria-label="隧道模式">
                <button
                  className={mode === 'full' ? 'active' : ''}
                  onClick={() => setMode('full')}
                  disabled={busy}
                >
                  全局
                </button>
                <button
                  className={mode === 'split' ? 'active' : ''}
                  onClick={() => setMode('split')}
                  disabled={busy}
                >
                  分流
                </button>
              </div>
              <button
                className="btn btn-primary"
                onClick={tunnel?.status === 'stale' ? onDisconnect : onConnect}
                disabled={busy || !hasManagedProfile}
                title={hasManagedProfile ? undefined : '需要先配置当前节点的本机连接'}
              >
                {busy && <span className="spinner" aria-hidden />}
                {tunnel?.status === 'stale' ? '清理残留' : '连接'}
              </button>
            </div>
          )}
        </div>

        <hr className="rule" style={{ margin: '20px 0' }} />

        <div className="bento" style={{ gridTemplateColumns: 'repeat(4,1fr)' }}>
          <Metric label="连接时长" value={formatDuration(uptime(tunnel))} />
          <Metric label="已传输" value={`↓${formatBytes(tunnel?.rx_bytes ?? 0)} ↑${formatBytes(tunnel?.tx_bytes ?? 0)}`} small />
          <Metric label="重连次数" value={String(tunnel?.reconnects ?? 0)} />
          <Metric
            label="出口"
            value={hasManagedProfile ? (managedServer?.public_ipv4 ?? managedServer?.host ?? '—') : '—'}
            small
          />
        </div>
      </section>

      {/* ── 实时速率 ── */}
      <div className="bento">
        <RateCard label="下载速率" bytesPerSec={rate.down} history={history.map((h) => h.down)} />
        <RateCard label="上传速率" bytesPerSec={rate.up} history={history.map((h) => h.up)} />
      </div>

      {/* ── 隧道诊断 ── */}
      <div className="card hoverable">
        <p className="row-between" style={{ marginBottom: 16 }}>
          <span style={{ fontWeight: 600 }}>隧道诊断</span>
          <Pill tone={tunnel?.session_alive ? 'ok' : 'off'}>
            {tunnel?.session_alive ? 'WireGuard 会话存活' : '无活动会话'}
          </Pill>
        </p>
        <div className="kv-grid">
          <Kv label="本机地址" value={hasManagedProfile ? profile.client_ip : '—'} />
          <Kv label="网关" value={hasManagedProfile ? profile.peer_ip : '—'} />
          <Kv label="MTU" value={hasManagedProfile ? String(profile.mtu) : '—'} />
          <Kv label="DNS" value={hasManagedProfile && profile.dns.length ? profile.dns.join(', ') : '—'} />
          {/* 换钥丢包是每 120s rekey 的正常产物，与真正的解密错误分开显示 ——
              混在一起会让正常长连接看起来像遭到攻击 */}
          <Kv label="换钥丢包" value={`${tunnel?.session_churn ?? 0}（正常）`} />
          <Kv
            label="解密错误"
            value={(tunnel?.decrypt_errors ?? 0) === 0 ? '0' : `⚠ ${tunnel?.decrypt_errors}`}
          />
          <Kv label="隧道进程" value={tunnel?.pid ? `pid ${tunnel.pid}` : '未运行'} />
        </div>
      </div>
    </div>
  )
}

function Metric({ label, value, small }: { label: string; value: string; small?: boolean }) {
  return (
    <div className="stack" style={{ gap: 4 }}>
      <span className="meta">{label}</span>
      <span
        className="num"
        style={{ fontSize: small ? 14 : 18, fontWeight: small ? 500 : 600, color: small ? 'var(--muted)' : undefined }}
      >
        {value}
      </span>
    </div>
  )
}

function Kv({ label, value }: { label: string; value: string }) {
  return (
    <div className="kv">
      <span className="meta">{label}</span>
      <span className="num truncate selectable" title={value}>
        {value}
      </span>
    </div>
  )
}

function RateCard({
  label,
  bytesPerSec,
  history,
}: {
  label: string
  bytesPerSec: number
  history: number[]
}) {
  const { value, unit } = formatRate(bytesPerSec)
  return (
    <div className="card hoverable span-3">
      <div className="row-between" style={{ marginBottom: 4 }}>
        <span className="meta">{label}</span>
        <span className="num" style={{ fontSize: 24, fontWeight: 700 }}>
          {value}{' '}
          <span style={{ fontSize: 13, color: 'var(--muted)', fontWeight: 500 }}>{unit}</span>
        </span>
      </div>
      <Sparkline values={history} />
    </div>
  )
}

function uptime(tunnel: TunnelState | undefined): number {
  if (!tunnel?.started_at) return 0
  return Math.max(0, Math.floor(Date.now() / 1000) - tunnel.started_at)
}

function describeStatus(status: TunnelStatus | undefined): {
  tone: PillTone
  label: string
  heroClass: string
} {
  switch (status) {
    case 'connected':
      return { tone: 'ok', label: '已连接', heroClass: '' }
    case 'connecting':
      return { tone: 'busy', label: '连接中', heroClass: 'connecting' }
    case 'reconnecting':
      return { tone: 'warn', label: '重连中', heroClass: 'connecting' }
    case 'fallback_direct':
      return { tone: 'err', label: '已回落直连', heroClass: 'unprotected' }
    case 'stale':
      return { tone: 'err', label: '异常退出', heroClass: 'unprotected' }
    case 'external':
      return { tone: 'ok', label: '已连接（终端启动）', heroClass: '' }
    default:
      return { tone: 'off', label: '未连接', heroClass: 'disconnected' }
  }
}
