/**
 * 设置页 —— 对齐原型 desktop.html 的 #page-settings
 *
 * 原型的「凭据策略/默认参数」是静态展示。这里显示真实值，
 * 并补一块 CLI 可用性检查 —— 隧道控制依赖它，缺了必须让用户知道。
 */

import { Alert } from '@/components/States'
import { Pill } from '@/components/Pill'
import { useTheme } from '@/hooks/useTheme'
import { useAppInfo, useProfile, useTunnel } from '@/hooks/useTunnel'
import { formatDate } from '@/lib/format'

export function SettingsPage() {
  const { theme, setTheme } = useTheme()
  const { data: info } = useAppInfo()
  const { data: profile } = useProfile()
  const { data: tunnel } = useTunnel()

  return (
    <div className="page-inner">
      <div className="page-header">
        <h2>设置</h2>
      </div>

      {info && !info.cli_available && (
        <Alert tone="err" title="未检测到 miaovps 命令行工具">
          隧道的建立和断开由独立的 root 进程完成，需要先安装 CLI：
          <br />
          <code className="num selectable" style={{ fontSize: 12 }}>
            cargo install --path crates/miaovps-cli
          </code>
        </Alert>
      )}

      <div className="bento">
        {/* ── 本机连接 ── */}
        <div className="card hoverable span-3">
          <p style={{ fontWeight: 600, marginBottom: 14 }}>本机连接</p>
          {profile?.exists ? (
            <div className="stack" style={{ gap: 12 }}>
              <Row label="服务器">
                <span className="num truncate selectable">{profile.server_endpoint}</span>
              </Row>
              <Row label="本机地址">
                <span className="num">{profile.client_ip}</span>
              </Row>
              <Row label="网关">
                <span className="num">{profile.peer_ip}</span>
              </Row>
              <Row label="MTU">
                <span className="num">{profile.mtu}</span>
              </Row>
              <Row label="DNS">
                <span className="num truncate">{profile.dns.join(', ') || '—'}</span>
              </Row>
              <Row label="密钥自洽">
                <Pill tone={profile.key_consistent ? 'ok' : 'err'}>
                  {profile.key_consistent ? '正常' : '不匹配'}
                </Pill>
              </Row>
            </div>
          ) : (
            <p className="meta">尚未配置。在设备页面选一台设备「设为本机连接」。</p>
          )}
        </div>

        {/* ── 凭据策略 ── */}
        <div className="card hoverable span-3">
          <p style={{ fontWeight: 600, marginBottom: 14 }}>凭据策略</p>
          <div className="stack" style={{ gap: 12 }}>
            <Row label="SSH 凭据">
              <span className="meta">本地文件 0600</span>
            </Row>
            <Row label="设备私钥">
              <span className="meta">系统 Keychain</span>
            </Row>
            <Row label="本机隧道私钥">
              <span className="meta">profile.json 0600</span>
            </Row>
            <Row label="提权方式">
              <span className="meta">连接时系统授权</span>
            </Row>
          </div>
          <p className="hint" style={{ marginTop: 12 }}>
            隧道私钥存文件而非 Keychain：连接进程以 root 运行，
            访问的是 root 的 Keychain，读不到用户态写入的密钥。
          </p>
        </div>

        {/* ── 默认参数 ── */}
        <div className="card hoverable span-3">
          <p style={{ fontWeight: 600, marginBottom: 14 }}>部署默认参数</p>
          <div className="stack" style={{ gap: 12 }}>
            <Row label="WireGuard 端口">
              <span className="num">51820</span>
            </Row>
            <Row label="VPN 子网">
              <span className="num">10.66.66.0/24</span>
            </Row>
            <Row label="默认 DNS">
              <span className="num">1.1.1.1, 8.8.8.8</span>
            </Row>
            <Row label="默认 MTU">
              <span className="num">1380</span>
            </Row>
          </div>
          <p className="hint" style={{ marginTop: 12 }}>
            MTU 必须与服务端 wg0 一致，否则大包会被静默丢弃
            （症状是「ping 通但传文件卡死」）。
          </p>
        </div>

        {/* ── 主题 ── */}
        <div className="card hoverable span-3">
          <p style={{ fontWeight: 600, marginBottom: 14 }}>主题</p>
          <div className="row" style={{ gap: 10 }} role="group" aria-label="主题">
            <button
              className={`btn ${theme === 'light' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setTheme('light')}
              aria-pressed={theme === 'light'}
            >
              浅色
            </button>
            <button
              className={`btn ${theme === 'dark' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setTheme('dark')}
              aria-pressed={theme === 'dark'}
            >
              深色
            </button>
          </div>
        </div>

        {/* ── 关于 ── */}
        <div className="card hoverable span-6">
          <p style={{ fontWeight: 600, marginBottom: 14 }}>关于</p>
          <div className="kv-grid">
            <div className="kv">
              <span className="meta">版本</span>
              <span className="num">MiaoVPS v{info?.version ?? '0.1.0'}</span>
            </div>
            <div className="kv">
              <span className="meta">数据目录</span>
              <span className="num truncate selectable" title={info?.data_dir}>
                {info?.data_dir ?? '—'}
              </span>
            </div>
            <div className="kv">
              <span className="meta">CLI 路径</span>
              <span className="num truncate selectable" title={info?.cli_path ?? undefined}>
                {info?.cli_path ?? '未安装'}
              </span>
            </div>
            {tunnel && tunnel.started_at > 0 && (
              <div className="kv">
                <span className="meta">本次连接开始于</span>
                <span className="num">{formatDate(tunnel.started_at)}</span>
              </div>
            )}
          </div>
          <p className="hint" style={{ marginTop: 14 }}>
            本地优先的私人 VPN 客户端 · 无需注册账户 · 无中心服务器。
            所有数据只存在这台机器上，节点是你自己的 VPS。
          </p>
        </div>
      </div>
    </div>
  )
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="row-between" style={{ minWidth: 0 }}>
      <span style={{ flexShrink: 0 }}>{label}</span>
      <span style={{ minWidth: 0, textAlign: 'right' }}>{children}</span>
    </div>
  )
}
