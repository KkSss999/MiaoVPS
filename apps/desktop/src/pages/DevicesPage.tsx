/**
 * 设备页 —— 设备网格 + 详情 + 导出配置 + 设为本机连接
 *
 * 对齐原型 desktop.html 的 #page-devices。原型只有卡片和详情，
 * 这里多一个「设为本机连接」——它是从「已部署」到「一键连接」的桥。
 */

import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { save } from '@tauri-apps/plugin-dialog'
import { writeText } from '@tauri-apps/plugin-clipboard-manager'
import { Pill, type PillTone } from '@/components/Pill'
import { Alert, EmptyState, ErrorState, SkeletonCard } from '@/components/States'
import { CopyIcon, DownloadIcon, LinkIcon, PlusIcon } from '@/components/Icons'
import { useToast } from '@/components/Toast'
import { AddDeviceModal } from './AddDeviceModal'
import { useDevices, useRemoveDevice, useServers, useWgNode } from '@/hooks/useServers'
import { useProfile, useUseDeviceAsLocal } from '@/hooks/useTunnel'
import * as api from '@/ipc/commands'
import { DEVICE_TYPE_LABELS, type Device } from '@/ipc/types'
import { formatBytes, formatDate, formatRelative, keyFingerprint, stripMask } from '@/lib/format'

export function DevicesPage() {
  const toast = useToast()
  const { data: servers, isLoading: serversLoading } = useServers()
  const [serverId, setServerId] = useState<string | null>(null)
  const [selected, setSelected] = useState<string | null>(null)
  const [showAdd, setShowAdd] = useState(false)

  // 默认选第一台服务器
  useEffect(() => {
    if (!serverId && servers && servers.length > 0) setServerId(servers[0]!.id)
  }, [servers, serverId])

  const { data: devices, isLoading, error, refetch } = useDevices(serverId)
  const { data: node } = useWgNode(serverId)
  const { data: profile } = useProfile()
  const removeDevice = useRemoveDevice(serverId)
  const setLocal = useUseDeviceAsLocal()

  const selectedDevice = useMemo(
    () => devices?.find((d) => d.id === selected) ?? null,
    [devices, selected],
  )

  async function onExport(device: Device) {
    try {
      const config = await api.exportConfig(device.id)
      const path = await save({
        title: '导出 WireGuard 配置',
        defaultPath: `${device.name.replace(/[^\w一-龥-]/g, '_')}.conf`,
        filters: [{ name: 'WireGuard 配置', extensions: ['conf'] }],
      })
      if (!path) return
      await api.saveConfigFile(path, config)
      toast.success('配置已导出（文件权限 0600，内含私钥请勿外传）')
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '导出失败')
    }
  }

  async function onCopy(device: Device) {
    try {
      const config = await api.exportConfig(device.id)
      await writeText(config)
      toast.success('配置已复制到剪贴板（含私钥）')
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '复制失败')
    }
  }

  async function onSetLocal(device: Device) {
    if (profile?.exists) {
      const ok = window.confirm(
        `把「${device.name}」设为本机连接？\n\n` +
          `当前本机配置（${profile.client_ip} @ ${profile.server_endpoint}）会被覆盖。`,
      )
      if (!ok) return
    }
    try {
      await setLocal.mutateAsync(device.id)
      toast.success('本机连接已配置，可以回首页一键连接了')
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '设置失败')
    }
  }

  async function onRemove(device: Device) {
    const ok = window.confirm(
      `删除设备「${device.name}」？\n\n` +
        '本地记录会被清除，但 VPS 上的 peer 需要手动移除：\n' +
        `sudo wg set wg0 peer ${device.public_key} remove`,
    )
    if (!ok) return
    try {
      await removeDevice.mutateAsync(device.id)
      if (selected === device.id) setSelected(null)
      toast.success(`已删除 ${device.name}`)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '删除失败')
    }
  }

  if (serversLoading) {
    return (
      <div className="page-inner">
        <div className="page-header">
          <h2>设备管理</h2>
        </div>
        <SkeletonCard lines={2} />
      </div>
    )
  }

  if (!servers || servers.length === 0) {
    return (
      <div className="page-inner">
        <div className="page-header">
          <h2>设备管理</h2>
        </div>
        <EmptyState
          title="先添加一个节点"
          hint="设备需要挂在已部署 WireGuard 的节点上。"
          action={
            <Link className="btn btn-primary" to="/nodes">
              去添加节点
            </Link>
          }
        />
      </div>
    )
  }

  const deployed = !!node

  return (
    <div className="page-inner">
      <div className="page-header">
        <h2>设备管理</h2>
        <div className="row" style={{ gap: 8 }}>
          {servers.length > 1 && (
            <select
              value={serverId ?? ''}
              onChange={(e) => {
                setServerId(e.target.value)
                setSelected(null)
              }}
              aria-label="选择节点"
              style={{
                padding: '8px 12px',
                borderRadius: 'var(--radius)',
                border: '1px solid var(--border)',
                background: 'var(--bg)',
                color: 'var(--fg)',
                fontSize: 13,
              }}
            >
              {servers.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name}
                </option>
              ))}
            </select>
          )}
          <button
            className="btn btn-primary"
            onClick={() => setShowAdd(true)}
            disabled={!deployed}
            title={deployed ? undefined : '该节点尚未部署 WireGuard'}
          >
            <PlusIcon style={{ width: 14, height: 14 }} />
            添加设备
          </button>
        </div>
      </div>

      {!deployed && (
        <Alert tone="warn" title="该节点尚未部署 WireGuard">
          添加设备需要先知道服务器公钥和监听端口。
          <Link to="/nodes" style={{ textDecoration: 'underline' }}>
            {' '}
            去部署
          </Link>
        </Alert>
      )}

      {error ? (
        <ErrorState
          title="无法读取设备列表"
          message={error instanceof Error ? error.message : String(error)}
          onRetry={() => refetch()}
        />
      ) : isLoading ? (
        <SkeletonCard lines={3} />
      ) : !devices || devices.length === 0 ? (
        <EmptyState
          title="还没有设备"
          hint="每台设备有独立的密钥和 VPN 地址。添加后会自动注册到服务端 peer 列表。"
          action={
            deployed ? (
              <button className="btn btn-primary" onClick={() => setShowAdd(true)}>
                添加第一台设备
              </button>
            ) : undefined
          }
        />
      ) : (
        <div className="bento">
          {devices.map((device) => {
            const isLocal =
              profile?.exists && profile.client_ip === stripMask(device.vpn_address)
            return (
              <button
                key={device.id}
                className={`card hoverable clickable span-3 stack${selected === device.id ? ' selected' : ''}`}
                style={{ gap: 12 }}
                onClick={() => setSelected(selected === device.id ? null : device.id)}
                aria-pressed={selected === device.id}
              >
                <div className="row-between">
                  <span style={{ fontWeight: 600 }} className="truncate">
                    {device.name}
                  </span>
                  <DeviceStatusPill device={device} />
                </div>
                <p className="num meta truncate">
                  {stripMask(device.vpn_address)} · {formatRelative(device.latest_handshake_at)}
                </p>
                <p className="num meta">
                  ↓{formatBytes(device.rx_bytes)} ↑{formatBytes(device.tx_bytes)}
                </p>
                <div className="row" style={{ gap: 6 }}>
                  <span className="tag">{DEVICE_TYPE_LABELS[device.device_type]}</span>
                  {isLocal && <span className="tag">本机</span>}
                </div>
              </button>
            )
          })}
        </div>
      )}

      {/* ── 设备详情 ── */}
      {selectedDevice && (
        <div className="card hoverable">
          <p className="row-between" style={{ marginBottom: 16 }}>
            <span style={{ fontWeight: 600 }}>{selectedDevice.name} · 详情</span>
            <DeviceStatusPill device={selectedDevice} />
          </p>
          <div className="kv-grid">
            <Kv label="虚拟 IP" value={selectedDevice.vpn_address} />
            <Kv label="公钥指纹" value={keyFingerprint(selectedDevice.public_key)} />
            <Kv label="创建时间" value={formatDate(selectedDevice.created_at)} />
            <Kv label="DNS" value={node?.dns.join(', ') ?? '—'} />
            <Kv label="MTU" value={node?.mtu ? String(node.mtu) : '1380'} />
            <Kv label="AllowedIPs" value="0.0.0.0/0" />
          </div>
          <hr className="rule" style={{ margin: '18px 0' }} />
          <div className="row" style={{ gap: 10, flexWrap: 'wrap' }}>
            <button
              className="btn btn-primary"
              onClick={() => onSetLocal(selectedDevice)}
              disabled={setLocal.isPending}
            >
              {setLocal.isPending && <span className="spinner" aria-hidden />}
              <LinkIcon style={{ width: 14, height: 14 }} />
              设为本机连接
            </button>
            <button className="btn btn-secondary" onClick={() => onExport(selectedDevice)}>
              <DownloadIcon style={{ width: 14, height: 14 }} />
              导出配置 (.conf)
            </button>
            <button className="btn btn-secondary" onClick={() => onCopy(selectedDevice)}>
              <CopyIcon style={{ width: 14, height: 14 }} />
              复制配置
            </button>
            <button
              className="btn btn-danger"
              onClick={() => onRemove(selectedDevice)}
              disabled={removeDevice.isPending}
              style={{ marginLeft: 'auto' }}
            >
              删除设备
            </button>
          </div>
          <p className="hint" style={{ marginTop: 12 }}>
            配置文件含客户端私钥。「设为本机连接」会把私钥写入本机 profile
            以便一键连接；导出的 .conf 用于手机等其他设备的官方 WireGuard 客户端。
          </p>
        </div>
      )}

      {showAdd && serverId && (
        <AddDeviceModal serverId={serverId} onClose={() => setShowAdd(false)} />
      )}
    </div>
  )
}

function DeviceStatusPill({ device }: { device: Device }) {
  const { tone, label } = describeDevice(device)
  return <Pill tone={tone}>{label}</Pill>
}

/**
 * 设备状态 —— 与 Rust 的 Device::status() 判定保持一致
 *
 * 阈值来自 miaovps_core：3 分钟内算在线，30 分钟内算最近活跃。
 */
function describeDevice(device: Device): { tone: PillTone; label: string } {
  if (!device.enabled) return { tone: 'off', label: '已禁用' }
  if (!device.latest_handshake_at) return { tone: 'off', label: '从未连接' }
  const age = Math.floor(Date.now() / 1000) - device.latest_handshake_at
  if (age < 180) return { tone: 'ok', label: '在线' }
  if (age < 1800) return { tone: 'warn', label: '最近在线' }
  return { tone: 'off', label: '离线' }
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
