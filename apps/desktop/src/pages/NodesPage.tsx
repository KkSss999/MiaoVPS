/**
 * 节点页 —— VPS 列表 + 环境检测 + 九步部署
 *
 * 对齐原型 desktop.html 的 #page-nodes：节点列表卡 + 部署进度卡。
 */

import { useState } from 'react'
import { useLocation } from 'react-router-dom'
import { Pill, type PillTone } from '@/components/Pill'
import { StepList } from '@/components/StepList'
import { EmptyState, ErrorState, SkeletonCard } from '@/components/States'
import { PlusIcon } from '@/components/Icons'
import { useToast } from '@/components/Toast'
import { AddServerModal } from './AddServerModal'
import { InspectModal } from './InspectModal'
import { useDeployProgress } from '@/hooks/useDeploy'
import { useDeployServer, useRemoveServer, useServers, useWgNode } from '@/hooks/useServers'
import type { Server, ServerStatus } from '@/ipc/types'

export function NodesPage() {
  const toast = useToast()
  const { data: servers, isLoading, error, refetch } = useServers()
  const [showAdd, setShowAdd] = useState(false)
  const [inspecting, setInspecting] = useState<Server | null>(null)
  const [deployTarget, setDeployTarget] = useState<Server | null>(null)
  const location = useLocation()
  const traySelectedServerId = (location.state as { traySelectedServerId?: string } | null)
    ?.traySelectedServerId

  const deploy = useDeployServer()
  const removeServer = useRemoveServer()
  const progress = useDeployProgress()

  async function onDeploy(server: Server) {
    setDeployTarget(server)
    progress.reset()
    try {
      const result = await deploy.mutateAsync({ serverId: server.id })
      if (result.status === 'success') {
        toast.success(`${server.name} 部署成功，可以添加设备了`)
      } else {
        toast.error(`${server.name} 部署未完成，见下方失败步骤`)
      }
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '部署失败')
    } finally {
      progress.finish()
    }
  }

  async function onRemove(server: Server) {
    // 删服务器会连带删掉设备记录，必须确认
    const ok = window.confirm(
      `删除节点「${server.name}」？\n\n` +
        '本地的服务器记录、设备记录和凭据都会被清除。\n' +
        'VPS 上已部署的 WireGuard 不会被卸载。',
    )
    if (!ok) return
    try {
      await removeServer.mutateAsync(server.id)
      toast.success(`已删除 ${server.name}`)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '删除失败')
    }
  }

  if (isLoading) {
    return (
      <div className="page-inner">
        <div className="page-header">
          <h2>我的节点</h2>
        </div>
        <SkeletonCard lines={2} />
        <SkeletonCard lines={2} />
      </div>
    )
  }

  if (error) {
    return (
      <div className="page-inner">
        <ErrorState
          title="无法读取节点列表"
          message={error instanceof Error ? error.message : String(error)}
          onRetry={() => refetch()}
        />
      </div>
    )
  }

  return (
    <div className="page-inner">
      <div className="page-header">
        <h2>我的节点</h2>
        <button className="btn btn-primary" onClick={() => setShowAdd(true)}>
          <PlusIcon style={{ width: 14, height: 14 }} />
          添加 VPS
        </button>
      </div>

      {!servers || servers.length === 0 ? (
        <EmptyState
          title="还没有节点"
          hint="添加一台你自己的 VPS，MiaoVPS 会通过 SSH 把它部署成 WireGuard 节点。服务器上不会安装常驻 Agent。"
          action={
            <button className="btn btn-primary" onClick={() => setShowAdd(true)}>
              添加第一台 VPS
            </button>
          }
        />
      ) : (
        <div className="bento">
          {servers.map((server) => (
            <NodeCard
              key={server.id}
              server={server}
              busy={deploy.isPending && deployTarget?.id === server.id}
              anyDeploying={deploy.isPending}
              selected={traySelectedServerId === server.id}
              onInspect={() => setInspecting(server)}
              onDeploy={() => onDeploy(server)}
              onRemove={() => onRemove(server)}
            />
          ))}
        </div>
      )}

      {/* 部署进度卡 —— 部署开始后出现，结束后保留以便查看结果 */}
      {deployTarget && (Object.keys(progress.steps).length > 0 || progress.running) && (
        <div className="card hoverable">
          <p className="row-between" style={{ marginBottom: 16 }}>
            <span className="eyebrow">{deployTarget.name} 部署进度</span>
            {progress.running ? (
              <Pill tone="busy">进行中</Pill>
            ) : (
              <button className="btn btn-ghost" onClick={() => setDeployTarget(null)}>
                收起
              </button>
            )}
          </p>
          <StepList steps={progress.steps} />
          {deploy.data?.server_public_key && !progress.running && (
            <>
              <hr className="rule" style={{ margin: '18px 0' }} />
              <div className="kv">
                <span className="meta">服务器公钥</span>
                <span className="num selectable" style={{ wordBreak: 'break-all', fontSize: 12 }}>
                  {deploy.data.server_public_key}
                </span>
              </div>
            </>
          )}
        </div>
      )}

      {showAdd && <AddServerModal onClose={() => setShowAdd(false)} />}
      {inspecting && <InspectModal server={inspecting} onClose={() => setInspecting(null)} />}
    </div>
  )
}

function NodeCard({
  server,
  busy,
  anyDeploying,
  selected,
  onInspect,
  onDeploy,
  onRemove,
}: {
  server: Server
  busy: boolean
  anyDeploying: boolean
  selected: boolean
  onInspect: () => void
  onDeploy: () => void
  onRemove: () => void
}) {
  const { data: node } = useWgNode(server.id)
  const view = describeServer(server.status, busy)
  const deployed = !!node
  const canDeploy = ['added', 'online', 'incomplete'].includes(server.status)
  const deployHint = canDeploy
    ? undefined
    : server.status === 'pending_inspection'
      ? '请先完成环境检测'
      : '检测尚未通过；请处理问题后重新检测'

  const subtitle = [
    server.public_ipv4 ?? server.host,
    server.os_name ?? undefined,
    server.architecture ?? undefined,
    deployed ? `wg 端口 ${node.listen_port}` : undefined,
  ]
    .filter(Boolean)
    .join(' · ')

  return (
    <div className={`card hoverable span-6 row-between${selected ? ' selected' : ''}`}>
      <div className="list-row" style={{ minWidth: 0, flex: 1 }}>
        <span className={`dot ${view.dot}`} aria-hidden />
        <div style={{ minWidth: 0 }}>
          <p style={{ fontWeight: 600 }} className="truncate">
            {server.name}
          </p>
          <p className="meta truncate" style={{ marginTop: 4 }} title={subtitle}>
            {subtitle}
          </p>
        </div>
      </div>
      <div className="row" style={{ gap: 8, flexShrink: 0 }}>
        <Pill tone={view.tone}>{view.label}</Pill>
        <button className="btn btn-secondary" onClick={onInspect} disabled={anyDeploying}>
          检测
        </button>
        <button
          className="btn btn-secondary"
          onClick={onDeploy}
          disabled={anyDeploying || !canDeploy}
          title={deployHint}
        >
          {busy && <span className="spinner" aria-hidden />}
          {deployed ? '重新部署' : '部署'}
        </button>
        <button className="btn btn-ghost" onClick={onRemove} disabled={anyDeploying}>
          删除
        </button>
      </div>
    </div>
  )
}

function describeServer(
  status: ServerStatus,
  busy: boolean,
): { tone: PillTone; label: string; dot: string } {
  if (busy) return { tone: 'busy', label: '部署中', dot: 'busy' }
  switch (status) {
    case 'pending_inspection':
      return { tone: 'off', label: '待检测', dot: 'off' }
    case 'online':
      return { tone: 'ok', label: 'WireGuard 就绪', dot: 'ok' }
    case 'deploying':
      return { tone: 'busy', label: '部署中', dot: 'busy' }
    case 'config_broken':
      return { tone: 'err', label: '配置异常', dot: 'err' }
    case 'needs_attention':
      return { tone: 'warn', label: '有警告项', dot: 'off' }
    case 'offline':
      return { tone: 'off', label: '离线', dot: 'off' }
    case 'incomplete':
      return { tone: 'warn', label: '部署未完成', dot: 'off' }
    default:
      return { tone: 'off', label: '待检测', dot: 'off' }
  }
}
