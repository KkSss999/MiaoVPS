/**
 * 环境检测结果
 *
 * 11 项检测里任何一项 Blocked 都不能部署。Warning 不阻塞，
 * 但要把建议一并显示 —— 用户需要知道为什么被标黄。
 */

import { useEffect } from 'react'
import { Modal } from '@/components/Modal'
import { Alert } from '@/components/States'
import { Pill, type PillTone } from '@/components/Pill'
import { useInspectServer } from '@/hooks/useServers'
import type { DetectStatus, Server } from '@/ipc/types'

interface Props {
  server: Server
  onClose: () => void
}

export function InspectModal({ server, onClose }: Props) {
  const inspect = useInspectServer()

  // 打开即开始检测 —— 用户点「检测」的意图很明确，不用再点一次
  useEffect(() => {
    inspect.mutate(server.id)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [server.id])

  const report = inspect.data

  return (
    <Modal
      title={`环境检测 · ${server.name}`}
      onClose={onClose}
      closable={!inspect.isPending}
      wide
      footer={
        <>
          <button
            className="btn btn-secondary"
            onClick={() => inspect.mutate(server.id)}
            disabled={inspect.isPending}
          >
            重新检测
          </button>
          <button className="btn btn-primary" onClick={onClose} disabled={inspect.isPending}>
            关闭
          </button>
        </>
      }
    >
      {inspect.isPending && (
        <div className="stack" style={{ gap: 10 }}>
          <p className="meta">正在通过 SSH 连接 {server.host} 并执行 11 项检测…</p>
          {Array.from({ length: 6 }).map((_, i) => (
            <div
              key={i}
              className="skeleton skeleton-line"
              style={{ width: `${90 - i * 8}%`, animationDelay: `${i * 0.1}s` }}
            />
          ))}
        </div>
      )}

      {inspect.error && (
        <Alert tone="err" title="检测失败">
          {inspect.error instanceof Error ? inspect.error.message : String(inspect.error)}
        </Alert>
      )}

      {report && (
        <>
          {report.blocked ? (
            <Alert tone="err" title="存在阻塞项">
              部署前需要先解决下面标「阻塞」的问题。
            </Alert>
          ) : report.all_passed ? (
            <Alert tone="info" title="全部通过">
              可以开始部署 WireGuard。
            </Alert>
          ) : (
            <Alert tone="warn" title="有警告项">
              不阻塞部署，但建议先了解下面的提示。
            </Alert>
          )}

          <div className="stack" style={{ gap: 0 }}>
            {report.items.map((item) => (
              <div
                key={item.key}
                style={{
                  display: 'flex',
                  gap: 12,
                  alignItems: 'flex-start',
                  padding: '10px 0',
                  borderTop: '1px solid var(--border)',
                }}
              >
                <span style={{ minWidth: 92, fontWeight: 600, fontSize: 13 }}>{item.name}</span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <p className="num selectable" style={{ fontSize: 12, wordBreak: 'break-all' }}>
                    {item.message}
                  </p>
                  {item.suggestion && (
                    <p className="meta" style={{ marginTop: 4 }}>
                      → {item.suggestion}
                    </p>
                  )}
                </div>
                <Pill tone={toneOf(item.status)}>{labelOf(item.status)}</Pill>
              </div>
            ))}
          </div>
        </>
      )}
    </Modal>
  )
}

function toneOf(status: DetectStatus): PillTone {
  if (status === 'Pass') return 'ok'
  if (status === 'Warning') return 'warn'
  return 'err'
}

function labelOf(status: DetectStatus): string {
  if (status === 'Pass') return '通过'
  if (status === 'Warning') return '警告'
  return '阻塞'
}
