/**
 * 添加设备
 *
 * 创建成功后直接展示完整配置 —— 私钥只在这一刻方便复制，
 * 之后虽然还能从 Keychain 重新导出，但用户当场拿到最省事。
 */

import { useState } from 'react'
import { writeText } from '@tauri-apps/plugin-clipboard-manager'
import { Modal } from '@/components/Modal'
import { Alert } from '@/components/States'
import { CopyIcon } from '@/components/Icons'
import { useToast } from '@/components/Toast'
import { useAddDevice } from '@/hooks/useServers'
import type { DeviceType } from '@/ipc/types'
import { DEVICE_TYPE_LABELS } from '@/ipc/types'

interface Props {
  serverId: string
  onClose: () => void
}

const TYPES: DeviceType[] = ['mac', 'windows', 'i_phone', 'android', 'linux', 'other']

export function AddDeviceModal({ serverId, onClose }: Props) {
  const toast = useToast()
  const addDevice = useAddDevice(serverId)
  const [name, setName] = useState('')
  const [deviceType, setDeviceType] = useState<DeviceType>('mac')
  const [nameError, setNameError] = useState<string | null>(null)
  const [submitError, setSubmitError] = useState<string | null>(null)

  const result = addDevice.data

  async function onSubmit(e?: React.FormEvent) {
    e?.preventDefault()
    setSubmitError(null)
    if (!name.trim()) {
      setNameError('给设备起个名字')
      return
    }
    try {
      await addDevice.mutateAsync({ name: name.trim(), deviceType })
      toast.success('设备已创建并注册为服务端 peer')
    } catch (err) {
      setSubmitError(err instanceof Error ? err.message : '添加失败')
    }
  }

  async function copyConfig() {
    if (!result) return
    await writeText(result.config)
    toast.success('配置已复制（含私钥）')
  }

  // 创建成功后切到「展示配置」视图
  if (result) {
    return (
      <Modal
        title={`${result.device.name} 已创建`}
        onClose={onClose}
        wide
        footer={
          <>
            <button className="btn btn-secondary" onClick={copyConfig}>
              <CopyIcon style={{ width: 14, height: 14 }} />
              复制配置
            </button>
            <button className="btn btn-primary" onClick={onClose}>
              完成
            </button>
          </>
        }
      >
        <Alert tone="info" title="已注册到服务端">
          分配地址 {result.device.vpn_address}。这台设备的公钥已加入 VPS 的 peer 列表。
        </Alert>
        <div className="field">
          <label>WireGuard 配置</label>
          <pre className="codeblock">{result.config}</pre>
          <span className="hint">
            配置含客户端私钥，不要发到聊天群或提交进仓库。私钥已存入系统
            Keychain，之后可在设备详情里重新导出。
          </span>
        </div>
      </Modal>
    )
  }

  return (
    <Modal
      title="添加设备"
      onClose={onClose}
      closable={!addDevice.isPending}
      footer={
        <>
          <button className="btn btn-ghost" onClick={onClose} disabled={addDevice.isPending}>
            取消
          </button>
          <button className="btn btn-primary" onClick={onSubmit} disabled={addDevice.isPending}>
            {addDevice.isPending && <span className="spinner" aria-hidden />}
            创建
          </button>
        </>
      }
    >
      <form onSubmit={onSubmit} className="stack" style={{ gap: 'var(--gap-md)' }}>
        {submitError && <Alert tone="err">{submitError}</Alert>}

        <div className={`field${nameError ? ' invalid' : ''}`}>
          <label htmlFor="dev-name">设备名称</label>
          <input
            id="dev-name"
            value={name}
            onChange={(e) => {
              setName(e.target.value)
              setNameError(null)
            }}
            placeholder="我的 MacBook"
            autoComplete="off"
          />
          {nameError && <span className="error-text">{nameError}</span>}
        </div>

        <div className="field">
          <label htmlFor="dev-type">设备类型</label>
          <select
            id="dev-type"
            value={deviceType}
            onChange={(e) => setDeviceType(e.target.value as DeviceType)}
          >
            {TYPES.map((t) => (
              <option key={t} value={t}>
                {DEVICE_TYPE_LABELS[t]}
              </option>
            ))}
          </select>
          <span className="hint">
            创建时会生成独立密钥对、分配 VPN 地址，并通过 SSH 注册到服务端。
          </span>
        </div>
      </form>
    </Modal>
  )
}
