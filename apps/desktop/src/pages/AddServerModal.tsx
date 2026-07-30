/**
 * 添加 VPS 表单
 *
 * 凭据必须填 —— 没凭据的服务器记录建了也连不上，
 * 后面 inspect/deploy 全会失败。所以校验放在提交前。
 */

import { useState } from 'react'
import { open } from '@tauri-apps/plugin-dialog'
import { Modal } from '@/components/Modal'
import { Alert } from '@/components/States'
import { useToast } from '@/components/Toast'
import { useAddServer } from '@/hooks/useServers'
import type { SshAuthType } from '@/ipc/types'

interface Props {
  onClose: () => void
}

interface Form {
  name: string
  host: string
  port: string
  user: string
  authType: SshAuthType
  password: string
  keyPath: string
  passphrase: string
}

const INITIAL: Form = {
  name: '',
  host: '',
  port: '22',
  user: 'root',
  authType: 'private_key',
  password: '',
  keyPath: '',
  passphrase: '',
}

export function AddServerModal({ onClose }: Props) {
  const toast = useToast()
  const addServer = useAddServer()
  const [form, setForm] = useState<Form>(INITIAL)
  const [errors, setErrors] = useState<Partial<Record<keyof Form, string>>>({})
  const [submitError, setSubmitError] = useState<string | null>(null)

  function set<K extends keyof Form>(key: K, value: Form[K]) {
    setForm((f) => ({ ...f, [key]: value }))
    setErrors((e) => ({ ...e, [key]: undefined }))
  }

  function validate(): boolean {
    const next: Partial<Record<keyof Form, string>> = {}
    if (!form.name.trim()) next.name = '给节点起个名字'
    if (!form.host.trim()) next.host = '填写 IP 或域名'
    const port = Number(form.port)
    if (!Number.isInteger(port) || port < 1 || port > 65535) next.port = '端口需在 1–65535'
    if (!form.user.trim()) next.user = '填写 SSH 登录用户'
    if (form.authType === 'password' && !form.password) next.password = '填写 SSH 密码'
    if (form.authType === 'private_key' && !form.keyPath) next.keyPath = '选择私钥文件'
    setErrors(next)
    return Object.keys(next).length === 0
  }

  async function pickKey() {
    const picked = await open({
      multiple: false,
      directory: false,
      title: '选择 SSH 私钥',
    })
    if (typeof picked === 'string') set('keyPath', picked)
  }

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setSubmitError(null)
    if (!validate()) return

    try {
      const server = await addServer.mutateAsync({
        name: form.name.trim(),
        host: form.host.trim(),
        port: Number(form.port),
        user: form.user.trim(),
        authType: form.authType,
        ...(form.authType === 'password'
          ? { password: form.password }
          : { keyPath: form.keyPath, passphrase: form.passphrase || undefined }),
      })
      toast.success(`已添加 ${server.name}，接下来做一次环境检测`)
      onClose()
    } catch (err) {
      setSubmitError(err instanceof Error ? err.message : '添加失败')
    }
  }

  return (
    <Modal
      title="添加 VPS"
      onClose={onClose}
      closable={!addServer.isPending}
      footer={
        <>
          <button className="btn btn-ghost" onClick={onClose} disabled={addServer.isPending}>
            取消
          </button>
          <button className="btn btn-primary" onClick={onSubmit} disabled={addServer.isPending}>
            {addServer.isPending && <span className="spinner" aria-hidden />}
            添加
          </button>
        </>
      }
    >
      <form onSubmit={onSubmit} className="stack" style={{ gap: 'var(--gap-md)' }}>
        {submitError && <Alert tone="err">{submitError}</Alert>}

        <div className={`field${errors.name ? ' invalid' : ''}`}>
          <label htmlFor="srv-name">节点名称</label>
          <input
            id="srv-name"
            value={form.name}
            onChange={(e) => set('name', e.target.value)}
            placeholder="新加坡 VPS"
            autoComplete="off"
          />
          {errors.name && <span className="error-text">{errors.name}</span>}
        </div>

        <div className="field-row">
          <div className={`field${errors.host ? ' invalid' : ''}`}>
            <label htmlFor="srv-host">IP 或域名</label>
            <input
              id="srv-host"
              value={form.host}
              onChange={(e) => set('host', e.target.value)}
              placeholder="203.0.113.10"
              autoComplete="off"
              spellCheck={false}
            />
            {errors.host && <span className="error-text">{errors.host}</span>}
          </div>
          <div className={`field${errors.port ? ' invalid' : ''}`}>
            <label htmlFor="srv-port">SSH 端口</label>
            <input
              id="srv-port"
              value={form.port}
              onChange={(e) => set('port', e.target.value)}
              inputMode="numeric"
            />
            {errors.port && <span className="error-text">{errors.port}</span>}
          </div>
        </div>

        <div className={`field${errors.user ? ' invalid' : ''}`}>
          <label htmlFor="srv-user">SSH 用户</label>
          <input
            id="srv-user"
            value={form.user}
            onChange={(e) => set('user', e.target.value)}
            autoComplete="off"
            spellCheck={false}
          />
          <span className="hint">
            非 root 用户需要有 sudo 权限。部署过程会自动探测 root / 免密 sudo。
          </span>
          {errors.user && <span className="error-text">{errors.user}</span>}
        </div>

        <div className="field">
          <label>认证方式</label>
          <div className="segmented" role="group" aria-label="认证方式">
            <button
              type="button"
              className={form.authType === 'private_key' ? 'active' : ''}
              onClick={() => set('authType', 'private_key')}
            >
              私钥
            </button>
            <button
              type="button"
              className={form.authType === 'password' ? 'active' : ''}
              onClick={() => set('authType', 'password')}
            >
              密码
            </button>
          </div>
        </div>

        {form.authType === 'private_key' ? (
          <>
            <div className={`field${errors.keyPath ? ' invalid' : ''}`}>
              <label htmlFor="srv-key">私钥文件</label>
              <div className="row" style={{ gap: 8 }}>
                <input
                  id="srv-key"
                  value={form.keyPath}
                  onChange={(e) => set('keyPath', e.target.value)}
                  placeholder="~/.ssh/id_ed25519"
                  spellCheck={false}
                  style={{ flex: 1 }}
                />
                <button type="button" className="btn btn-secondary" onClick={pickKey}>
                  浏览
                </button>
              </div>
              {errors.keyPath && <span className="error-text">{errors.keyPath}</span>}
            </div>
            <div className="field">
              <label htmlFor="srv-passphrase">私钥密码短语（可选）</label>
              <input
                id="srv-passphrase"
                type="password"
                value={form.passphrase}
                onChange={(e) => set('passphrase', e.target.value)}
                autoComplete="new-password"
              />
            </div>
          </>
        ) : (
          <div className={`field${errors.password ? ' invalid' : ''}`}>
            <label htmlFor="srv-password">SSH 密码</label>
            <input
              id="srv-password"
              type="password"
              value={form.password}
              onChange={(e) => set('password', e.target.value)}
              autoComplete="new-password"
            />
            {errors.password && <span className="error-text">{errors.password}</span>}
          </div>
        )}

        <span className="hint">
          凭据保存在 ~/.miaovps/credentials/，权限 0600，只留在这台机器上。
        </span>
      </form>
    </Modal>
  )
}
