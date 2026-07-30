/**
 * Toast 通知
 *
 * 用于「操作已完成」这类不需要用户响应的反馈。
 * 需要用户看清并处理的错误走 Alert（留在页面上），不用 Toast。
 */

import { createContext, useCallback, useContext, useMemo, useRef, useState } from 'react'

type ToastTone = 'success' | 'error' | 'info'

interface ToastItem {
  id: number
  tone: ToastTone
  message: string
}

interface ToastApi {
  show: (message: string, tone?: ToastTone) => void
  success: (message: string) => void
  error: (message: string) => void
}

const ToastContext = createContext<ToastApi | null>(null)

export function useToast(): ToastApi {
  const ctx = useContext(ToastContext)
  if (!ctx) throw new Error('useToast 必须在 ToastProvider 内使用')
  return ctx
}

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([])
  const nextId = useRef(1)

  const show = useCallback((message: string, tone: ToastTone = 'info') => {
    const id = nextId.current++
    setItems((prev) => [...prev, { id, tone, message }])
    // 错误留久一点 —— 用户需要时间读完
    const ttl = tone === 'error' ? 6000 : 3200
    window.setTimeout(() => {
      setItems((prev) => prev.filter((t) => t.id !== id))
    }, ttl)
  }, [])

  const api = useMemo<ToastApi>(
    () => ({
      show,
      success: (m) => show(m, 'success'),
      error: (m) => show(m, 'error'),
    }),
    [show],
  )

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div className="toast-stack" aria-live="polite" aria-atomic="false">
        {items.map((t) => (
          <div key={t.id} className={`toast ${t.tone}`} role={t.tone === 'error' ? 'alert' : 'status'}>
            <span className="toast-dot" aria-hidden />
            <div className="toast-body selectable">{t.message}</div>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}
