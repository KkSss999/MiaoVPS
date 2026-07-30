/**
 * 四态占位组件 —— loading / empty / error
 *
 * 每个数据模块都必须有这三态。原型是静态的，所以这几个状态
 * 在设计稿里不存在，但真实数据下它们出现的频率比成功态更高。
 */

import { AlertIcon, EmptyBoxIcon, RefreshIcon } from './Icons'

/** 骨架屏 —— 卡片加载中 */
export function SkeletonCard({ lines = 3 }: { lines?: number }) {
  return (
    <div className="card">
      <div className="stack" style={{ gap: 10 }}>
        <div className="skeleton skeleton-line" style={{ width: '35%', height: 14 }} />
        {Array.from({ length: lines }).map((_, i) => (
          <div
            key={i}
            className="skeleton skeleton-line"
            style={{ width: `${85 - i * 15}%`, animationDelay: `${i * 0.12}s` }}
          />
        ))}
      </div>
    </div>
  )
}

/** 空态 */
export function EmptyState({
  title,
  hint,
  action,
}: {
  title: string
  hint?: string
  action?: React.ReactNode
}) {
  return (
    <div className="card">
      <div className="state-block">
        <span className="state-icon" aria-hidden>
          <EmptyBoxIcon />
        </span>
        <h3>{title}</h3>
        {hint && <p>{hint}</p>}
        {action}
      </div>
    </div>
  )
}

/** 错误态 —— 必须给重试入口，网络/SSH 抖动是常态 */
export function ErrorState({
  title,
  message,
  onRetry,
}: {
  title: string
  message: string
  onRetry?: () => void
}) {
  return (
    <div className="card">
      <div className="state-block error">
        <span className="state-icon" aria-hidden>
          <AlertIcon />
        </span>
        <h3>{title}</h3>
        <p className="selectable">{message}</p>
        {onRetry && (
          <button className="btn btn-secondary" onClick={onRetry}>
            <RefreshIcon className="btn-icon" />
            重试
          </button>
        )}
      </div>
    </div>
  )
}

/** 内联提示条 */
export function Alert({
  tone,
  title,
  children,
}: {
  tone: 'err' | 'warn' | 'info'
  title?: string
  children: React.ReactNode
}) {
  const Icon = tone === 'info' ? RefreshIcon : AlertIcon
  return (
    <div className={`alert ${tone}`} role={tone === 'err' ? 'alert' : 'status'}>
      <Icon />
      <div className="alert-body">
        {title && <div className="alert-title">{title}</div>}
        <div className="selectable">{children}</div>
      </div>
    </div>
  )
}
