/**
 * 状态胶囊
 *
 * 状态永远「文字 + 颜色」双重编码 —— 绝不仅靠色块区分在线/离线/失败。
 * 这是 brand-spec 的可访问性硬要求。
 */

export type PillTone = 'ok' | 'warn' | 'off' | 'err' | 'busy'

interface Props {
  tone: PillTone
  children: React.ReactNode
  className?: string
}

export function Pill({ tone, children, className }: Props) {
  return (
    <span className={`pill ${tone}${className ? ` ${className}` : ''}`}>
      <span className="pill-dot" aria-hidden />
      {children}
    </span>
  )
}
