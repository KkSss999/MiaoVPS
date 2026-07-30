/**
 * 图标 —— 全部内联 SVG，与原型 desktop.html 逐条对齐
 *
 * 不引图标库：原型的 stroke-width 和视觉重量是设计的一部分，
 * 换成 lucide/heroicons 会整体偏轻或偏重。
 */

type IconProps = { className?: string; style?: React.CSSProperties }

const base = {
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.8,
  strokeLinecap: 'round' as const,
  strokeLinejoin: 'round' as const,
}

export function HomeIcon(p: IconProps) {
  return (
    <svg {...base} className={p.className} style={p.style}>
      <path d="M3 12 12 3l9 9" />
      <path d="M5 10v10h14V10" />
    </svg>
  )
}

export function NodesIcon(p: IconProps) {
  return (
    <svg {...base} className={p.className} style={p.style}>
      <rect x="3" y="4" width="18" height="6" rx="1.5" />
      <rect x="3" y="14" width="18" height="6" rx="1.5" />
      <path d="M7 7h.01M7 17h.01" />
    </svg>
  )
}

export function DevicesIcon(p: IconProps) {
  return (
    <svg {...base} className={p.className} style={p.style}>
      <rect x="4" y="3" width="16" height="14" rx="2" />
      <path d="M9 21h6M12 17v4" />
    </svg>
  )
}

export function SettingsIcon(p: IconProps) {
  return (
    <svg {...base} className={p.className} style={p.style}>
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z" />
    </svg>
  )
}

/** 连接信号图标 —— hero 卡中心 */
export function SignalIcon(p: IconProps) {
  return (
    <svg {...base} strokeWidth={1.6} className={p.className} style={p.style}>
      <path d="M5 12.5a10 10 0 0 1 14 0" />
      <path d="M8 15.5a6 6 0 0 1 8 0" />
      <circle cx="12" cy="18.5" r="1.4" fill="currentColor" stroke="none" />
    </svg>
  )
}

export function CloseIcon(p: IconProps) {
  return (
    <svg {...base} className={p.className} style={p.style}>
      <path d="M18 6 6 18M6 6l12 12" />
    </svg>
  )
}

export function PlusIcon(p: IconProps) {
  return (
    <svg {...base} className={p.className} style={p.style}>
      <path d="M12 5v14M5 12h14" />
    </svg>
  )
}

export function CheckIcon(p: IconProps) {
  return (
    <svg {...base} strokeWidth={2.4} className={p.className} style={p.style}>
      <path d="M20 6 9 17l-5-5" />
    </svg>
  )
}

export function AlertIcon(p: IconProps) {
  return (
    <svg {...base} className={p.className} style={p.style}>
      <path d="M12 9v4M12 17h.01" />
      <path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" />
    </svg>
  )
}

export function InfoIcon(p: IconProps) {
  return (
    <svg {...base} className={p.className} style={p.style}>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 16v-5M12 8h.01" />
    </svg>
  )
}

/** 部署中的旋转弧 —— 原型 step-icon.active 用的就是这个 */
export function SpinnerArc(p: IconProps) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className={p.className} style={p.style}>
      <path d="M12 2a10 10 0 0 1 10 10" />
    </svg>
  )
}

export function EmptyBoxIcon(p: IconProps) {
  return (
    <svg {...base} strokeWidth={1.6} className={p.className} style={p.style}>
      <path d="M21 8v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8" />
      <path d="M2 8h20l-2-4H4L2 8z" />
      <path d="M10 12h4" />
    </svg>
  )
}

export function RefreshIcon(p: IconProps) {
  return (
    <svg {...base} className={p.className} style={p.style}>
      <path d="M21 12a9 9 0 1 1-3-6.7" />
      <path d="M21 4v5h-5" />
    </svg>
  )
}

export function CopyIcon(p: IconProps) {
  return (
    <svg {...base} className={p.className} style={p.style}>
      <rect x="9" y="9" width="12" height="12" rx="2" />
      <path d="M5 15V5a2 2 0 0 1 2-2h10" />
    </svg>
  )
}

export function DownloadIcon(p: IconProps) {
  return (
    <svg {...base} className={p.className} style={p.style}>
      <path d="M12 3v12M7 11l5 5 5-5" />
      <path d="M4 20h16" />
    </svg>
  )
}

export function ShieldIcon(p: IconProps) {
  return (
    <svg {...base} className={p.className} style={p.style}>
      <path d="M12 3 5 6v5c0 5 3 8.5 7 10 4-1.5 7-5 7-10V6l-7-3z" />
    </svg>
  )
}

export function LinkIcon(p: IconProps) {
  return (
    <svg {...base} className={p.className} style={p.style}>
      <path d="M9 15l6-6" />
      <path d="M11 6l1-1a4 4 0 0 1 6 6l-1 1" />
      <path d="M13 18l-1 1a4 4 0 0 1-6-6l1-1" />
    </svg>
  )
}
