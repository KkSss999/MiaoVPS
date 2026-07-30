/**
 * 速率折线 —— 对齐原型的 .sparkline-svg
 *
 * 用中性色（--fg，0.6 透明度）而非 accent：brand-spec 规定 accent
 * 只做状态信号，速率图表这类非状态可视化统一用中性色。
 */

interface Props {
  /** 数据点，越靠后越新 */
  values: number[]
  /** 原型的点数，不足时左侧补零保持折线从左端起 */
  points?: number
}

const VIEW_W = 100
const VIEW_H = 36

export function Sparkline({ values, points = 12 }: Props) {
  // 补齐到固定点数，避免只有 2 个点时折线横跨整个宽度显得突兀
  const padded = [...Array.from({ length: Math.max(0, points - values.length) }, () => 0), ...values.slice(-points)]

  const max = Math.max(...padded, 1)
  const step = VIEW_W / Math.max(1, padded.length - 1)

  const coords = padded
    .map((v, i) => {
      const x = (i * step).toFixed(1)
      // SVG 的 y 向下增长，所以要翻转；留 2px 上边距免得峰值贴边被裁
      const y = (VIEW_H - (v / max) * (VIEW_H - 2)).toFixed(1)
      return `${x},${y}`
    })
    .join(' ')

  return (
    <svg className="sparkline-svg" viewBox={`0 0 ${VIEW_W} ${VIEW_H}`} preserveAspectRatio="none" aria-hidden>
      <polyline points={coords} />
    </svg>
  )
}
