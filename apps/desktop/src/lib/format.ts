/**
 * 显示格式化
 *
 * 所有数值在 UI 里都走 mono 字体 + tabular-nums，
 * 所以这些函数的输出宽度要尽量稳定，避免数字跳动时布局抖动。
 */

/** 字节数 → 人类可读 */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '0 B'
  if (bytes < 1024) return `${bytes} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let value = bytes / 1024
  let i = 0
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024
    i++
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[i]}`
}

/** 速率 —— 与 formatBytes 同源但带 /s */
export function formatRate(bytesPerSec: number): { value: string; unit: string } {
  if (!Number.isFinite(bytesPerSec) || bytesPerSec < 0) return { value: '0', unit: 'B/s' }
  if (bytesPerSec < 1024) return { value: bytesPerSec.toFixed(0), unit: 'B/s' }
  const units = ['KB/s', 'MB/s', 'GB/s']
  let value = bytesPerSec / 1024
  let i = 0
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024
    i++
  }
  return { value: value.toFixed(value < 10 ? 1 : 0), unit: units[i]! }
}

/** 秒数 → HH:MM:SS */
export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return '00:00:00'
  const s = Math.floor(seconds)
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  const sec = s % 60
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(h)}:${pad(m)}:${pad(sec)}`
}

/** Unix 秒 → 相对时间 */
export function formatRelative(unixSecs: number | null): string {
  if (!unixSecs) return '从未连接'
  const diff = Math.floor(Date.now() / 1000) - unixSecs
  if (diff < 0) return '刚刚'
  if (diff < 60) return '刚刚'
  if (diff < 3600) return `${Math.floor(diff / 60)} 分钟前`
  if (diff < 86400) return `${Math.floor(diff / 3600)} 小时前`
  if (diff < 86400 * 30) return `${Math.floor(diff / 86400)} 天前`
  return formatDate(unixSecs)
}

/** Unix 秒 → YYYY-MM-DD */
export function formatDate(unixSecs: number): string {
  if (!unixSecs) return '—'
  const d = new Date(unixSecs * 1000)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
}

/**
 * 公钥 → 指纹
 *
 * 完整 base64 公钥有 44 字符，列表里放不下也不便于人眼比对。
 * 取前 4 字节做冒号分隔的十六进制，够用来核对是不是同一把钥匙。
 */
export function keyFingerprint(publicKeyB64: string): string {
  if (!publicKeyB64) return '—'
  try {
    const bin = atob(publicKeyB64)
    return Array.from(bin.slice(0, 4))
      .map((c) => c.charCodeAt(0).toString(16).padStart(2, '0').toUpperCase())
      .join(':')
  } catch {
    // 不是合法 base64 时退回截断显示，别让 UI 崩
    return publicKeyB64.slice(0, 11)
  }
}

/** 密钥截断显示 —— 日志和 UI 都不应展示完整密钥 */
export function shortKey(key: string, keep = 12): string {
  if (!key) return '—'
  return key.length <= keep ? key : `${key.slice(0, keep)}…`
}

/** 中文设备类型标签由 types.ts 提供，这里只处理 IP 展示 */
export function stripMask(addr: string): string {
  return addr.split('/')[0] ?? addr
}
