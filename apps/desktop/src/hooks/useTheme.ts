/**
 * 主题切换
 *
 * 写 `data-theme` 到 html 元素，令牌由 CSS 覆盖 —— 与原型行为一致。
 * localStorage 键名沿用原型的 `miaovps-theme`。
 */

import { useCallback, useState } from 'react'

export type Theme = 'dark' | 'light'

const KEY = 'miaovps-theme'

function current(): Theme {
  const attr = document.documentElement.getAttribute('data-theme')
  return attr === 'dark' ? 'dark' : 'light'
}

export function useTheme() {
  const [theme, setTheme] = useState<Theme>(current)

  const apply = useCallback((next: Theme) => {
    document.documentElement.setAttribute('data-theme', next)
    try {
      localStorage.setItem(KEY, next)
    } catch {
      // 隐私模式下 localStorage 可能抛异常，主题仍应生效
    }
    setTheme(next)
  }, [])

  return { theme, setTheme: apply }
}
