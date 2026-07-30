/**
 * 模态对话框
 *
 * 可访问性：Esc 关闭、焦点锁在对话框内、打开时焦点落到第一个可聚焦元素、
 * 关闭后焦点回到触发元素。这些是键盘用户能用起来的最低要求。
 */

import { useEffect, useRef } from 'react'
import { CloseIcon } from './Icons'

interface Props {
  title: string
  onClose: () => void
  children: React.ReactNode
  footer?: React.ReactNode
  /** 部署这类不可中断的操作要禁用关闭 */
  closable?: boolean
  wide?: boolean
}

const FOCUSABLE =
  'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'

export function Modal({ title, onClose, children, footer, closable = true, wide }: Props) {
  const dialogRef = useRef<HTMLDivElement>(null)
  const restoreFocusTo = useRef<Element | null>(null)

  useEffect(() => {
    restoreFocusTo.current = document.activeElement

    // 打开后焦点进对话框，否则键盘用户还停在背景页面上
    const first = dialogRef.current?.querySelector<HTMLElement>(FOCUSABLE)
    first?.focus()

    return () => {
      if (restoreFocusTo.current instanceof HTMLElement) restoreFocusTo.current.focus()
    }
  }, [])

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape' && closable) {
        e.preventDefault()
        onClose()
        return
      }
      // 焦点循环 —— Tab 到末尾回到开头，不跑到背景页面去
      if (e.key !== 'Tab') return
      const nodes = dialogRef.current?.querySelectorAll<HTMLElement>(FOCUSABLE)
      if (!nodes || nodes.length === 0) return
      const first = nodes[0]!
      const last = nodes[nodes.length - 1]!
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault()
        last.focus()
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault()
        first.focus()
      }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [closable, onClose])

  return (
    <div
      className="modal-backdrop"
      onMouseDown={(e) => {
        // 只有点在背板本身才关，拖选文字时不该误关
        if (e.target === e.currentTarget && closable) onClose()
      }}
    >
      <div
        className={`modal${wide ? ' wide' : ''}`}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        ref={dialogRef}
      >
        <div className="modal-header">
          <h3>{title}</h3>
          {closable && (
            <button className="icon-btn" onClick={onClose} aria-label="关闭">
              <CloseIcon />
            </button>
          )}
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-footer">{footer}</div>}
      </div>
    </div>
  )
}
