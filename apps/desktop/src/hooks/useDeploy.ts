/**
 * 部署进度
 *
 * 部署要跑几十秒。command 的 Promise 只在最后 resolve，中间进度靠
 * `deploy-progress` 事件。这个钩子把事件流聚合成「步骤 → 结果」的 map。
 */

import { useCallback, useEffect, useRef, useState } from 'react'
import { onDeployProgress } from '@/ipc/events'
import type { DeploymentStep, StepEvent, StepResult } from '@/ipc/types'

export type StepMap = Partial<Record<DeploymentStep, StepResult>>

export function useDeployProgress() {
  const [steps, setSteps] = useState<StepMap>({})
  const [running, setRunning] = useState(false)
  const unlisten = useRef<(() => void) | null>(null)

  useEffect(() => {
    let disposed = false

    onDeployProgress((ev: StepEvent) => {
      setSteps((prev) => ({ ...prev, [ev.step]: ev.result }))
    }).then((fn) => {
      // 组件在 listen 解析完成前就卸载了 —— 立刻退订，别泄漏监听器
      if (disposed) fn()
      else unlisten.current = fn
    })

    return () => {
      disposed = true
      unlisten.current?.()
      unlisten.current = null
    }
  }, [])

  /** 开始新一轮部署前清空上一轮的步骤，否则会看到旧的成功标记 */
  const reset = useCallback(() => {
    setSteps({})
    setRunning(true)
  }, [])

  const finish = useCallback(() => setRunning(false), [])

  return { steps, running, reset, finish }
}
