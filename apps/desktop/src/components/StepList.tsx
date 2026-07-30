/**
 * 九步部署进度 —— 对齐原型的 .step-row / .step-icon
 *
 * 按固定顺序渲染全部九步（STEP_ORDER），而不是按事件到达顺序 ——
 * 用户需要一开始就看到总共几步，而不是逐条冒出来。
 */

import { CheckIcon, SpinnerArc } from './Icons'
import { parseStepResult, STEP_LABELS, STEP_ORDER, type StepResult } from '@/ipc/types'
import type { DeploymentStep } from '@/ipc/types'

interface Props {
  steps: Partial<Record<DeploymentStep, StepResult>>
}

export function StepList({ steps }: Props) {
  return (
    <div className="stack" style={{ gap: 2 }}>
      {STEP_ORDER.map((step) => {
        const { kind, detail } = parseStepResult(steps[step])
        return (
          <div className={`step-row ${kind}`} key={step}>
            <span className={`step-icon ${kind}`} aria-hidden>
              {kind === 'success' && <CheckIcon />}
              {kind === 'running' && <SpinnerArc />}
              {kind === 'failed' && '✕'}
              {kind === 'warning' && '!'}
              {kind === 'pending' && '·'}
            </span>
            <span className="label">{STEP_LABELS[step]}</span>
            {/* 状态用文字兜底，不只靠图标颜色 */}
            <span className="step-detail" title={detail ?? undefined}>
              {detail ?? statusText(kind)}
            </span>
          </div>
        )
      })}
    </div>
  )
}

function statusText(kind: string): string {
  switch (kind) {
    case 'success':
      return '完成'
    case 'running':
      return '进行中'
    case 'failed':
      return '失败'
    case 'warning':
      return '警告'
    default:
      return '等待'
  }
}
