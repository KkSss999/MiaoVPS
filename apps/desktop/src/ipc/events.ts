/**
 * Tauri 事件订阅
 *
 * 部署要跑几十秒，不能等 command 返回才更新 UI。
 * Rust 侧把 StepSender 的接收端接到 app_handle.emit()。
 */

import { listen, type UnlistenFn } from '@tauri-apps/api/event'
import type { StepEvent } from './types'

export const DEPLOY_PROGRESS_EVENT = 'deploy-progress'

/**
 * 订阅部署进度
 *
 * 返回取消订阅函数 —— 必须在组件卸载时调用，否则重复部署会叠加监听器。
 */
export function onDeployProgress(handler: (ev: StepEvent) => void): Promise<UnlistenFn> {
  return listen<StepEvent>(DEPLOY_PROGRESS_EVENT, (e) => handler(e.payload))
}
