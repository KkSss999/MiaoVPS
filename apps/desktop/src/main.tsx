import React from 'react'
import ReactDOM from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { App } from './App'
import { ToastProvider } from './components/Toast'

import './styles/tokens.css'
import './styles/base.css'
import './styles/components.css'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // SSH 操作慢且有副作用，不要在窗口聚焦时自动重跑
      refetchOnWindowFocus: false,
      // 网络抖动重试一次就够，SSH 失败重试只是让用户多等
      retry: 1,
      staleTime: 5_000,
    },
  },
})

// 用 MemoryRouter 而非 BrowserRouter：Tauri 的 WebView 里没有真实
// URL 栏，HashRouter 会污染窗口标题，内存路由最干净
ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <ToastProvider>
          <App />
        </ToastProvider>
      </MemoryRouter>
    </QueryClientProvider>
  </React.StrictMode>,
)
