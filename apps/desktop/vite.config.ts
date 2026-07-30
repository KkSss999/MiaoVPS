import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'node:path'

// Tauri 固定用 1420 端口，改了这里 tauri.conf.json 的 devUrl 也要同步改
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { '@': path.resolve(__dirname, './src') },
  },
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    watch: {
      // src-tauri 的改动由 cargo 自己 watch，Vite 不必重启
      ignored: ['**/src-tauri/**'],
    },
  },
  // Tauri 用 WKWebView（Safari 内核），target 跟随而非 esnext
  build: {
    target: 'safari15',
    sourcemap: true,
  },
})
