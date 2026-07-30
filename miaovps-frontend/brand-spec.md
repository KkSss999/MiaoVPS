# MiaoVPS 品牌规范（基于 Open Design 设计系统）

**一句话定位：** 本地优先、无需注册账号的私人 WireGuard VPN 客户端 —— 技术上要专业可信，视觉上要轻松友好（"喵"猫主题），不做冷漠的企业软件感。

视觉方向由 **Open Design** 设计系统驱动。MiaoVPS 产品的品牌表达通过 Open Design 令牌体系落地。

## 六个 OKLch 令牌

```css
:root {
  --bg:              #000000;   /* Open Design Background — 页面底色（纯黑） */
  --surface:         #0a0a0a;   /* Open Design Surface — 卡片/面板 */
  --fg:              #ffffff;   /* Open Design Foreground — 正文文字 */
  --muted:           #7a7a7a;   /* Open Design Muted — 次要文字 */
  --border:          #242424;   /* Open Design Border — 分隔线 */
  --accent:          #63fe13;   /* Open Design Accent — 仅用于成功状态与微型操作标记，不是品牌色或交互主色 */
}
/* 辅助色 */
--accent-secondary: #26251e;    /* Open Design 深色中性表面 */
```

## 字体

- **Display（大标题/数字）：** Albert Sans（fallback: system-ui, -apple-system, "Segoe UI", "Helvetica Neue", Arial, sans-serif）—— 遵循 Open Design 排版体系。
- **Body（正文/UI）：** Albert Sans（fallback: system-ui, -apple-system, "Segoe UI", "Helvetica Neue", Arial, sans-serif）。
- **Mono（速率/IP/密钥指纹/时长等数值）：** "JetBrains Mono", ui-monospace, SFMono-Regular, monospace。

## 姿态规则（Posture）

1. **黑白主题，无侧边栏** —— `--bg: #000000` 为页面底色，`--surface: #0a0a0a` 为卡片表面。导航改为顶部导航（pill 高亮当前项），不再使用左侧边栏，页面主体用卡片化的 bento 网格布局承载信息。
2. **Accent 只做信号，不做装饰** —— Open Design 的 `--accent`（#63fe13）定位即为成功信号/微型操作标记。仅用在：连接状态指示、在线状态点（带呼吸脉冲动画）、部署步骤完成标记。每屏最多两处高饱和度使用，其余用低透明度版本做底色。速率图表、资源进度条等非状态类可视化统一用白色/中性色，不用 accent 铺色。主 CTA 按钮使用 `--fg` 反色方案，不用 accent。
3. **状态永远"文字/图标 + 颜色"双重编码**，绝不仅靠色块区分在线/离线/失败（对应可访问性要求）。
4. **卡片是信息容器，也是交互单元** —— 1px `--border`，8px 圆角；卡片可 hover 抬升并轻微提亮背景，作为可点击/可探索的反馈，但不叠加渐变或阴影堆叠；一张卡一件事。
5. **数字用 Mono 对齐** —— 速率、流量、时长、IP、公钥指纹全部 tabular / monospace，保证竖向对齐。
6. **动效克制而有生命力** —— 页面切换用淡入上移过渡，状态点用呼吸脉冲，进度条/图表用一次性填充动画；动效服务于"实时监控"的产品语境，不做装饰性动画。
7. **留白呼吸** —— 技术信息密度高，用充足的间距和分组（8px 基线网格）避免"仪表盘噎住"的感觉。
8. **禁止**：渐变背景、卡片左侧色条、表情符号图标、Hero 插画、多种强调色混用。
