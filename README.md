# Sea-Otter 🦦 (DevSweep Engine)

> 面向新一代 AI 编程工具与开发者 CLI/Agent 的精细化清理与体检工具。  
> 像海獭（Sea Otter）梳理皮毛一样，时刻保持开发者环境的整洁与安全。

---

## 🌟 为什么需要 Sea-Otter？

传统清理工具（如 CleanMyMac、AppCleaner）通常采用“以 App Bundle 为中心”的粗放匹配模式，主要扫描 `~/Library` 下的 Bundle ID 文件夹。这在面对现代 AI 编程助手与 Agent CLI（如 Claude Code, Codex, Alma, WorkBuddy, Antigravity, Kiro 等）时往往失效：
- **遗漏核心 Dotfiles**：大量数据分散在 `~/.claude`, `~/.codex`, `~/.gemini`, `~/.workbuddy` 等家目录隐藏文件夹中。
- **孤儿残留识别盲区**：软件已被拖入废纸篓删除，但残留的会话历史、向量数据库、CLI 软链接和 OAuth Token 依然长期霸占空间。
- **敏感数据泄露风险**：Token / Refresh Token / OAuth 凭证与代码缓存混杂，缺乏敏感度分级。
- **误伤开发者资产**：AI Agent 经常直接在用户目录下创建工作区，缺乏对 `.git` 项目的安全防线。

---

## 🗂 项目结构

```text
sea-otter/
├── schema/
│   └── rule.schema.json         # 规则库 JSON Schema 规范 (v1.0)
├── rules/                       # 各大 AI/开发者工具精细化指纹规则 (YAML)
│   ├── alma.yaml                # Alma AI Agent
│   ├── bolt.yaml                # Bolt (bolt.new / Bolt.diy)
│   ├── cherry-studio.yaml       # Cherry Studio (多模型客户端)
│   ├── claude-code.yaml         # Anthropic Claude Code CLI
│   ├── codex.yaml               # OpenAI Codex CLI
│   ├── cursor.yaml              # Cursor (AI IDE)
│   ├── gemini-antigravity.yaml  # Google Antigravity & Gemini CLI
│   ├── kiro.yaml                # Kiro IDE
│   ├── ollama.yaml              # Ollama 本地模型运行时
│   ├── trae.yaml                # ByteDance Trae AI IDE
│   ├── windsurf.yaml            # Codeium Windsurf Editor
│   └── workbuddy.yaml           # WorkBuddy AI
├── docs/
│   └── rule-schema.md           # 架构设计规范与数据协议文档
├── .gitignore
└── README.md
```

---

## 📐 规则库规范与设计哲学

每条工具规则遵循四层架构：
1. **元信息（Metadata）**：工具唯一标识、名称、分类、厂商与主页。
2. **状态感知检测（Detection）**：检测 Bundle ID、App 路径与 CLI 命令，自动判定 `已安装 (Installed)` 还是 `孤儿残留 (Orphaned Residual)`。
3. **分级目标分类（Targets）**：
   - `caches`: 纯缓存（安全随时清理）
   - `preferences`: 偏好设置与窗口状态
   - `credentials`: 敏感凭据（OAuth Token、密钥，标记 `contains_secrets: true`）
   - `data_and_history`: 会话历史数据库与向量记忆
   - `configs`: 配置文件与插件 Skills（默认不勾选，防误删）
   - `binaries_and_scripts`: CLI 软链接与入口脚本
4. **安全防线（Safety Guard）**：强制 `.git` 仓库保护与核心用户主目录防伤拦截。

---

## 🚀 规划路线 (Roadmap)

- [x] **Phase 1: 规范定义与首批实测指纹库沉淀** (v1.0 Schema + 6 款核心工具)
- [ ] **Phase 2: 本地扫描与空间统计引擎 (MVP Scanner)**
  - 支持双态检测
  - 递归精确计算占用容量
  - Dry-run 只读预览与终端彩色展示
- [ ] **Phase 3: 交互式安全清理执行器**
  - 支持系统废纸篓安全软删除（Trash）
  - 敏感 Token 特殊警示与二次确认
- [ ] **Phase 4: 规则社区生态与多端交付**
  - Raycast 插件扩展 / 菜单栏轻量监控
  - 规则在线动态同步更新
