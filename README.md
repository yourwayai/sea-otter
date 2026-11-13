<p align="center">
  <img src="assets/logo.png" alt="Sea-Otter Logo" width="180" style="border-radius: 20px;">
</p>

<h1 align="center">Sea-Otter 🦦</h1>

<p align="center">
  <strong>DevSweep Engine · 面向新一代 AI 编程工具与开发者 CLI/Agent 的精细化清理与体检工具</strong><br>
  <em>像海獭（Sea Otter）梳理皮毛一样，时刻保持开发者环境的整洁与安全。</em>
</p>

<p align="center">
  <a href="https://github.com/yourwayai/sea-otter/releases"><img src="https://img.shields.io/badge/version-1.0.0-blue.svg" alt="Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License"></a>
  <a href="README_EN.md"><img src="https://img.shields.io/badge/docs-English-blue.svg" alt="English Documentation"></a>
</p>

---

## 🌟 为什么需要 Sea-Otter？

传统清理工具（如 CleanMyMac、AppCleaner）通常采用“以 App Bundle 为中心”的粗放匹配模式，主要扫描 `~/Library` 下的 Bundle ID 文件夹。这在面对现代 AI 编程助手与 Agent CLI（如 Claude Code, Codex, Alma, WorkBuddy, Antigravity, Kiro 等）时往往失效：
- **遗漏核心 Dotfiles**：大量数据分散在 `~/.claude`, `~/.codex`, `~/.gemini`, `~/.workbuddy` 等家目录隐藏文件夹中。
- **孤儿残留识别盲区**：软件已被拖入废纸篓删除，但残留的会话历史、向量数据库、CLI 软链接和 OAuth Token 依然长期霸占空间。
- **敏感数据泄露风险**：Token / Refresh Token / OAuth 凭证与代码缓存混杂，缺乏敏感度分级。
- **误伤开发者资产**：AI Agent 经常直接在用户目录下创建工作区，缺乏对 `.git` 项目的安全防线。

---

## 🛡️ 核心防线：四级安全防护矩阵 (Four-Tier Safety Risk Matrix)

面向现代开发者与 AI 软件的磁盘治理，**安全性高于一切**。Sea-Otter 弃用传统的二元判定，正式落地四级安全防护矩阵：

| 级别 | 定义 | 典型对象 | 处理与勾选策略 |
| :--- | :--- | :--- | :--- |
| **🟢 L1: 极低风险 (Zero-Impact Junk)** | 纯垃圾文件、空锁、跨平台 Bug 目录 | 历史散落图片、`.ACCC_Lock`、`(null)` 幽灵目录、空骨架目录 | **默认勾选**，一键归档移入废纸篓 |
| **🟡 L2: 明确已卸载 (Orphaned Apps)** | 对应软件已删除，残留孤儿历史配置 | `Codex`、`Cursor`、`Claude`、`Trae` 等已卸载孤岛 | **默认勾选**，移入废纸篓隔离区 |
| **🟠 L3: 在用软件减负 (Bloatware/Cache)** | 正在使用的软件，但内部堆积了模型/临时缓存/凭据 | 正在使用的软件缓存、本地模型权重（Ollama/BGE）、OAuth 密钥 | **默认不勾选**，需加 `--include-l3` 显式确认 |
| **🔴 L4: 绝对安全红线 (Protected System)** | macOS 系统核心数据、权限库、代码工程、活跃进程 | `com.apple.TCC`、`AddressBook`、`CloudDocs`、`.git` 仓库、运行中的进程 | **硬编码屏蔽阻断**，完全禁止删除 |

### 四大绝对安全铁律

1. **系统红线库 (System Redline Vault) 强阻断**：
   - 对 `com.apple.TCC` (麦克风/摄像头/完全磁盘访问权限库)、`AddressBook`、`CallHistoryDB`、`CloudDocs`、`Keychain`、`com.apple.sharedfilelist` 等系统关键库设立绝对硬白名单，禁止任何触碰。
2. **多维存活状态交叉验证 (Process & Lock Guard)**：
   - 判定软件是否在用绝不仅看 `/Applications/*.app`，而是交叉比对进程表（`pgrep`）、常驻守护进程与单例文件锁（`SingletonLock`）。活跃工具自动上锁标记为 **`🔵 正在运行 (保护锁定)`**。
3. **代码仓库与工程资产“强制免疫”**：
   - 任何待清理路径自动浅层递归探测 `.git`、`.svn`、`.hg`、`.obsidian` 标识。只要检测到代码仓库，**强制阻断一键清理，将其归类为用户工程资产**。
4. **废纸篓软着陆隔离与敏感凭据审计**：
   - 默认采用系统原生 Trash 移入机制，零误删心理负担；明文 OAuth Token 和私钥自动打上 🔑 告警标并默认跳过。

---

## 🗂 项目结构

```text
sea-otter/
├── assets/                      # 项目资源（Logo 图标等）
│   └── logo.png
├── schema/
│   └── rule.schema.json         # 规则库 JSON Schema 规范 (v1.1)
├── rules/                       # 各大 AI/开发者工具精细化指纹规则 (YAML)
│   ├── 5ire.yaml                # 5ire AI Desktop (BGE-M3 本地向量模型)
│   ├── alma.yaml                # Alma AI Agent
│   ├── bolt.yaml                # Bolt (bolt.new / Bolt.diy)
│   ├── cherry-studio.yaml       # Cherry Studio (多模型客户端)
│   ├── claude-code.yaml         # Anthropic Claude Code CLI
│   ├── codex.yaml               # OpenAI Codex CLI
│   ├── cursor.yaml              # Cursor (AI IDE)
│   ├── gemini-antigravity.yaml  # Google Antigravity & Gemini CLI
│   ├── hermes.yaml              # Hermes Agent (多进程守护网关)
│   ├── kiro.yaml                # Kiro IDE
│   ├── ollama.yaml              # Ollama 本地模型运行时
│   ├── trae.yaml                # ByteDance Trae AI IDE
│   ├── windsurf.yaml            # Codeium Windsurf Editor
│   └── workbuddy.yaml           # WorkBuddy AI
├── docs/
│   ├── architecture-and-lessons-learned.md # 实战经验与架构指南 (v1.2 Milestone)
│   └── rule-schema.md           # 架构设计规范与数据协议文档
├── sea_otter/                   # 核心 Python 引擎
│   ├── safety.py                # 四级安全防护矩阵与系统红线库
│   ├── scanner.py               # 规则驱动的体检与多维状态识别
│   ├── cleaner.py               # 安全移入系统废纸篓执行引擎
│   ├── ui.py                    # 终端视觉与四级色彩徽标
│   └── cli.py                   # 命令行交互与调度
├── tests/                       # 单元测试套件 (19 项全覆盖)
├── pyproject.toml
├── setup.py
├── .gitignore
└── README.md
```

---

## 📦 安装与配置 (Installation)

### 方式 1: 直接从 GitHub 一键安装 (推荐)

无需下载源码，直接使用 `pip` 或 `pipx` 即可安装到系统中：

```bash
# 使用 pip 安装到当前用户空间
pip install --user git+https://github.com/yourwayai/sea-otter.git

# 或者使用 pipx 进行独立环境隔离安装
pipx install git+https://github.com/yourwayai/sea-otter.git
```

> **提示**：安装完成后，请确保 `~/.local/bin` 或 `~/Library/Python/3.x/bin` 已在您的系统 `PATH` 中。

---

### 方式 2: 源码克隆与本地安装 (开发者模式)

如果您希望本地调试或为 Sea-Otter 贡献规则：

```bash
# 1. 克隆代码仓库
git clone https://github.com/yourwayai/sea-otter.git
cd sea-otter

# 2. 安装可编辑开发版本
pip install --user -e .

# 3. 挂载到本地 PATH (可选，便于在任意目录执行)
ln -sf $(python3 -m site --user-base)/bin/sea-otter ~/.local/bin/sea-otter
```

---

### 方式 3: 免安装直接运行 (Zero Install)

克隆项目后直接执行根目录的脚本即可：

```bash
git clone https://github.com/yourwayai/sea-otter.git
cd sea-otter
./sea-otter scan
```

---

## 💻 CLI 使用指南

### 1. 扫描与体检 (`scan`)
输出带有四级安全风险色彩徽标、软件存活状态及空间汇总报告：

```bash
# 默认扫描所有规则，并输出空间占用与四级安全矩阵汇总
sea-otter scan

# 仅扫描指定的一个或多个工具
sea-otter scan cursor codex claude-code

# 显示所有工具（包含未安装且整洁无残留的项）
sea-otter scan --all

# 以 JSON 格式输出（带 risk_level，供 Raycast 插件或第三方脚本调用）
sea-otter scan --json
```

### 2. 安全清理 (`clean`)
默认仅清理通过安全仲裁的 **L1（极低风险）** 与 **L2（明确已卸载）** 孤儿残留，所有被清理项安全移入 macOS 废纸篓：

```bash
# Dry-run 模拟预览（只读模式，不修改任何文件系统）
sea-otter clean --dry-run
sea-otter clean cursor --dry-run

# 仅清理纯缓存（Cache）分类
sea-otter clean --category caches --dry-run

# 纳入 L3 在用软件减负项（如正在使用的软件本地模型权重、日志缓存）
sea-otter clean --include-l3 --dry-run

# 包含敏感凭据一起清理（默认会保护跳过 Token/密钥）
sea-otter clean --include-secrets

# 免交互确认直接清理
sea-otter clean cursor -y
```

### 3. 规则库查看与校验 (`rules`)
```bash
# 查看内置收录的工具规则列表
sea-otter rules list

# 校验所有规则的 YAML 规范与字段完整性
sea-otter rules validate
```

---

## 🚀 规划路线 (Roadmap)

- [x] **Phase 1: 规则规范定义与首批核心工具指纹库** (14 款主流核心 AI 工具)
- [x] **Phase 2: 本地扫描与安全矩阵引擎**
  - [x] **四级安全防护矩阵 (L1 ~ L4)** 与系统红线库 (`com.apple.TCC` 等)
  - [x] 进程表与单例锁活跃存活交叉验证（如 Hermes 守护保护）
  - [x] 代码仓库与工作区资产绝对免疫（`.git`, `.svn`, `.obsidian`）
  - [x] 智能嵌套去重与 macOS 系统原生废纸篓软着陆隔离
- [ ] **Phase 3: 现代扫描穿透与端侧模型治理 (v1.2 架构演进)**
  - [ ] 跨平台 Bug 与根目录散落探测 (`(null)` 幽灵目录、散落锁文件)
  - [ ] Chrome 4GB 端侧大模型 (`OptGuideOnDeviceModel` / Gemini Nano) 专项裁剪
  - [ ] 多通道发布孤岛检测（Edge / Chrome Stable vs Canary/Dev 活跃度交叉仲裁）
  - [ ] 原子隔离归档与一键无损回滚系统 (`sea-otter rollback [session_id]`)
- [ ] **Phase 4: Agentic 接口与生态交付**
  - [ ] Antigravity / Claude Code 原生 MCP Server 支持
  - [ ] Raycast 扩展插件与 Homebrew 分发

