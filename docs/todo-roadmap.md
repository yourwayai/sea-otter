# Sea-Otter (DevSweep) 演进路线与待办清单 (Optimization Backlog)

> **版本定位**：基于 [architecture-and-lessons-learned.md](architecture-and-lessons-learned.md) (v1.2 Milestone Release) 实战指南提炼，记录项目后续的迭代规划与具体待办项。  
> **更新状态**：已完成第 1 项（四级安全防护矩阵落地），剩余 **11 项待办任务** 如下。

---

## 📋 待办进度看板 (Kanban)

```
[ 已完成 (1) ] ──────────> [ 进行中 (0) ] ──────────> [ 待开始 (11) ]
• 四级安全矩阵 (L1~L4)                                 • P0 阶段: 3 项
                                                       • P1 阶段: 4 项
                                                       • P2 阶段: 4 项
```

---

## 阶段一：P0 核心资产与模型细分治理（最高优先级）

### [ ] Task 01: 端侧大模型与权重专项识别引擎 (AIModelScanner)
* **痛点/价值**：以 Google Chrome 为代表的现代软件会静默拉取 4GB 的端侧大模型（`OptGuideOnDeviceModel` / Gemini Nano），Ollama、Jan、Cherry Studio 也会下载海量权重（`.gguf`、`.safetensors`），传统清理工具对此完全失明。
* **涉及模块**：
  * `sea_otter/scanner.py`（增加模型扩展名与特征嗅探）
  * `rules/google-chrome.yaml`（新增 Chrome 端侧模型规则）
* **验收标准**：
  1. 能独立嗅探 `.gguf` / `.safetensors` / `.onnx` / `.bin` 大模型权重文件；
  2. 独立识别 Chrome 端侧模型并高亮标注 `[本地模型权重 (4.0 GB)]`；
  3. 支持独立裁剪模型文件而不损毁宿主软件的运行配置。

---

### [ ] Task 02: 本地会话库与向量嵌入细粒度裁剪模式
* **痛点/价值**：Electron 类 AI 客户端（如 Cherry Studio）呈现“二进制附件 + 向量嵌入”双重膨胀，用户往往只想清理海量临时图片/PDF 会话附件（`Data/` 1.5GB）或过期的向量数据库（`IndexedDB/` 1.2GB），而希望保留助手 Prompt 预设与核心对话文本。
* **涉及模块**：
  * `rules/cherry-studio.yaml`
  * `sea_otter/scanner.py`
  * `sea_otter/cli.py`（支持细粒度子项勾选或按子目标裁剪）
* **验收标准**：
  1. 支持将单一工具的数据目录拆分为细粒度子项目；
  2. 提供“保留配置与对话，仅清除会话大附件与过期嵌入向量库”的安全减负模式。

---

### [ ] Task 03: 规则库 Schema v1.2 升级与数据规范校验
* **痛点/价值**：目前的 `schema/rule.schema.json` 缺少对发布通道分支、端侧模型特征与幽灵目录规则的约束。
* **涉及模块**：
  * `schema/rule.schema.json`
  * `sea_otter/schema/rule.schema.json`
  * `sea_otter/cli.py` (`cmd_rules validate`)
* **验收标准**：
  1. Schema 新增 `channels`（多通道分支矩阵定义，含 `current_channel`、`related_channels`）；
  2. Schema 新增 `targets.ai_models`（支持 `is_model_weight`、`regenerable` 声明）；
  3. Schema 新增 `ghost_rules`（支持 `root_patterns` 正则规则）；
  4. 运行 `sea-otter rules validate` 能全面校验新老规则。

---

## 阶段二：P1 扫描盲区穿透与原子无损回滚（系统级鲁棒性）

### [ ] Task 04: 跨平台代码 Bug 与根目录散落探测引擎 (RootOrphanScanner)
* **痛点/价值**：传统清理软件假设“软件一定会规矩地把文件写在二级子目录”。现实中，跨平台代码 Bug 经常在 `~/Library/Application Support/` 直属根节点生成 `(null)` 幽灵目录、10 年前解包的中文引导图（`2052-TM1000*.png`）、死锁标记（`.ACCC_Lock`）与骨架空目录（`ProApps`）。
* **涉及模块**：
  * `sea_otter/scanner.py`（新增根节点遍历与正则异常探测）
  * `sea_otter/ui.py`
* **验收标准**：
  1. 准确正则捕获异常目录：`^(\(null\)|undefined|null|none|\s+)$`；
  2. 捕获根节点散落的历史解包单文件与死锁标志；
  3. 识别大小 `< 64KB` 且子孙项全空的骨架空目录（Skeleton Dirs）；
  4. 归类至 **L1 极低风险**，支持一键安全清理。

---

### [ ] Task 05: 浏览器与 IDE 多通道发布孤岛检测引擎 (ChannelRedundancyScanner)
* **痛点/价值**：开发者常并存安装前沿测试版（Canary / Dev / Beta）与正式版（Stable）。当用户已稳定在正式版时，测试通道往往长期滞留数百兆无用缓存。
* **涉及模块**：
  * `sea_otter/scanner.py`
  * `rules/microsoft-edge.yaml` / `rules/google-chrome.yaml`
* **验收标准**：
  1. 自动关联产品家族通道矩阵（Edge / Edge Canary / Edge Dev；Chrome / Chrome Beta / Chrome Canary）；
  2. 实现活跃度交叉仲裁（Channel Cross-Check）：当正式版高频使用，而测试通道超过 90 天未启动时，提示用户“一键清理停用的测试通道”。

---

### [ ] Task 06: 原子隔离区与一键无损回滚系统 (`sea-otter rollback`)
* **痛点/价值**：直接调用系统删除操作即使放入废纸篓，在面对上百个散落文件时也很难定位和精准恢复。必须实现带元数据清单的原子归档。
* **涉及模块**：
  * `sea_otter/cleaner.py`（建立时间戳隔离区与 manifest）
  * `sea_otter/cli.py`（新增 `rollback` 子命令）
* **验收标准**：
  1. 清理时在 `~/.Trash/AppSupport_Cleanup_<timestamp>/` 建立隔离目录；
  2. 自动生成标准 `manifest.json`，完整记录原始绝对路径、时间戳、所属 App、大小与风险等级；
  3. 执行 `sea-otter rollback [session_id]` 可逐条将隔离文件安全恢复至原路径。

---

### [ ] Task 07: 官方规则库第一轮扩充 (Chrome / Edge / 微信开发者工具 / 飞书)
* **痛点/价值**：将实战排查中发现的大头软件规则正式纳入官方仓库。
* **涉及模块**：
  * `rules/google-chrome.yaml`（端侧模型、组件缓存）
  * `rules/microsoft-edge.yaml`（多通道分支）
  * `rules/wechat-devtools.yaml`（微信 web 开发者工具模拟器与项目缓存）
  * `rules/lark-and-steam.yaml`（飞书离线历史与 Steam 孤儿库）
* **验收标准**：
  1. 新增 4 款以上高频软件规则；
  2. 经真机扫描验证，能识别出实机中的典型残留占用。

---

## 阶段三：P2 生态扩展、反向推导与体验演进（长效价值）

### [ ] Task 08: 应用名与路径脱节的三级反向映射引擎 (Association Engine)
* **痛点/价值**：解决“应用叫 VS Code，目录叫 Code；应用叫 ChatGPT，目录叫 com.openai.chat”导致的 79+ 款已卸载历史应用漏报难题。
* **涉及模块**：
  * `sea_otter/scanner.py`（孤儿目录反向推导算法）
* **验收标准**：
  1. 一级：通过目录下 `Info.plist` / `CFBundleIdentifier` 反查应用；
  2. 二级：内置已知高频特征字典反查；
  3. 三级：启发式探测（无对应应用且超过 180 天未被任何进程访问）。

---

### [ ] Task 09: 敏感凭据与 API Key 深度隐私审计 (Secret Leak Warning)
* **痛点/价值**：废弃应用残留的 SQLite 或 JSON 文件中常保存有明文 OAuth Token 或 API Key（如 WorkBuddy 残留明文 Token），存在本地信息泄露隐患。
* **涉及模块**：
  * `sea_otter/scanner.py`
  * `sea_otter/ui.py`
* **验收标准**：
  1. 深度检测常见的凭据文件名与敏感键名（`access_token`、`api_key`、`secret`、`private_key`）；
  2. 终端展示明显的隐私告警标志，并在清理前提示用户备份或安全抹除。

---

### [ ] Task 10: Agentic MCP Server 原生接口集成
* **痛点/价值**：现代开发者通过自然语言直接在 Antigravity、Claude Code、Cursor 中与 AI 协作，工具应具备原生 Agentic 能力。
* **涉及模块**：
  * `sea_otter/mcp_server.py`（全新模块）
  * `pyproject.toml`（暴露 `sea-otter-mcp` 入口）
* **验收标准**：
  1. 符合标准 Model Context Protocol (MCP) 规范；
  2. 暴露 `sea_otter_scan`、`sea_otter_clean`、`sea_otter_rollback` 工具给 AI Agent 调用；
  3. 支持在 AI 对话中直接查看空间占用与交互确认减负。

---

### [ ] Task 11: 扫描并发与 I/O 性能优化
* **痛点/价值**：当用户目录中存在大量深度目录或海量小文件时，单线程扫描会产生可感知的 I/O 阻塞。
* **涉及模块**：
  * `sea_otter/scanner.py`
* **验收标准**：
  1. 使用轻量高效的 `os.scandir` 全面替代 `os.walk`；
  2. 引入 `concurrent.futures.ThreadPoolExecutor` 并行扫描多款工具；
  3. 全盘规则扫描耗时缩短 50% 以上。

---

## 💡 推进建议

建议后续按照以下节奏，按需分批次完成：
* **第一步**：实现 **Task 01 (端侧大模型识别)** 与 **Task 03 (Schema v1.2)**；
* **第二步**：实现 **Task 04 (`(null)` 幽灵目录探测)** 与 **Task 06 (`manifest.json` 回滚系统)**；
* **第三步**：规则扩充与 MCP Server 封装。
