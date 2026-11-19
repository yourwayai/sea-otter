# Sea-Otter (DevSweep) 演进路线与待办清单 (Optimization Backlog)

> **版本定位**：基于 [architecture-and-lessons-learned.md](architecture-and-lessons-learned.md) (v1.2 Milestone Release) 实战指南提炼，记录项目后续的迭代规划与具体待办项。  
> **更新状态**：已完成前 4 项（四级安全防护矩阵、端侧大模型识别引擎、本地会话与向量裁剪、Schema v1.2 规范与校验），**P0 阶段全部圆满达成**，剩余 **8 项待办任务** 如下。

---

## 📋 待办进度看板 (Kanban)

```
[ 已完成 (4) ] ──────────> [ 进行中 (0) ] ──────────> [ 待开始 (8) ]
• 四级安全矩阵 (L1~L4)                                 • P0 阶段: 0 项 (全部达成!)
• 端侧大模型引擎 (AIModelScanner)                      • P1 阶段: 4 项
• 细粒度会话与向量裁剪 (Slim Mode)                     • P2 阶段: 4 项
• 规则 Schema v1.2 规范与校验 (Validator)
```

---

## 阶段一：P0 核心资产与模型细分治理（最高优先级，已全部完成 🎉）

### [x] Task 01: 端侧大模型与权重专项识别引擎 (AIModelScanner)
* **痛点/价值**：以 Google Chrome 为代表的现代软件会静默拉取 4GB 的端侧大模型（`OptGuideOnDeviceModel` / Gemini Nano），Ollama、Jan、Cherry Studio 也会下载海量权重（`.gguf`、`.safetensors`），传统清理工具对此完全失明。
* **涉及模块**：
  * `sea_otter/scanner.py`（实现 `AIModelScanner`，支持 `.gguf`, `.safetensors`, `.onnx`, `.bin`, `.pt`, `GGUF` Magic Header 嗅探与 Chrome Optimization Guide 解析）
  * `rules/google-chrome.yaml` / `sea_otter/rules/google-chrome.yaml`（新增 Chrome 端侧模型与缓存规则，严密排除 `Default/` 与 `Profile *` 用户目录）
  * `sea_otter/ui.py`（增加 `get_model_badge` 视觉标签 `🧠[本地模型权重 (4.0 GB)]`）
  * `sea_otter/cli.py`（支持 `scan -m / --models` 与 `clean --models` 专项扫描与修剪模式）
  * `schema/rule.schema.json`（扩充 `is_model_weight`, `model_name`, `model_format`, `regenerable` 规范）
* **验收结果**：
  1. ✅ 能够精准嗅探并识别 `.gguf`、`.safetensors`、`.onnx`、`.bin`、`.pt` 及 Magic Header；
  2. ✅ 准确识别系统上真实存在的 Chrome Gemini Nano（`OptGuideOnDeviceModel`，4.0 GB）并在 CLI 呈现醒目标签；
  3. ✅ 支持通过 `sea-otter clean --models` 进行独立模型修剪减负，安全保护宿主应用账号与配置；
  4. ✅ 单元测试全套覆盖并通过验证。

---

### [x] Task 02: 本地会话库与向量嵌入细粒度裁剪模式
* **痛点/价值**：Electron 类 AI 客户端（如 Cherry Studio）呈现“二进制附件 + 向量嵌入”双重膨胀，用户往往只想清理海量临时图片/PDF 会话附件（`Data/` 1.5GB）或过期的向量数据库（`IndexedDB/` 1.2GB），而希望保留助手 Prompt 预设与核心对话文本。
* **涉及模块**：
  * `rules/cherry-studio.yaml` / `sea_otter/rules/cherry-studio.yaml`（将单一工作区细分拆解为会话大附件、向量嵌入库、知识库文档与渲染缓存）
  * `sea_otter/scanner.py`（`TargetMatch` 扩充 `prunable`、`sub_target_of`、`regenerable` 属性，支持嵌套 `sub_targets` 递归解析与去重）
  * `sea_otter/safety.py`（安全防线增强通配符排除检查，保护父目录不被误删）
  * `sea_otter/ui.py`（新增 `get_prunable_badge` 标识 `📎[会话大附件]`、`🛠️[运行时组件]` 与 `✂️[可减负]`）
  * `sea_otter/cli.py`（新增 `clean -s / --slim` 安全减负模式，自动放行 L3 减负项同时硬隔离核心数据库）
  * `schema/rule.schema.json`（扩充 `prunable` 与 `sub_targets` 规范）
* **验收结果**：
  1. ✅ 将 Cherry Studio 单一目录成功拆分为 14 处细粒度子项，精准识别本机实机存在的 **1.3 GB 会话大附件** 与 **1.2 GB 向量数据库**（共释放 3.0 GB）；
  2. ✅ 提供 `sea-otter clean --slim` 安全减负模式，仅清除附件、向量库与渲染缓存，100% 保留核心会话数据库（`cherrystudio.sqlite`）、助手 Prompt 模板与 API 密钥；
  3. ✅ 单元测试全覆盖，验证规则结构、子项目解析与排除保护。

---

### [x] Task 03: 规则库 Schema v1.2 升级与数据规范校验
* **痛点/价值**：此前的 `schema/rule.schema.json` 缺少对发布通道分支、端侧模型特征与幽灵目录规则的约束，验证时缺少全字段深度语义校验。
* **涉及模块**：
  * `schema/rule.schema.json` & `sea_otter/schema/rule.schema.json`（全面升级至 Schema v1.2）
  * `sea_otter/validator.py`（实现轻量零依赖的 Rule Schema v1.2 深度校验器）
  * `sea_otter/cli.py` (`cmd_rules validate` 支持展示通道分支与幽灵规则状态）
  * `rules/google-chrome.yaml` / `sea_otter/rules/google-chrome.yaml`（落地 channels 与 ghost_rules 生产示例）
* **验收结果**：
  1. ✅ Schema 新增 `channels`（定义 `current_channel` 与 `related_channels` 矩阵）；
  2. ✅ Schema 完善 `targets.ai_models`（包含 `is_model_weight`、`model_name`、`model_format`、`regenerable`、`prunable`、`sub_targets` 声明）；
  3. ✅ Schema 新增 `ghost_rules`（支持 `root_patterns` 与正则表达式语法校验）；
  4. ✅ 运行 `sea-otter rules validate` 成功全量校验当前 15 条内置规则，并输出通道与幽灵规则特征；
  5. ✅ 单元测试新增 `TestRuleSchemaV12`，全覆盖正常与各类异常（非法 ID、非法类别、缺少字段、无效正则等）场景。

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
