<p align="center">
  <img src="assets/logo.png" alt="Sea-Otter Logo" width="180" style="border-radius: 20px;">
</p>

<h1 align="center">Sea-Otter 🦦</h1>

<p align="center">
  <strong>DevSweep Engine · Precision Health Inspection & Cleanup Tool for Next-Gen AI Coding Assistants & Agent CLIs</strong><br>
  <em>Clean your AI developer tools just like an otter grooms its fur!</em>
</p>

<p align="center">
  <a href="https://github.com/yourwayai/sea-otter/releases"><img src="https://img.shields.io/badge/version-1.0.0-blue.svg" alt="Version"></a>
  <a href="https://github.com/yourwayai/sea-otter"><img src="https://img.shields.io/badge/schema-v1.2-purple.svg" alt="Rule Schema v1.2"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License"></a>
  <a href="https://github.com/yourwayai/sea-otter"><img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey.svg" alt="Platform"></a>
  <a href="README.md"><img src="https://img.shields.io/badge/docs-中文文档-orange.svg" alt="Chinese Docs"></a>
</p>

---

## 🌟 Why Sea-Otter?

Traditional Mac cleanup apps (such as CleanMyMac or AppCleaner) typically rely on an "App Bundle-centric" heuristic, checking Bundle ID folders under `~/Library`. This breaks down against modern AI coding assistants, on-device LLMs, and autonomous Agent CLIs (e.g., Claude Code, Codex, Cherry Studio, Cursor, Windsurf, Trae, Ollama, Hermes, 5ire):

- **Hidden Dotfile Blindspots**: Databases, caches, and configs are scattered across hidden home directories like `~/.claude`, `~/.codex`, `~/.gemini`, and `~/.ollama`.
- **Silent On-Device AI Models & Vector Stores**: Browsers silently pull **4.0 GB Gemini Nano** (`OptGuideOnDeviceModel`), while Electron AI clients accumulate gigabytes of chat attachments (`Data/Files`) and `IndexedDB` vector embeddings.
- **Root-Level Ghost Bugs & Channel Islands**: Cross-platform bugs drop `(null)` directories, `default.store`, `.ACCC_Lock`, or empty skeleton trees directly into `~/Library/Application Support/`, while unused Canary/Dev/Beta browser channels linger for months.
- **Orphan Residuals & Plaintext Secrets**: After uninstalling an app, SQLite histories, OAuth Refresh Tokens, and API keys remain exposed without sensitivity tagging or safe rollback.
- **Accidental Workspace Damage**: AI agents often store `.git` repositories or workspaces under user folders; conventional cleaners lack repository immunity guardrails.

---

## ✨ Key Capabilities (v1.2 Architecture)

- 🧠 **On-Device AI Model Engine (`AIModelScanner`)**: Detects `.gguf`, `.safetensors`, `.onnx`, `.bin`, `.pt`, `.pth`, `GGUF` magic headers, and Chrome Optimization Guide (`Gemini Nano`). Supports `scan/clean --models` to prune multi-GB weights without touching user profiles.
- ✂️ **Fine-Grained Slimming Mode (`--slim`)**: Recursively expands `sub_targets` and `prunable` markers to trim large chat attachments (`Data/Files`) and vector indices (`IndexedDB`) while protecting core databases (e.g., `cherrystudio.sqlite`) and configs.
- 👻 **Root Orphan & Ghost Bug Scanner (`RootOrphanScanner`, `--ghosts`)**: Scans storage root entries directly to catch `^(\(null\)|undefined|null|none|\s+)$` directories, legacy unpacked assets (`2052-TM*`), misplaced CoreData files (`default.store*`), dead locks (`.ACCC_Lock`, `.ADCS_Lock`), and `< 64KB` skeleton empty directories.
- 🏝️ **Multi-Channel Redundancy Cross-Check (`ChannelRedundancyScanner`, `--channels`)**: Links Chrome, Edge, and VS Code channel families; flags Canary/Dev/Beta/Insiders channels inactive for **> 90 days** while Stable is actively used.
- 🔗 **Three-Tier Reverse Association Engine (`AssociationEngine`, `--associations`)**: Resolves decoupled app/folder names via `Info.plist` / `CFBundleIdentifier` lookup, curated signature DB (`Code` → VS Code, `com.openai.chat` → ChatGPT), and **180-day** idle heuristic probing.
- 🔑 **Deep Secret Leak Auditing (`SecretLeakAuditor`, `--secrets`)**: Audits JSON, YAML, `.env`, PEM private keys, and read-only SQLite databases for plaintext `access_token`, `api_key`, `secret`, and `private_key` (without exposing raw values), displaying high-risk privacy badges and pre-clean backup/wipe warnings.
- ⏪ **Atomic Quarantine & Lossless Rollback (`sea-otter rollback`)**: Archives cleaned items into `~/.Trash/AppSupport_Cleanup_<timestamp>/` with a structured `manifest.json` (v1.2.0), automatic name collision disambiguation, conflict protection, and one-command restoration.

---

## 🛡️ Core Safety Guardrails: Four-Tier Safety Risk Matrix

For modern developers and AI storage governance, **safety precedes everything**. Sea-Otter enforces a Four-Tier Safety Risk Matrix:

| Tier | Definition | Typical Targets | Selection & Cleanup Strategy |
| :--- | :--- | :--- | :--- |
| **🟢 L1: Zero-Impact Junk** | Pure junk files, dead locks, cross-platform bug dirs, pure caches | `(null)` ghost dir, `default.store`, `.ACCC_Lock`, skeleton dirs, browser caches | **Selected by default**, archived safely |
| **🟡 L2: Orphaned Apps** | Residual data from uninstalled apps or uninstalled stale channels | Abandoned `Codex`, `Cursor`, uninstalled `Chrome Beta` channel data | **Selected by default**, isolated to quarantine |
| **🟠 L3: In-Use Bloatware** | Active apps with bloated weights, attachments, or caches | Chrome on-device LLMs (4 GB), Cherry Studio attachments/vectors, active caches | **Unselected by default**, requires `--include-l3` or `--models`/`--slim`/`--channels` |
| **🔴 L4: Protected System** | macOS critical databases, code workspaces, active processes | `com.apple.TCC`, `AddressBook`, `CloudDocs`, `.git` repos, running daemons | **Hardcoded block**, strictly forbidden to delete |

### Four Absolute Safety Pillars

1. **System Redline Vault (Hardcoded Immunity)**:
   - Strictly blocks `com.apple.TCC`, `AddressBook`, `CallHistoryDB`, `CloudDocs`, `Keychain`, `com.apple.sharedfilelist`, `Safari`, `Mail`, `Photos`, and native macOS system folders.
2. **Multi-Dimensional Survival Cross-Validation (Process & Lock Guard)**:
   - Cross-references the system process table (`pgrep`), background daemons, and singleton locks (`SingletonLock`). Active apps are locked as **`🔵 Running (Protected)`**.
3. **Code Workspace & Repository Immunity**:
   - Probes candidate paths for `.git`, `.svn`, `.hg`, and `.obsidian`, and enforces `exclude_paths` (including wildcard descendant checks) to guarantee zero accidental loss of source code or user settings.
4. **Atomic Quarantine & Secret Auditing**:
   - Moves cleaned targets into `~/.Trash/AppSupport_Cleanup_<timestamp>/` with `manifest.json` for lossless `sea-otter rollback`; plaintext OAuth tokens and keys are tagged with 🔑 and skipped unless explicitly authorized.

---

## 🗂 Project Structure

```text
sea-otter/
├── assets/                      # Brand assets (banner, logo, icons)
│   ├── banner.jpg
│   └── logo.png
├── schema/                      # Rule schema specification (v1.2)
│   └── rule.schema.json
├── rules/                       # 19 curated high-precision rules (YAML)
│   ├── 5ire.yaml                # 5ire AI Desktop (BGE-M3 model weights)
│   ├── alma.yaml                # Alma AI Agent
│   ├── bolt.yaml                # Bolt (bolt.new / Bolt.diy)
│   ├── cherry-studio.yaml       # Cherry Studio (fine-grained attachments & vector DB)
│   ├── claude-code.yaml         # Anthropic Claude Code CLI
│   ├── codex.yaml               # OpenAI Codex CLI
│   ├── cursor.yaml              # Cursor (AI IDE)
│   ├── gemini-antigravity.yaml  # Google Antigravity & Gemini CLI
│   ├── google-chrome.yaml       # Google Chrome (Gemini Nano, channels, ghost rules)
│   ├── hermes.yaml              # Hermes Agent (Daemon & Supervisor)
│   ├── kiro.yaml                # Kiro IDE
│   ├── lark-and-steam.yaml      # Lark/Feishu & Steam orphans (protects games & saves)
│   ├── microsoft-edge.yaml      # Microsoft Edge (multi-channel matrix & on-device models)
│   ├── ollama.yaml              # Ollama Local LLM Runtime
│   ├── trae.yaml                # ByteDance Trae AI IDE
│   ├── vscode.yaml              # Visual Studio Code (multi-channel matrix & caches)
│   ├── wechat-devtools.yaml     # WeChat DevTools (simulator & build caches)
│   ├── windsurf.yaml            # Codeium Windsurf Editor
│   └── workbuddy.yaml           # WorkBuddy AI
├── docs/                        # Architecture guides & design protocols
│   ├── architecture-and-lessons-learned.md
│   ├── rule-schema.md
│   └── todo-roadmap.md
├── sea_otter/                   # Python package engine (includes synced rules/ & schema/)
│   ├── safety.py                # Four-Tier Safety Matrix & System Redline Vault
│   ├── scanner.py               # RuleScanner / AIModelScanner / SecretLeakAuditor / RootOrphanScanner / ChannelRedundancyScanner / AssociationEngine
│   ├── cleaner.py               # SafeCleaner & QuarantineManager (atomic archive & rollback)
│   ├── validator.py             # Zero-dependency Rule Schema v1.2 validator
│   ├── ui.py                    # Terminal formatting & badges
│   └── cli.py                   # CLI dispatcher & interactive console
├── tests/
│   └── test_suite.py            # Automated unit test suite (61 tests)
├── pyproject.toml               # PEP 517 / 621 package metadata
├── README.md                    # Chinese Documentation
└── README_EN.md                 # English Documentation
```

---

## 📦 Installation

### Method 1: Install directly via GitHub (Recommended)

```bash
# Install to current user environment via pip
pip install --user git+https://github.com/yourwayai/sea-otter.git

# Or install in an isolated environment via pipx
pipx install git+https://github.com/yourwayai/sea-otter.git
```

> **Note**: Please make sure `~/.local/bin` is included in your system `PATH`.

---

### Method 2: Clone and Install Locally (Developer Mode)

```bash
git clone https://github.com/yourwayai/sea-otter.git
cd sea-otter
pip install --user -e .
ln -sf $(python3 -m site --user-base)/bin/sea-otter ~/.local/bin/sea-otter
```

---

### Method 3: Zero-Install Run

Run directly from source without installing:

```bash
git clone https://github.com/yourwayai/sea-otter.git
cd sea-otter
./sea-otter scan
```

---

## 💻 CLI Usage Guide

Run `sea-otter` with no arguments to open the interactive console, or use subcommands directly for automation:

### 1. Health Inspection (`scan`)
```bash
# Scan all 19 rules, root-level orphans, and multi-channel redundancies
sea-otter scan

# Scan specific tools only
sea-otter scan cursor codex google-chrome

# Scan on-device AI model weights only (Gemini Nano, GGUF, BGE-M3)
sea-otter scan --models

# Scan prunable slimming targets (chat attachments, vector DBs, caches)
sea-otter scan --slim

# Scan root-level ghost directories, scattered files, dead locks & skeleton dirs (L1)
sea-otter scan --ghosts

# Scan stale preview/dev browser & IDE channels (> 90 days inactive)
sea-otter scan --channels

# Scan decoupled orphan directories via 3-tier reverse association (Plist / Signature DB / 180-day heuristic)
sea-otter scan --associations

# Run deep privacy audit for plaintext OAuth tokens, API keys, and private keys
sea-otter scan --secrets

# Include clean tools with zero residuals
sea-otter scan --all

# Output structured JSON (with risk_level, ghost_type, channel_name, etc.)
sea-otter scan --json
```

### 2. Safe Cleanup (`clean`)
```bash
# Dry-run preview (Read-only simulation; zero file changes)
sea-otter clean --dry-run
sea-otter clean cursor --dry-run

# Prune on-device AI model weights only (preserves host app configs)
sea-otter clean --models --dry-run

# Slimming mode: prune attachments, vector embeddings, and caches while guarding SQLite DBs
sea-otter clean cherry-studio --slim --dry-run

# Clean L1 root-level ghost directories, scattered files, and empty skeletons
sea-otter clean --ghosts --dry-run

# Clean stale Canary/Dev/Beta channels inactive for > 90 days
sea-otter clean --channels --dry-run

# Clean orphaned app directories resolved by the 3-tier Association Engine
sea-otter clean --associations --dry-run

# Clean only pure caches across all tools
sea-otter clean --category caches --dry-run

# Include L3 in-use bloatware or sensitive credentials
sea-otter clean --include-l3 --dry-run
sea-otter clean cursor --include-secrets --dry-run

# Execute cleanup without interactive confirmation (archives to ~/.Trash quarantine)
sea-otter clean cursor -y
```

### 3. Atomic Quarantine & Lossless Rollback (`rollback`)
```bash
# List all quarantine cleanup sessions and manifest summaries
sea-otter rollback --list

# Preview restoring the latest quarantine session
sea-otter rollback --dry-run

# Restore the latest (or specific) cleanup session losslessly to original paths
sea-otter rollback
sea-otter rollback cleanup_20261125_114500 -y

# Force overwrite if files were recreated at original paths
sea-otter rollback cleanup_20261125_114500 --force -y
```

### 4. Rules Validation (`rules`) & Project Info (`about`)
```bash
# List all 19 curated rules
sea-otter rules list

# Validate YAML syntax, channels, ghost_rules, and Schema v1.2 compliance
sea-otter rules validate

# Show project philosophy and safety guardrails
sea-otter about
```

---

## 🗺️ Roadmap

- [x] **Phase 1 & P0: Core Safety Matrix & AI Asset Governance**
  - [x] **Four-Tier Safety Risk Matrix (L1 ~ L4)**, System Redline Vault (`com.apple.TCC`), Process/Lock Guard, `.git` Immunity
  - [x] **On-Device AI Model Engine (`AIModelScanner`)** (`.gguf`, `.safetensors`, `.onnx`, Chrome 4GB Gemini Nano)
  - [x] **Fine-Grained Slimming Mode (`--slim`)** (`sub_targets` expansion & core DB exclusion)
  - [x] **Rule Schema v1.2 & Deep Validator (`validator.py`)**
- [x] **Phase 2 & P1: Scanner Penetration & Atomic Rollback**
  - [x] **Root Orphan Scanner (`RootOrphanScanner`)**: `(null)` ghost dirs, scattered files, dead locks, `< 64KB` skeleton dirs
  - [x] **Multi-Channel Redundancy Arbiter (`ChannelRedundancyScanner`)**: 90-day Stable vs Canary/Dev/Beta cross-check
  - [x] **Atomic Quarantine & Lossless Rollback (`sea-otter rollback`)**: `manifest.json` archival & restoration
  - [x] **Official Rules Expansion Round 1**: Chrome, Edge, WeChat DevTools, Lark/Steam, VS Code (19 rules total)
- [ ] **Phase 3 & P2: Ecosystem Expansion & Agentic Integration**
  - [x] Three-tier reverse Association Engine for decoupled app/folder names
  - [x] Deep Secret Leak Warning for plaintext OAuth tokens and API keys
  - [ ] Native Antigravity / Claude Code MCP Server (`sea-otter-mcp`)
  - [ ] Concurrent I/O scanning optimization (`os.scandir` + `ThreadPoolExecutor`)

---

## 🤝 Contributing

Contributions of new tool rules or improvements are warmly welcome!
1. Check the [Schema v1.2 Specification](schema/rule.schema.json).
2. Add or update `<tool-id>.yaml` under `rules/` (and `sea_otter/rules/`).
3. Run `sea-otter rules validate` and `python3 -m unittest tests.test_suite` to verify compliance.
4. Submit a Pull Request.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
