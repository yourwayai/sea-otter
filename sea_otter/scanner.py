"""
扫描引擎核心模块 (Scanner Engine)
解析规则库，判定软件安装状态，递归计算文件空间与安全状态。
"""

import os
import re
import glob
import json
import time
import sqlite3
import plistlib
import subprocess
from urllib.parse import quote
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple, Set
import yaml

from sea_otter.safety import (
    normalize_path,
    validate_target_safety,
    assess_risk_level,
    contains_workspace_or_repo,
    is_system_redline_path,
    RiskLevel,
)

@dataclass
class TargetMatch:
    category: str
    raw_path: str
    resolved_path: str
    description: str
    size_bytes: int
    file_count: int
    contains_secrets: bool
    is_model_weight: bool
    default_selected: bool
    is_safe: bool
    safety_reason: str
    risk_level: str = RiskLevel.L2_ORPHAN.value
    model_name: Optional[str] = None
    model_format: Optional[str] = None
    prunable: bool = False
    sub_target_of: Optional[str] = None
    regenerable: bool = True
    ghost_type: Optional[str] = None
    channel_name: Optional[str] = None
    inactive_days: Optional[int] = None
    stable_channel_id: Optional[str] = None
    tool_id: Optional[str] = None
    tool_name: Optional[str] = None
    association_tier: Optional[int] = None
    association_method: Optional[str] = None
    associated_app: Optional[str] = None
    associated_bundle_id: Optional[str] = None
    secret_findings: List[str] = field(default_factory=list)
    secret_severity: Optional[str] = None

@dataclass
class AIModelInspectionResult:
    is_model_weight: bool = False
    model_name: Optional[str] = None
    model_format: Optional[str] = None
    total_weight_bytes: int = 0
    model_files_count: int = 0
    detected_files: List[str] = field(default_factory=list)

class AIModelScanner:
    """
    AI-Native 端侧大模型与权重文件专项识别引擎 (AIModelScanner)
    负责嗅探 .gguf, .safetensors, .onnx, .bin 等大模型权重及端侧模型目录。
    """
    # 明确支持的大模型权重文件扩展名
    KNOWN_MODEL_EXTENSIONS = {
        ".gguf": "GGUF",
        ".safetensors": "SafeTensors",
        ".onnx": "ONNX",
        ".bin": "Binary Weights",
        ".pt": "PyTorch Checkpoint",
        ".pth": "PyTorch Checkpoint",
        ".tflite": "TensorFlow Lite",
        ".mlmodel": "CoreML",
        ".mlpackage": "CoreML Package",
    }

    # 已知典型权重文件名模式
    KNOWN_MODEL_FILENAMES = {
        "weights.bin",
        "model.bin",
        "pytorch_model.bin",
        "consolidated.00.pth",
    }

    @classmethod
    def is_model_file(cls, filepath: str) -> tuple[bool, Optional[str]]:
        """判定单个文件是否为大模型权重文件 (通过扩展名、文件名或 Magic Bytes)"""
        basename = os.path.basename(filepath)
        lower_name = basename.lower()
        _, ext = os.path.splitext(lower_name)

        # 1. 明确扩展名命中
        if ext in [".gguf", ".safetensors", ".onnx", ".tflite", ".mlmodel"]:
            return True, cls.KNOWN_MODEL_EXTENSIONS[ext]

        if ext == ".pt":
            return True, cls.KNOWN_MODEL_EXTENSIONS[ext]

        if ext == ".pth":
            # 排除 Python site-packages 中的 .pth 路径配置文件 (通常极小且为纯文本)
            try:
                if os.path.isfile(filepath):
                    with open(filepath, "rb") as f:
                        magic = f.read(4)
                        # PyTorch .pth 通常是 zip (b"PK\x03\x04") 或 pickle (b"\x80")
                        if magic.startswith(b"PK") or magic.startswith(b"\x80"):
                            return True, cls.KNOWN_MODEL_EXTENSIONS[ext]
                        return False, None
            except Exception:
                return False, None
            return True, cls.KNOWN_MODEL_EXTENSIONS[ext]

        # 2. .bin 权重文件识别
        if lower_name in cls.KNOWN_MODEL_FILENAMES or lower_name.startswith("pytorch_model"):
            return True, "Binary Weights"

        if ext == ".bin":
            try:
                # 超过 10MB 的 .bin 文件或文件名包含 model/weight
                size = os.path.getsize(filepath)
                if size >= 10 * 1024 * 1024 or "model" in lower_name or "weight" in lower_name:
                    return True, "Binary Weights"
            except OSError:
                pass

        # 3. GGUF Magic Header 嗅探 (前 4 字节为 b"GGUF")
        try:
            if os.path.isfile(filepath) and os.path.getsize(filepath) >= 4:
                with open(filepath, "rb") as f:
                    header = f.read(4)
                    if header == b"GGUF":
                        return True, "GGUF"
        except (OSError, PermissionError):
            pass

        return False, None

    @classmethod
    def _inspect_chrome_optguide(cls, dirpath: str) -> Optional[tuple[str, str]]:
        """检测 Chrome Optimization Guide 端侧 Gemini Nano 模型"""
        if "optguideondevicemodel" in dirpath.lower():
            # 尝试解析子目录中的 manifest.json
            try:
                for root, _, files in os.walk(dirpath):
                    if "manifest.json" in files:
                        manifest_path = os.path.join(root, "manifest.json")
                        with open(manifest_path, "r", encoding="utf-8") as f:
                            data = json.load(f)
                            spec_name = data.get("BaseModelSpec", {}).get("name")
                            if spec_name:
                                return f"Gemini Nano ({spec_name})", "Chrome On-Device Weights (.bin)"
                            elif "name" in data:
                                return f"Gemini Nano ({data['name']})", "Chrome On-Device Weights (.bin)"
            except Exception:
                pass
            return "Gemini Nano", "Chrome On-Device Weights (.bin)"
        return None

    @classmethod
    def inspect_path(cls, path: str, max_files: int = 5000) -> AIModelInspectionResult:
        """
        全量探测指定路径自身或其内部是否包含大模型权重资产
        """
        normalized = normalize_path(path)
        if not os.path.exists(normalized):
            return AIModelInspectionResult()

        # 1. 目标本身为单文件
        if os.path.isfile(normalized) or os.path.islink(normalized):
            is_model, fmt = cls.is_model_file(normalized)
            if is_model:
                try:
                    fsize = os.path.getsize(normalized)
                except OSError:
                    fsize = 0
                model_name = os.path.splitext(os.path.basename(normalized))[0]
                return AIModelInspectionResult(
                    is_model_weight=True,
                    model_name=model_name,
                    model_format=fmt or "AI Model",
                    total_weight_bytes=fsize,
                    model_files_count=1,
                    detected_files=[normalized]
                )
            return AIModelInspectionResult()

        # 2. 目标为目录
        # 优先检测 Chrome Gemini Nano 特征
        chrome_info = cls._inspect_chrome_optguide(normalized)
        model_name = chrome_info[0] if chrome_info else None
        model_format = chrome_info[1] if chrome_info else None

        # 针对 Ollama 目录特定标记
        if ".ollama" in normalized and "models" in normalized:
            if not model_name:
                model_name = "Ollama Local LLM Library"
            if not model_format:
                model_format = "GGUF Blobs"

        # 针对 5ire / BGE-M3 目录特定标记
        if "5ire" in normalized and "transformers-models" in normalized:
            if not model_name:
                model_name = "BGE-M3 Embedding Model"
            if not model_format:
                model_format = "ONNX"

        # 针对 Cherry Studio 本地向量嵌入库与知识库
        if ("cherrystudio" in normalized.lower() or "cherry studio" in normalized.lower()):
            if "indexeddb" in normalized.lower():
                if not model_name:
                    model_name = "Vector Embeddings (IndexedDB)"
                if not model_format:
                    model_format = "IndexedDB Blob & LevelDB"
            elif "knowledgebase" in normalized.lower():
                if not model_name:
                    model_name = "KnowledgeBase Documents"
                if not model_format:
                    model_format = "Vector Knowledge Base"

        detected_files = []
        total_weight_bytes = 0
        formats_seen = set()
        scanned_count = 0

        try:
            for root, dirs, files in os.walk(normalized):
                # 排除 .git, venv, node_modules, site-packages 等虚拟环境或开发目录
                dirs[:] = [
                    d for d in dirs
                    if d.lower() not in {".git", "node_modules", "site-packages", "__pycache__", "dist-packages"}
                    and "venv" not in d.lower()
                    and not d.lower().startswith(".env")
                ]
                for f in files:
                    scanned_count += 1
                    if scanned_count > max_files:
                        break
                    fp = os.path.join(root, f)
                    is_model, fmt = cls.is_model_file(fp)
                    if is_model:
                        try:
                            fsize = os.path.getsize(fp)
                        except OSError:
                            fsize = 0
                        detected_files.append(fp)
                        total_weight_bytes += fsize
                        if fmt:
                            formats_seen.add(fmt)
                if scanned_count > max_files:
                    break
        except OSError:
            pass

        if detected_files:
            if not model_format and formats_seen:
                model_format = ", ".join(sorted(formats_seen))
            if not model_name:
                if len(detected_files) == 1:
                    model_name = os.path.splitext(os.path.basename(detected_files[0]))[0]
                else:
                    model_name = os.path.basename(normalized)

            return AIModelInspectionResult(
                is_model_weight=True,
                model_name=model_name,
                model_format=model_format or "AI Model",
                total_weight_bytes=total_weight_bytes,
                model_files_count=len(detected_files),
                detected_files=detected_files
            )

        # 如果目录命中了特定模型/向量库特征
        if model_name:
            return AIModelInspectionResult(
                is_model_weight=True,
                model_name=model_name,
                model_format=model_format or "Vector Embeddings",
                total_weight_bytes=total_weight_bytes,
                model_files_count=len(detected_files) or 1,
                detected_files=detected_files or [normalized]
            )

        return AIModelInspectionResult()


@dataclass
class SecretAuditResult:
    """敏感凭据与 API Key 深度隐私审计结果 (Secret Leak Warning)"""
    contains_secrets: bool = False
    severity: Optional[str] = None  # "high" | "medium" | None
    matched_files: List[str] = field(default_factory=list)
    matched_keys: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)


class SecretLeakAuditor:
    """
    敏感凭据与 API Key 深度隐私审计引擎 (SecretLeakAuditor)
    深度检测废弃或残留目录中的凭据文件与明文敏感键名（access_token, api_key, secret, private_key 等），
    仅记录脱敏后的文件与键名线索，绝不在报告或终端输出任何明文凭据值。
    """

    KNOWN_CREDENTIAL_FILENAMES = {
        "oauth_creds.json",
        "auth.json",
        "credentials.json",
        "credentials.yaml",
        "credentials.yml",
        "credentials.toml",
        "credentials",
        "token.json",
        "tokens.json",
        "secrets.json",
        "secret.json",
        "api_keys.json",
        "apikeys.json",
        "bootstrap_token.enc",
        "jetski-standalone-oauth-token",
        "workbuddy-desktop-ai.info",
        ".npmrc",
        ".pypirc",
        ".netrc",
        ".env",
        ".env.local",
        ".env.production",
        "id_rsa",
        "id_ed25519",
        "id_ecdsa",
        "id_dsa",
    }

    PRIVATE_KEY_EXTENSIONS = {".key", ".p12", ".pfx"}

    CREDENTIAL_FILENAME_REGEX = re.compile(
        r"^(?!.*(?:tokenizer|token_count|token_budget|max_tokens|microcredential)).*"
        r"(?:^|[-_.])(?:oauth|oauth_creds|credentials?|secrets?|api[-_]?keys?|auth[-_]?tokens?|refresh[-_]?tokens?|access[-_]?tokens?)"
        r"(?:[-_.].*)?\.(?:json|ya?ml|toml|ini|conf|info|txt|enc|env)$",
        re.IGNORECASE,
    )

    TEXT_INSPECT_EXTENSIONS = {
        ".json", ".yaml", ".yml", ".toml", ".ini", ".conf",
        ".env", ".txt", ".info", ".xml", ".plist",
    }

    SQLITE_EXTENSIONS = {".sqlite", ".sqlite3", ".db", ".vscdb"}

    EXCLUDED_SUBDIRS = {
        ".git", ".svn", ".hg", "node_modules", "site-packages", "__pycache__",
        "dist-packages", "venv", ".venv", "cache", "code cache", "gpucache",
        "dawngraphitecache", "dawnwebgpucache", "crashpad", "indexeddb",
        "local storage", "session storage", "blob_storage", "blobs",
        "dictionaries", "extensions", "logs",
    }

    # 匹配常见配置文件中含非空赋值的敏感键名
    SENSITIVE_KEY_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (
            re.compile(
                r"""(?:["']?)(access_token|refresh_token|oauth_token|id_token|bearer_token|auth_token|session_token)(?:["']?)\s*[:=]\s*(?!["']?(?:null|none|false|true|undefined|<[^>]+>|\$\{[^}]+\})?["']?(?:\s*[,}\]\n]|$))["']?[A-Za-z0-9._~+/=-]{3,}""",
                re.IGNORECASE,
            ),
            "access_token",
        ),
        (
            re.compile(
                r"""(?:["']?)(openai_api_key|anthropic_api_key|gemini_api_key|api_key|apikey|x-api-key)(?:["']?)\s*[:=]\s*(?!["']?(?:null|none|false|true|undefined|<[^>]+>|\$\{[^}]+\})?["']?(?:\s*[,}\]\n]|$))["']?[A-Za-z0-9._~+/=-]{3,}""",
                re.IGNORECASE,
            ),
            "api_key",
        ),
        (
            re.compile(
                r"""(?:["']?)(client_secret|api_secret|app_secret|secret_key|secret)(?:["']?)\s*[:=]\s*(?!["']?(?:null|none|false|true|undefined|<[^>]+>|\$\{[^}]+\})?["']?(?:\s*[,}\]\n]|$))["']?[A-Za-z0-9._~+/=-]{3,}""",
                re.IGNORECASE,
            ),
            "secret",
        ),
        (
            re.compile(
                r"""(?:["']?)(private_key|signing_key|encryption_key)(?:["']?)\s*[:=]\s*(?!["']?(?:null|none|false|true|undefined|<[^>]+>|\$\{[^}]+\})?["']?(?:\s*[,}\]\n]|$))["']?[A-Za-z0-9._~+/=\\ -]{3,}""",
                re.IGNORECASE,
            ),
            "private_key",
        ),
    ]

    TOKEN_VALUE_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "private_key"),
        (re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}\b"), "api_key"),
        (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "access_token"),
        (re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"), "api_key"),
        (re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "access_token"),
    ]

    SQLITE_SENSITIVE_KEY_NAMES = (
        "access_token", "refresh_token", "oauth_token", "api_key",
        "apikey", "client_secret", "secret_key", "secret", "private_key",
    )

    SQLITE_AUTH_TABLE_HINTS = (
        "auth", "token", "secret", "cred", "account", "session",
        "setting", "config", "itemtable", "kv", "pref", "key",
    )

    MAX_TEXT_READ_BYTES = 256 * 1024
    MAX_SQLITE_BYTES = 10 * 1024 * 1024

    @classmethod
    def _is_credential_filename(cls, basename: str) -> bool:
        low = basename.lower()
        if low in cls.KNOWN_CREDENTIAL_FILENAMES:
            return True
        _, ext = os.path.splitext(low)
        if ext in cls.PRIVATE_KEY_EXTENSIONS:
            return True
        if low.startswith(".env.") and low != ".env.example":
            return True
        return bool(cls.CREDENTIAL_FILENAME_REGEX.match(basename))

    @classmethod
    def _scan_text_content(cls, text: str) -> List[str]:
        keys: List[str] = []
        seen: Set[str] = set()
        for pat, label in cls.SENSITIVE_KEY_PATTERNS:
            if pat.search(text) and label not in seen:
                keys.append(label)
                seen.add(label)
        for pat, label in cls.TOKEN_VALUE_PATTERNS:
            if pat.search(text) and label not in seen:
                keys.append(label)
                seen.add(label)
        return keys

    @classmethod
    def _scan_sqlite_file(cls, filepath: str) -> List[str]:
        """以只读 URI 模式审计 SQLite 表名/列名/键值中的敏感凭据字段（零写入副作用）"""
        try:
            if os.path.getsize(filepath) > cls.MAX_SQLITE_BYTES:
                return []
        except OSError:
            return []

        found_keys: List[str] = []
        seen: Set[str] = set()
        conn = None
        try:
            uri = f"file:{quote(os.path.abspath(filepath))}?mode=ro"
            conn = sqlite3.connect(uri, uri=True, timeout=0.5)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
            tables = [row[0] for row in cur.fetchall() if row and isinstance(row[0], str)]

            for tbl in tables[:20]:
                safe_tbl = tbl.replace('"', '""')
                tbl_low = tbl.lower()
                try:
                    cur.execute(f'PRAGMA table_info("{safe_tbl}")')
                    cols = [str(r[1]) for r in cur.fetchall() if len(r) > 1 and r[1]]
                except sqlite3.Error:
                    continue

                for col in cols:
                    col_low = col.lower()
                    for sk in cls.SQLITE_SENSITIVE_KEY_NAMES:
                        if sk in col_low:
                            canon = "api_key" if "api" in sk else ("private_key" if "private" in sk else ("secret" if "secret" in sk else "access_token"))
                            if canon not in seen:
                                found_keys.append(canon)
                                seen.add(canon)

                if any(h in tbl_low for h in cls.SQLITE_AUTH_TABLE_HINTS) or found_keys:
                    try:
                        cur.execute(f'SELECT * FROM "{safe_tbl}" LIMIT 50')
                        for row in cur.fetchall():
                            row_text = " ".join(str(cell) for cell in row if cell is not None)
                            if not row_text:
                                continue
                            for key_label in cls._scan_text_content(row_text):
                                if key_label not in seen:
                                    found_keys.append(key_label)
                                    seen.add(key_label)
                            row_low = row_text.lower()
                            for sk in cls.SQLITE_SENSITIVE_KEY_NAMES:
                                if sk in row_low and len(row) >= 2:
                                    # key/value 对场景下确认存在非空 value
                                    non_empty_vals = [str(c).strip() for c in row if c is not None and str(c).strip()]
                                    if len(non_empty_vals) >= 2 and non_empty_vals[1].lower() not in {"null", "none", ""}:
                                        canon = "api_key" if "api" in sk else ("private_key" if "private" in sk else ("secret" if "secret" in sk else "access_token"))
                                        if canon not in seen:
                                            found_keys.append(canon)
                                            seen.add(canon)
                    except sqlite3.Error:
                        continue
        except sqlite3.Error:
            return []
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
        return found_keys

    @classmethod
    def _inspect_single_file(cls, filepath: str) -> Tuple[bool, List[str]]:
        basename = os.path.basename(filepath)
        lower_name = basename.lower()
        _, ext = os.path.splitext(lower_name)

        fname_match = cls._is_credential_filename(basename)
        matched_keys: List[str] = []

        if ext in cls.SQLITE_EXTENSIONS:
            matched_keys = cls._scan_sqlite_file(filepath)
        elif ext in cls.TEXT_INSPECT_EXTENSIONS or ext in cls.PRIVATE_KEY_EXTENSIONS or ext == ".pem" or fname_match or lower_name.startswith(".env"):
            try:
                if os.path.isfile(filepath) and os.path.getsize(filepath) <= 2 * 1024 * 1024:
                    with open(filepath, "rb") as f:
                        raw = f.read(cls.MAX_TEXT_READ_BYTES)
                    if b"\x00" not in raw:
                        text = raw.decode("utf-8", errors="ignore")
                        matched_keys = cls._scan_text_content(text)
            except OSError:
                pass

        return fname_match, matched_keys

    @classmethod
    def inspect_path(
        cls,
        path: str,
        max_files: int = 400,
        declared_contains_secrets: bool = False,
    ) -> SecretAuditResult:
        """
        对目标文件或目录执行深度敏感凭据隐私审计。
        """
        normalized = normalize_path(path)
        matched_files: List[str] = []
        matched_keys: List[str] = []
        seen_keys: Set[str] = set()
        findings: List[str] = []

        if not os.path.exists(normalized):
            if declared_contains_secrets:
                return SecretAuditResult(
                    contains_secrets=True,
                    severity="medium",
                    findings=["规则声明包含敏感认证凭据"],
                )
            return SecretAuditResult()

        def _record_file(rel_label: str, fname_hit: bool, keys: List[str]):
            if not fname_hit and not keys:
                return
            matched_files.append(rel_label)
            for k in keys:
                if k not in seen_keys:
                    matched_keys.append(k)
                    seen_keys.add(k)
            if len(findings) < 5:
                if keys and fname_hit:
                    findings.append(f"{rel_label} (凭据文件·含敏感键: {', '.join(keys)})")
                elif keys:
                    findings.append(f"{rel_label} (含敏感键: {', '.join(keys)})")
                else:
                    findings.append(f"{rel_label} (匹配敏感凭据文件名)")

        if os.path.isfile(normalized) and not os.path.islink(normalized):
            fname_hit, keys = cls._inspect_single_file(normalized)
            _record_file(os.path.basename(normalized), fname_hit, keys)
        elif os.path.isdir(normalized) and not os.path.islink(normalized):
            scanned = 0
            stack = [normalized]
            try:
                while stack and scanned < max_files:
                    current = stack.pop()
                    try:
                        with os.scandir(current) as it:
                            entries = sorted(it, key=lambda e: e.name)
                    except OSError:
                        continue

                    for entry in entries:
                        if scanned >= max_files:
                            break
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            low_d = entry.name.lower()
                            if low_d in cls.EXCLUDED_SUBDIRS or "venv" in low_d:
                                continue
                            stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            scanned += 1
                            fname_hit, keys = cls._inspect_single_file(entry.path)
                            if fname_hit or keys:
                                rel = os.path.relpath(entry.path, normalized)
                                _record_file(rel, fname_hit, keys)
            except OSError:
                pass

        if matched_files or matched_keys:
            severity = "high" if (matched_keys or any(
                os.path.basename(f).lower() in cls.KNOWN_CREDENTIAL_FILENAMES for f in matched_files
            )) else "medium"
            return SecretAuditResult(
                contains_secrets=True,
                severity=severity,
                matched_files=matched_files,
                matched_keys=matched_keys,
                findings=findings,
            )

        if declared_contains_secrets:
            return SecretAuditResult(
                contains_secrets=True,
                severity="medium",
                findings=["规则声明包含敏感认证凭据"],
            )

        return SecretAuditResult()


@dataclass
class ToolScanReport:
    tool_id: str
    name: str
    category: str
    vendor: str
    homepage: str
    status: str  # "running" | "installed" | "orphaned" | "clean"
    detection_matches: List[str] = field(default_factory=list)
    running_processes: List[str] = field(default_factory=list)
    active_locks: List[str] = field(default_factory=list)
    targets: List[TargetMatch] = field(default_factory=list)
    total_size_bytes: int = 0
    safe_size_bytes: int = 0
    model_weight_size_bytes: int = 0

    @property
    def has_residuals(self) -> bool:
        return len(self.targets) > 0

    @property
    def secret_count(self) -> int:
        return sum(1 for t in self.targets if t.contains_secrets)

    @property
    def is_running(self) -> bool:
        return self.status == "running"

    @property
    def l1_targets(self) -> List[TargetMatch]:
        return [t for t in self.targets if t.risk_level == RiskLevel.L1_SAFE.value]

    @property
    def l2_targets(self) -> List[TargetMatch]:
        return [t for t in self.targets if t.risk_level == RiskLevel.L2_ORPHAN.value]

    @property
    def l3_targets(self) -> List[TargetMatch]:
        return [t for t in self.targets if t.risk_level == RiskLevel.L3_IN_USE.value]

    @property
    def l4_targets(self) -> List[TargetMatch]:
        return [t for t in self.targets if t.risk_level == RiskLevel.L4_DANGER.value]


class RootOrphanScanner:
    """
    跨平台代码 Bug 与根目录散落探测引擎 (RootOrphanScanner)
    专门探测 ~/Library/Application Support/ 等存储根目录直属节点的：
      1. 异常空指针/Bug 命名目录或文件: ^(\\(null\\)|undefined|null|none|\\s+)$
      2. 根目录散落的历史解包单文件 (如 2052-TM1000*.png, default.store)
      3. 过期隐藏死锁标记 (如 .ACCC_Lock, .ADCS_Lock)
      4. 大小 < 64KB 且递归子孙项全空的骨架空目录 (Skeleton Dirs)
    """

    DEFAULT_ROOTS = ["~/Library/Application Support"]
    SKELETON_MAX_BYTES = 64 * 1024  # 64 KB
    IGNORED_ROOT_ENTRIES = {".DS_Store", ".localized", ".Trash", ".Spotlight-V100", ".fseventsd"}

    # macOS 系统原生目录白名单，避免将其空目录误判为可清理骨架空目录
    MACOS_SYSTEM_APP_SUPPORT_DIRS = {
        "Animoji",
        "App Store",
        "AskPermission",
        "CallHistoryTransactions",
        "Console",
        "CoreParsec",
        "CrashReporter",
        "DifferentialPrivacy",
        "DiskImages",
        "Dock",
        "FaceTime",
        "FileProvider",
        "Knowledge",
        "MobileSync",
        "Motion",
        "Music",
        "Podcasts",
        "Preview",
        "Quick Look",
        "SyncedPreferences",
        "SyncServices",
        "System Preferences",
        "TV",
        "TrustedPeersHelper",
        "accountsd",
        "familycircled",
        "homeenergyd",
        "icdd",
        "iCloud",
        "locationaccessstored",
        "syncdefaultsd",
        "transparencyd",
        "videosubscriptionsd",
    }

    ABNORMAL_NAME_REGEX = re.compile(r"^(\(null\)|undefined|null|none|\s+)$", re.IGNORECASE)

    DEAD_LOCK_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (re.compile(r"^\.(ACCC|ADCS)_Lock.*$", re.IGNORECASE), "Adobe 历史零字节隐藏死锁标记"),
        (re.compile(r"^\..+_Lock$", re.IGNORECASE), "根目录过期隐藏死锁标记"),
        (re.compile(r"^.*\.(lock|lck)$", re.IGNORECASE), "根目录残留锁文件"),
    ]

    SCATTERED_FILE_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
        (
            re.compile(r"^2052-TM\d+.*\.(png|jpg|jpeg|bmp|gif|ico)$", re.IGNORECASE),
            "历史跨平台安装包解包残留的引导图片",
            "temp_images",
        ),
        (
            re.compile(r"^2052-TM.*$", re.IGNORECASE),
            "历史跨平台安装包解包残留单文件",
            "temp_images",
        ),
        (
            re.compile(r"^default\.store(-shm|-wal)?$", re.IGNORECASE),
            "CoreData 根目录违规落盘数据库残留",
            "ghost",
        ),
    ]

    def __init__(self, roots: Optional[List[str]] = None):
        self.roots = roots if roots is not None else list(self.DEFAULT_ROOTS)

    @staticmethod
    def _compute_entry_size_and_count(path: str) -> Tuple[int, int]:
        """计算条目体积与文件数（符号链接只计自身）"""
        if os.path.islink(path) or os.path.isfile(path):
            try:
                return os.lstat(path).st_size, 1
            except OSError:
                return 0, 1

        total_size = 0
        file_count = 0
        try:
            for root, _, files in os.walk(path):
                for f in files:
                    fp = os.path.join(root, f)
                    try:
                        total_size += os.lstat(fp).st_size
                        file_count += 1
                    except OSError:
                        pass
        except OSError:
            pass
        return total_size, file_count

    @classmethod
    def inspect_skeleton_dir(cls, dirpath: str) -> Tuple[bool, int, int]:
        """
        检测目录是否为骨架空目录 (Skeleton Dir)：
        大小 < 64KB 且递归子孙项中不含任何真实业务文件（仅允许空子目录或 Finder .DS_Store）。
        返回: (is_skeleton, total_size_bytes, file_count)
        """
        if not os.path.isdir(dirpath) or os.path.islink(dirpath):
            return False, 0, 0

        total_size = 0
        total_files = 0
        stack = [dirpath]

        try:
            while stack:
                current = stack.pop()
                has_ws, _ = contains_workspace_or_repo(current)
                if has_ws:
                    return False, 0, 0

                with os.scandir(current) as it:
                    for entry in it:
                        if entry.is_symlink():
                            return False, 0, 0
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        else:
                            try:
                                st_size = entry.stat(follow_symlinks=False).st_size
                            except OSError:
                                return False, 0, 0
                            total_size += st_size
                            total_files += 1
                            if entry.name != ".DS_Store":
                                return False, 0, 0
                            if total_size >= cls.SKELETON_MAX_BYTES:
                                return False, 0, 0
        except OSError:
            return False, 0, 0

        if total_size < cls.SKELETON_MAX_BYTES:
            return True, total_size, total_files
        return False, 0, 0

    def _build_l1_match(
        self,
        entry_path: str,
        category: str,
        description: str,
        size_bytes: int,
        file_count: int,
        ghost_type: str,
    ) -> Optional[TargetMatch]:
        """通过四级安全矩阵校验并构造 L1 TargetMatch"""
        risk_lvl, is_safe, reason = assess_risk_level(
            target_path=entry_path,
            software_status="orphaned",
            category=category,
        )
        if not is_safe or risk_lvl == RiskLevel.L4_DANGER:
            return None

        return TargetMatch(
            category=category,
            raw_path=entry_path,
            resolved_path=entry_path,
            description=description,
            size_bytes=size_bytes,
            file_count=file_count,
            contains_secrets=False,
            is_model_weight=False,
            default_selected=True,
            is_safe=is_safe,
            safety_reason=reason,
            risk_level=risk_lvl.value if isinstance(risk_lvl, RiskLevel) else str(risk_lvl),
            prunable=False,
            regenerable=False,
            ghost_type=ghost_type,
            tool_id="root-orphans",
            tool_name="根目录散落与幽灵残留 (Root Orphans)",
        )

    def _classify_root_entry(self, entry: os.DirEntry) -> Optional[TargetMatch]:
        """对根目录下的单个直属条目进行 Bug/散落/死锁/骨架空目录分类探测"""
        name = entry.name
        path = entry.path

        if name in self.IGNORED_ROOT_ENTRIES:
            return None

        # 绝对系统红线与工作区前置过滤
        is_redline, _ = is_system_redline_path(path)
        if is_redline:
            return None
        is_safe, _ = validate_target_safety(path)
        if not is_safe:
            return None

        # 1. 异常 Bug 命名目录或文件: ^(\(null\)|undefined|null|none|\s+)$
        if self.ABNORMAL_NAME_REGEX.match(name):
            size, count = self._compute_entry_size_and_count(path)
            kind = "目录" if entry.is_dir(follow_symlinks=False) else "文件"
            return self._build_l1_match(
                entry_path=path,
                category="ghost",
                description=f"跨平台代码空指针/异常命名 Bug 产生的幽灵{kind} ({repr(name)})",
                size_bytes=size,
                file_count=count,
                ghost_type="bug_name",
            )

        # 2. 过期隐藏死锁标记 (支持文件或空锁目录/套接字)
        for pat, desc in self.DEAD_LOCK_PATTERNS:
            if pat.match(name):
                size, count = self._compute_entry_size_and_count(path)
                return self._build_l1_match(
                    entry_path=path,
                    category="locks",
                    description=f"{desc} ({name})",
                    size_bytes=size,
                    file_count=count,
                    ghost_type="dead_lock",
                )

        # 3. 根目录散落的历史解包单文件与违规落盘库
        if entry.is_file(follow_symlinks=False) or entry.is_symlink():
            for pat, desc, cat in self.SCATTERED_FILE_PATTERNS:
                if pat.match(name):
                    size, count = self._compute_entry_size_and_count(path)
                    return self._build_l1_match(
                        entry_path=path,
                        category=cat,
                        description=f"{desc} ({name})",
                        size_bytes=size,
                        file_count=count,
                        ghost_type="scattered_file",
                    )

        # 4. 骨架空目录探测 (大小 < 64KB 且子孙项全空)
        if entry.is_dir(follow_symlinks=False):
            if name in self.MACOS_SYSTEM_APP_SUPPORT_DIRS or name.startswith(".") or name.startswith("com.apple."):
                return None
            is_skeleton, sk_size, sk_count = self.inspect_skeleton_dir(path)
            if is_skeleton:
                return self._build_l1_match(
                    entry_path=path,
                    category="skeleton",
                    description=f"骨架空目录 (< 64KB 且子孙项全空，如历史空预设目录 {name})",
                    size_bytes=sk_size,
                    file_count=sk_count,
                    ghost_type="skeleton_dir",
                )

        return None

    def scan(self) -> ToolScanReport:
        """执行存储根目录散落与幽灵残留扫描"""
        targets: List[TargetMatch] = []
        scanned_roots: List[str] = []
        seen_paths = set()

        for raw_root in self.roots:
            root_path = normalize_path(raw_root)
            if not os.path.isdir(root_path):
                continue
            scanned_roots.append(f"根目录扫描: {raw_root}")
            try:
                with os.scandir(root_path) as it:
                    entries = sorted(it, key=lambda e: e.name)
                for entry in entries:
                    if entry.path in seen_paths:
                        continue
                    match = self._classify_root_entry(entry)
                    if match:
                        seen_paths.add(entry.path)
                        targets.append(match)
            except OSError:
                continue

        total_size = sum(t.size_bytes for t in targets)
        safe_size = sum(t.size_bytes for t in targets if t.is_safe)

        return ToolScanReport(
            tool_id="root-orphans",
            name="根目录散落与幽灵残留 (Root Orphans)",
            category="runtime",
            vendor="Cross-Platform / OS Root Bugs",
            homepage="",
            status="orphaned" if targets else "clean",
            detection_matches=scanned_roots,
            targets=targets,
            total_size_bytes=total_size,
            safe_size_bytes=safe_size,
            model_weight_size_bytes=0,
        )


class ChannelRedundancyScanner:
    """
    浏览器与 IDE 多通道发布孤岛检测引擎 (ChannelRedundancyScanner)
    1. 自动关联产品家族通道矩阵（Edge / Edge Canary / Dev / Beta; Chrome / Beta / Canary / Dev; VS Code / Insiders）
    2. 活跃度交叉仲裁 (Channel Cross-Check)：
       当正式版 (Stable) 处于近期活跃使用状态，而测试通道超过 90 天未启动时，
       将其标记为停用测试通道孤岛，提示用户一键安全清理。
    """

    DEFAULT_STALE_DAYS = 90
    DEFAULT_STABLE_ACTIVE_DAYS = 30

    # 内置产品家族通道矩阵（支持与 YAML 规则中的 channels 声明自动合并）
    DEFAULT_FAMILIES: List[Dict[str, Any]] = [
        {
            "id": "google-chrome",
            "name": "Google Chrome",
            "category": "browser",
            "vendor": "Google",
            "stable_data_path": "~/Library/Application Support/Google/Chrome",
            "stable_app_paths": ["/Applications/Google Chrome.app"],
            "stable_process_names": ["Google Chrome"],
            "related_channels": [
                {
                    "id": "chrome-canary",
                    "name": "Google Chrome Canary",
                    "channel": "canary",
                    "data_path": "~/Library/Application Support/Google/Chrome Canary",
                    "cache_path": "~/Library/Caches/Google/Chrome Canary",
                    "app_path": "/Applications/Google Chrome Canary.app",
                    "process_name": "Google Chrome Canary",
                },
                {
                    "id": "chrome-beta",
                    "name": "Google Chrome Beta",
                    "channel": "beta",
                    "data_path": "~/Library/Application Support/Google/Chrome Beta",
                    "cache_path": "~/Library/Caches/Google/Chrome Beta",
                    "app_path": "/Applications/Google Chrome Beta.app",
                    "process_name": "Google Chrome Beta",
                },
                {
                    "id": "chrome-dev",
                    "name": "Google Chrome Dev",
                    "channel": "dev",
                    "data_path": "~/Library/Application Support/Google/Chrome Dev",
                    "cache_path": "~/Library/Caches/Google/Chrome Dev",
                    "app_path": "/Applications/Google Chrome Dev.app",
                    "process_name": "Google Chrome Dev",
                },
            ],
        },
        {
            "id": "microsoft-edge",
            "name": "Microsoft Edge",
            "category": "browser",
            "vendor": "Microsoft",
            "stable_data_path": "~/Library/Application Support/Microsoft Edge",
            "stable_app_paths": ["/Applications/Microsoft Edge.app"],
            "stable_process_names": ["Microsoft Edge"],
            "related_channels": [
                {
                    "id": "edge-canary",
                    "name": "Microsoft Edge Canary",
                    "channel": "canary",
                    "data_path": "~/Library/Application Support/Microsoft Edge Canary",
                    "cache_path": "~/Library/Caches/Microsoft Edge Canary",
                    "app_path": "/Applications/Microsoft Edge Canary.app",
                    "process_name": "Microsoft Edge Canary",
                },
                {
                    "id": "edge-dev",
                    "name": "Microsoft Edge Dev",
                    "channel": "dev",
                    "data_path": "~/Library/Application Support/Microsoft Edge Dev",
                    "cache_path": "~/Library/Caches/Microsoft Edge Dev",
                    "app_path": "/Applications/Microsoft Edge Dev.app",
                    "process_name": "Microsoft Edge Dev",
                },
                {
                    "id": "edge-beta",
                    "name": "Microsoft Edge Beta",
                    "channel": "beta",
                    "data_path": "~/Library/Application Support/Microsoft Edge Beta",
                    "cache_path": "~/Library/Caches/Microsoft Edge Beta",
                    "app_path": "/Applications/Microsoft Edge Beta.app",
                    "process_name": "Microsoft Edge Beta",
                },
            ],
        },
        {
            "id": "vscode",
            "name": "Visual Studio Code",
            "category": "ide",
            "vendor": "Microsoft",
            "stable_data_path": "~/Library/Application Support/Code",
            "stable_app_paths": ["/Applications/Visual Studio Code.app"],
            "stable_process_names": ["Code Helper", "Visual Studio Code"],
            "related_channels": [
                {
                    "id": "vscode-insiders",
                    "name": "Visual Studio Code - Insiders",
                    "channel": "insiders",
                    "data_path": "~/Library/Application Support/Code - Insiders",
                    "cache_path": "~/Library/Caches/com.microsoft.VSCodeInsiders",
                    "app_path": "/Applications/Visual Studio Code - Insiders.app",
                    "process_name": "Visual Studio Code - Insiders",
                },
            ],
        },
    ]

    ACTIVITY_PROBE_FILES = (
        "Local State",
        "Last Version",
        "Preferences",
        "SingletonLock",
        "Default/Preferences",
        "Default/History",
        "User/globalStorage/storage.json",
    )

    def __init__(
        self,
        rules: Optional[List[Dict[str, Any]]] = None,
        stale_days: int = DEFAULT_STALE_DAYS,
        stable_active_days: int = DEFAULT_STABLE_ACTIVE_DAYS,
        use_builtin_defaults: Optional[bool] = None,
        now: Optional[float] = None,
    ):
        self.rules = rules
        self.stale_days = stale_days
        self.stable_active_days = stable_active_days
        self.use_builtin_defaults = (rules is None) if use_builtin_defaults is None else use_builtin_defaults
        self.now = now

    @staticmethod
    def _infer_stable_data_path(rule: Dict[str, Any]) -> Optional[str]:
        """从规则的 lock_files / exclude_paths / targets 中推导主通道数据目录"""
        if rule.get("channels", {}).get("stable_data_path"):
            return rule["channels"]["stable_data_path"]

        lock_files = rule.get("protection", {}).get("lock_files", [])
        for lf in lock_files:
            if lf:
                return os.path.dirname(lf)

        exclude_paths = rule.get("safety", {}).get("exclude_paths", [])
        for ex in exclude_paths:
            if ex and not ex.endswith("*"):
                return os.path.dirname(ex)

        for cat in ("data_and_history", "caches"):
            items = rule.get("targets", {}).get(cat, [])
            if items and isinstance(items, list) and items[0].get("path"):
                return items[0]["path"]
        return None

    @staticmethod
    def _infer_cache_path(data_path: str) -> Optional[str]:
        """由 ~/Library/Application Support/... 推导对应的 ~/Library/Caches/... 路径"""
        if not data_path:
            return None
        norm = normalize_path(data_path)
        marker = f"{os.sep}Library{os.sep}Application Support{os.sep}"
        if marker in norm:
            return norm.replace(marker, f"{os.sep}Library{os.sep}Caches{os.sep}", 1)
        return None

    def _build_families(self) -> List[Dict[str, Any]]:
        """合并内置家族矩阵与 YAML 规则中的 channels 矩阵"""
        family_map: Dict[str, Dict[str, Any]] = {}
        if self.use_builtin_defaults:
            for fam in self.DEFAULT_FAMILIES:
                copied = dict(fam)
                copied["related_channels"] = [dict(rc) for rc in fam.get("related_channels", [])]
                family_map[fam["id"]] = copied

        for rule in (self.rules or []):
            ch_cfg = rule.get("channels")
            if not isinstance(ch_cfg, dict):
                continue
            rid = rule.get("id", "unknown")
            rel_list = ch_cfg.get("related_channels", [])
            if not isinstance(rel_list, list) or not rel_list:
                continue

            existing = family_map.get(rid)
            inferred_stable_data = self._infer_stable_data_path(rule)
            if existing is None:
                existing = {
                    "id": rid,
                    "name": rule.get("name", rid),
                    "category": rule.get("category", "browser"),
                    "vendor": rule.get("vendor", ""),
                    "stable_data_path": inferred_stable_data or "",
                    "stable_app_paths": list(rule.get("detection", {}).get("app_paths", [])),
                    "stable_process_names": list(rule.get("protection", {}).get("process_names", [])),
                    "related_channels": [],
                }
                family_map[rid] = existing
            else:
                if inferred_stable_data and not existing.get("stable_data_path"):
                    existing["stable_data_path"] = inferred_stable_data
                if rule.get("detection", {}).get("app_paths"):
                    existing["stable_app_paths"] = list(rule["detection"]["app_paths"])
                if rule.get("protection", {}).get("process_names"):
                    existing["stable_process_names"] = list(rule["protection"]["process_names"])

            by_rel_id = {rc.get("id"): rc for rc in existing["related_channels"] if rc.get("id")}
            for rc in rel_list:
                if not isinstance(rc, dict) or not rc.get("id"):
                    continue
                rc_id = rc["id"]
                if rc_id in by_rel_id:
                    for k, v in rc.items():
                        if v:
                            by_rel_id[rc_id][k] = v
                else:
                    new_rc = dict(rc)
                    if "cache_path" not in new_rc and new_rc.get("data_path"):
                        inferred_cache = self._infer_cache_path(new_rc["data_path"])
                        if inferred_cache:
                            new_rc["cache_path"] = inferred_cache
                    existing["related_channels"].append(new_rc)
                    by_rel_id[rc_id] = new_rc

        return list(family_map.values())

    @classmethod
    def get_last_activity_ts(cls, path: str) -> Optional[float]:
        """获取通道数据目录的最近活跃修改时间戳 (mtime)"""
        norm = normalize_path(path)
        if not os.path.exists(norm):
            return None

        latest_ts = 0.0
        try:
            latest_ts = max(latest_ts, os.lstat(norm).st_mtime)
        except OSError:
            return None

        if os.path.isdir(norm):
            for probe in cls.ACTIVITY_PROBE_FILES:
                probe_path = os.path.join(norm, probe)
                if os.path.lexists(probe_path):
                    try:
                        latest_ts = max(latest_ts, os.lstat(probe_path).st_mtime)
                    except OSError:
                        pass
            try:
                with os.scandir(norm) as it:
                    for entry in it:
                        try:
                            latest_ts = max(latest_ts, entry.stat(follow_symlinks=False).st_mtime)
                        except OSError:
                            pass
            except OSError:
                pass

        return latest_ts if latest_ts > 0 else None

    @staticmethod
    def _compute_path_size_and_count(path: str) -> Tuple[int, int]:
        """计算路径体积与文件数"""
        if not os.path.exists(path):
            return 0, 0
        if os.path.islink(path) or os.path.isfile(path):
            try:
                return os.lstat(path).st_size, 1
            except OSError:
                return 0, 1
        total_size = 0
        file_count = 0
        try:
            for root, _, files in os.walk(path):
                for f in files:
                    fp = os.path.join(root, f)
                    try:
                        total_size += os.lstat(fp).st_size
                        file_count += 1
                    except OSError:
                        pass
        except OSError:
            pass
        return total_size, file_count

    @staticmethod
    def _is_channel_running(data_path: str, process_name: Optional[str] = None) -> bool:
        """检测指定通道是否处于活跃运行状态"""
        if data_path and os.path.isdir(data_path):
            for lock_name in ("SingletonLock", "SingletonSocket"):
                if os.path.lexists(os.path.join(data_path, lock_name)):
                    return True
        if process_name:
            try:
                res = subprocess.run(["pgrep", "-fl", process_name], capture_output=True, text=True, timeout=2)
                if res.returncode == 0 and res.stdout.strip():
                    return True
            except Exception:
                pass
        return False

    def _is_stable_active(self, family: Dict[str, Any], now_ts: float) -> Tuple[bool, Optional[int]]:
        """判定产品家族主通道 (Stable) 是否正在高频/近期活跃使用"""
        app_paths = family.get("stable_app_paths", [])
        data_path = family.get("stable_data_path", "")

        app_exists = any(os.path.exists(normalize_path(p)) for p in app_paths if p)
        data_exists = bool(data_path and os.path.exists(normalize_path(data_path)))
        if not app_exists and not data_exists:
            return False, None

        if data_exists and self._is_channel_running(normalize_path(data_path)):
            return True, 0

        last_ts = self.get_last_activity_ts(data_path) if data_exists else None
        if last_ts is None:
            return False, None

        inactive_days = max(0, int((now_ts - last_ts) // 86400))
        return (inactive_days <= self.stable_active_days), inactive_days

    def scan(self) -> ToolScanReport:
        """执行全家族多通道发布孤岛交叉检测"""
        now_ts = self.now if self.now is not None else time.time()
        families = self._build_families()
        targets: List[TargetMatch] = []
        detection_matches: List[str] = []
        seen_paths = set()

        for fam in families:
            stable_id = fam["id"]
            stable_name = fam["name"]
            stable_active, stable_days = self._is_stable_active(fam, now_ts)
            if not stable_active:
                continue

            detection_matches.append(f"主通道活跃: {stable_name} ({stable_days or 0} 天内使用)")

            for rc in fam.get("related_channels", []):
                rel_name = rc.get("name", rc.get("id", "Unknown Channel"))
                rel_channel = rc.get("channel", "preview")
                rel_data_raw = rc.get("data_path", "")
                if not rel_data_raw:
                    continue

                rel_data_path = normalize_path(rel_data_raw)
                if not os.path.exists(rel_data_path):
                    continue

                rel_proc = rc.get("process_name") or rel_name
                is_running = self._is_channel_running(rel_data_path, rel_proc)
                if is_running:
                    continue

                last_ts = self.get_last_activity_ts(rel_data_path)
                if last_ts is None:
                    continue

                inactive_days = max(0, int((now_ts - last_ts) // 86400))
                if inactive_days < self.stale_days:
                    continue

                rel_app_path = rc.get("app_path")
                app_installed = bool(rel_app_path and os.path.exists(normalize_path(rel_app_path)))
                sw_status = "installed" if app_installed else "orphaned"

                candidate_paths: List[Tuple[str, str, str]] = [
                    (
                        rel_data_path,
                        "data_and_history",
                        f"停用测试通道孤岛 ({rel_name} 已超过 {inactive_days} 天未启动，主通道 {stable_name} 活跃使用中)",
                    )
                ]
                rel_cache_raw = rc.get("cache_path") or self._infer_cache_path(rel_data_raw)
                if rel_cache_raw:
                    rel_cache_path = normalize_path(rel_cache_raw)
                    if os.path.exists(rel_cache_path):
                        cache_ts = self.get_last_activity_ts(rel_cache_path)
                        cache_days = max(0, int((now_ts - cache_ts) // 86400)) if cache_ts else inactive_days
                        if cache_days >= self.stale_days:
                            candidate_paths.append((
                                rel_cache_path,
                                "caches",
                                f"停用测试通道缓存 ({rel_name} 已超过 {inactive_days} 天未启动)",
                            ))

                for path, cat, desc in candidate_paths:
                    if path in seen_paths:
                        continue
                    size_bytes, file_count = self._compute_path_size_and_count(path)
                    risk_lvl, is_safe, reason = assess_risk_level(
                        target_path=path,
                        software_status=sw_status,
                        category=cat,
                    )
                    if risk_lvl == RiskLevel.L4_DANGER:
                        default_selected = False
                        is_safe = False
                    elif risk_lvl == RiskLevel.L3_IN_USE:
                        default_selected = False
                    else:
                        default_selected = is_safe

                    targets.append(TargetMatch(
                        category=cat,
                        raw_path=path,
                        resolved_path=path,
                        description=desc,
                        size_bytes=size_bytes,
                        file_count=file_count,
                        contains_secrets=False,
                        is_model_weight=False,
                        default_selected=default_selected,
                        is_safe=is_safe,
                        safety_reason=reason,
                        risk_level=risk_lvl.value if isinstance(risk_lvl, RiskLevel) else str(risk_lvl),
                        prunable=True,
                        regenerable=True,
                        channel_name=rel_channel,
                        inactive_days=inactive_days,
                        stable_channel_id=stable_id,
                        tool_id=stable_id,
                        tool_name=rel_name,
                    ))
                    seen_paths.add(path)

        total_size = sum(t.size_bytes for t in targets)
        safe_size = sum(t.size_bytes for t in targets if t.is_safe)

        return ToolScanReport(
            tool_id="channel-redundancy",
            name="多通道发布孤岛 (Channel Redundancy)",
            category="browser",
            vendor="Browser & IDE Release Channels",
            homepage="",
            status="orphaned" if targets else "clean",
            detection_matches=detection_matches,
            targets=targets,
            total_size_bytes=total_size,
            safe_size_bytes=safe_size,
            model_weight_size_bytes=0,
        )


@dataclass
class InstalledAppInfo:
    """已安装 macOS 应用元数据索引条目"""
    name: str
    app_path: str
    bundle_id: str = ""
    executable: str = ""
    display_name: str = ""


@dataclass
class AssociationResult:
    """三级反向映射引擎单目录推导结果"""
    dirpath: str
    dir_name: str
    tier: Optional[int]          # 1 | 2 | 3 | None
    method: str                  # "plist_bundle_id" | "signature_db" | "heuristic" | "unresolved" | "protected"
    status: str                  # "running" | "installed" | "orphaned" | "active_unknown" | "skipped"
    app_name: Optional[str] = None
    bundle_id: Optional[str] = None
    inactive_days: Optional[int] = None
    reason: str = ""


class AssociationEngine:
    """
    应用名与存储路径脱节的三级反向映射引擎 (Association Engine)

    解决如 "应用叫 VS Code，目录叫 Code；应用叫 ChatGPT，目录叫 com.openai.chat" 导致的孤儿漏报难题：
      • 一级 (Tier 1 - Plist & Bundle ID): 解析目录下 Info.plist / CFBundleIdentifier 或反查反向域名目录名
      • 二级 (Tier 2 - Signature DB):      内置高频特征字典反查脱节的目录名 -> 宿主应用 / Bundle ID
      • 三级 (Tier 3 - Heuristic):         无对应应用/活跃进程，且超过 180 天未被任何进程访问 -> 启发式孤儿
    """

    DEFAULT_ROOTS = ["~/Library/Application Support"]
    DEFAULT_APP_DIRS = ["/Applications", "/System/Applications", "~/Applications"]
    DEFAULT_STALE_DAYS = 180
    BUNDLE_ID_REGEX = re.compile(r"^[a-zA-Z0-9-]+(\.[a-zA-Z0-9_-]+){2,}$")
    LOCK_INDICATORS = ("SingletonLock", "SingletonSocket", "lockfile", ".lock")

    # 共享底层框架或系统跨应用辅助目录，不作为单一软件孤儿贸然标记
    SHARED_INFRA_DIRS = {
        "CEF",
        "GoogleUpdater",
        "EdgeUpdater",
        "Microsoft AutoUpdate",
        "Microsoft Update Assistant",
        "Microsoft DevDiv",
        "WebKit",
        "CloudKit",
        "Users",
        "Temp",
        "tmp",
        "Logs",
    }

    # 二级高频特征字典：将与 .app 名称脱节的数据目录映射到真实宿主应用元数据
    KNOWN_APP_SIGNATURES: Dict[str, Dict[str, Any]] = {
        "code": {
            "app_name": "Visual Studio Code",
            "bundle_ids": ["com.microsoft.VSCode"],
            "app_paths": ["/Applications/Visual Studio Code.app"],
            "process_names": ["Visual Studio Code", "Code Helper"],
        },
        "code - insiders": {
            "app_name": "Visual Studio Code - Insiders",
            "bundle_ids": ["com.microsoft.VSCodeInsiders"],
            "app_paths": ["/Applications/Visual Studio Code - Insiders.app"],
            "process_names": ["Visual Studio Code - Insiders"],
        },
        "com.openai.chat": {
            "app_name": "ChatGPT",
            "bundle_ids": ["com.openai.chat"],
            "app_paths": ["/Applications/ChatGPT.app"],
            "process_names": ["ChatGPT"],
        },
        "openai": {
            "app_name": "ChatGPT",
            "bundle_ids": ["com.openai.chat"],
            "app_paths": ["/Applications/ChatGPT.app"],
            "process_names": ["ChatGPT"],
        },
        "telegram desktop": {
            "app_name": "Telegram",
            "bundle_ids": ["ru.keepcoder.Telegram", "org.telegram.desktop"],
            "app_paths": ["/Applications/Telegram.app", "/Applications/Telegram Desktop.app"],
            "process_names": ["Telegram"],
        },
        "bravesoftware": {
            "app_name": "Brave Browser",
            "bundle_ids": ["com.brave.Browser"],
            "app_paths": ["/Applications/Brave Browser.app"],
            "process_names": ["Brave Browser"],
        },
        "firefox": {
            "app_name": "Firefox",
            "bundle_ids": ["org.mozilla.firefox"],
            "app_paths": ["/Applications/Firefox.app"],
            "process_names": ["firefox"],
        },
        "mozilla": {
            "app_name": "Firefox / Thunderbird (Mozilla)",
            "bundle_ids": ["org.mozilla.firefox", "org.mozilla.thunderbird"],
            "app_paths": ["/Applications/Firefox.app", "/Applications/Thunderbird.app"],
            "process_names": ["firefox", "thunderbird"],
        },
        "videofusion": {
            "app_name": "CapCut / VideoFusion",
            "bundle_ids": ["com.lemon.lvoverseas", "com.bytedance.videofusion"],
            "app_paths": ["/Applications/VideoFusion-macOS.app", "/Applications/CapCut.app"],
            "process_names": ["VideoFusion", "CapCut"],
        },
        "capcut": {
            "app_name": "CapCut",
            "bundle_ids": ["com.lemon.lvoverseas"],
            "app_paths": ["/Applications/CapCut.app", "/Applications/VideoFusion-macOS.app"],
            "process_names": ["CapCut", "VideoFusion"],
        },
        "byteexec": {
            "app_name": "Lark / Feishu",
            "bundle_ids": ["com.bytedance.lark", "com.electron.lark"],
            "app_paths": ["/Applications/Lark.app", "/Applications/Feishu.app"],
            "process_names": ["Lark", "Feishu"],
        },
        "larkshell": {
            "app_name": "Lark / Feishu",
            "bundle_ids": ["com.bytedance.lark", "com.electron.lark"],
            "app_paths": ["/Applications/Lark.app", "/Applications/Feishu.app"],
            "process_names": ["Lark", "Feishu"],
        },
        "skype": {
            "app_name": "Skype",
            "bundle_ids": ["com.skype.skype"],
            "app_paths": ["/Applications/Skype.app"],
            "process_names": ["Skype"],
        },
        "jan": {
            "app_name": "Jan AI",
            "bundle_ids": ["jan.ai.app", "ai.jan.desktop"],
            "app_paths": ["/Applications/Jan.app"],
            "process_names": ["Jan"],
        },
        "quark": {
            "app_name": "Quark",
            "bundle_ids": ["com.quark.browser", "com.alibaba.quark"],
            "app_paths": ["/Applications/Quark.app"],
            "process_names": ["Quark"],
        },
        "notion mail": {
            "app_name": "Notion Mail",
            "bundle_ids": ["com.notion.mail", "notion.mail.id"],
            "app_paths": ["/Applications/Notion Mail.app"],
            "process_names": ["Notion Mail"],
        },
        "notion": {
            "app_name": "Notion",
            "bundle_ids": ["notion.id"],
            "app_paths": ["/Applications/Notion.app"],
            "process_names": ["Notion"],
        },
        "vivaldi": {
            "app_name": "Vivaldi",
            "bundle_ids": ["com.vivaldi.Vivaldi"],
            "app_paths": ["/Applications/Vivaldi.app"],
            "process_names": ["Vivaldi"],
        },
        "arc": {
            "app_name": "Arc",
            "bundle_ids": ["company.thebrowser.Browser"],
            "app_paths": ["/Applications/Arc.app"],
            "process_names": ["Arc"],
        },
        "dia": {
            "app_name": "Dia",
            "bundle_ids": ["company.thebrowser.dia"],
            "app_paths": ["/Applications/Dia.app"],
            "process_names": ["Dia"],
        },
        "comet": {
            "app_name": "Comet",
            "bundle_ids": ["ai.perplexity.comet"],
            "app_paths": ["/Applications/Comet.app"],
            "process_names": ["Comet"],
        },
        "accio": {
            "app_name": "Accio",
            "bundle_ids": ["com.accio.desktop"],
            "app_paths": ["/Applications/Accio.app"],
            "process_names": ["Accio"],
        },
        "cindyglobal": {
            "app_name": "CindyGlobal",
            "bundle_ids": [],
            "app_paths": ["/Applications/CindyGlobal.app"],
            "process_names": ["CindyGlobal"],
        },
        "citro labs": {
            "app_name": "Citro Labs",
            "bundle_ids": [],
            "app_paths": ["/Applications/Citro Labs.app"],
            "process_names": ["Citro"],
        },
        "lingma": {
            "app_name": "Tongyi Lingma",
            "bundle_ids": ["com.alibabacloud.lingma"],
            "app_paths": ["/Applications/Lingma.app"],
            "process_names": ["Lingma"],
        },
        "ibkr desktop": {
            "app_name": "IBKR Desktop",
            "bundle_ids": ["com.interactivebrokers.desktop"],
            "app_paths": ["/Applications/IBKR Desktop.app"],
            "process_names": ["IBKR Desktop"],
        },
        "slack": {
            "app_name": "Slack",
            "bundle_ids": ["com.tinyspeck.slackmacgap"],
            "app_paths": ["/Applications/Slack.app"],
            "process_names": ["Slack"],
        },
        "discord": {
            "app_name": "Discord",
            "bundle_ids": ["com.hnc.Discord"],
            "app_paths": ["/Applications/Discord.app"],
            "process_names": ["Discord"],
        },
        "zoom.us": {
            "app_name": "Zoom",
            "bundle_ids": ["us.zoom.xos"],
            "app_paths": ["/Applications/zoom.us.app"],
            "process_names": ["zoom.us"],
        },
        "sublime text": {
            "app_name": "Sublime Text",
            "bundle_ids": ["com.sublimetext.4", "com.sublimetext.3"],
            "app_paths": ["/Applications/Sublime Text.app"],
            "process_names": ["Sublime Text"],
        },
        "lm studio": {
            "app_name": "LM Studio",
            "bundle_ids": ["ai.elementlabs.lmstudio"],
            "app_paths": ["/Applications/LM Studio.app"],
            "process_names": ["LM Studio"],
        },
        "zed": {
            "app_name": "Zed",
            "bundle_ids": ["dev.zed.Zed"],
            "app_paths": ["/Applications/Zed.app"],
            "process_names": ["zed"],
        },
        "warp": {
            "app_name": "Warp",
            "bundle_ids": ["dev.warp.Warp-Stable"],
            "app_paths": ["/Applications/Warp.app"],
            "process_names": ["Warp"],
        },
        "raycast": {
            "app_name": "Raycast",
            "bundle_ids": ["com.raycast.macos"],
            "app_paths": ["/Applications/Raycast.app"],
            "process_names": ["Raycast"],
        },
        "docker": {
            "app_name": "Docker Desktop",
            "bundle_ids": ["com.docker.docker"],
            "app_paths": ["/Applications/Docker.app"],
            "process_names": ["Docker"],
        },
        "postman": {
            "app_name": "Postman",
            "bundle_ids": ["com.postmanlabs.mac"],
            "app_paths": ["/Applications/Postman.app"],
            "process_names": ["Postman"],
        },
        "spotify": {
            "app_name": "Spotify",
            "bundle_ids": ["com.spotify.client"],
            "app_paths": ["/Applications/Spotify.app"],
            "process_names": ["Spotify"],
        },
        "obsidian": {
            "app_name": "Obsidian",
            "bundle_ids": ["md.obsidian"],
            "app_paths": ["/Applications/Obsidian.app"],
            "process_names": ["Obsidian"],
        },
        "tailscale": {
            "app_name": "Tailscale",
            "bundle_ids": ["io.tailscale.ipn.macos"],
            "app_paths": ["/Applications/Tailscale.app"],
            "process_names": ["Tailscale"],
        },
        "iina": {
            "app_name": "IINA",
            "bundle_ids": ["com.colliderli.iina"],
            "app_paths": ["/Applications/IINA.app"],
            "process_names": ["IINA"],
        },
        "orbstack": {
            "app_name": "OrbStack",
            "bundle_ids": ["dev.kdrag0n.OrbStack"],
            "app_paths": ["/Applications/OrbStack.app"],
            "process_names": ["OrbStack"],
        },
        "claude": {
            "app_name": "Claude",
            "bundle_ids": ["com.anthropic.claudefordesktop"],
            "app_paths": ["/Applications/Claude.app"],
            "process_names": ["Claude"],
        },
        "gemini": {
            "app_name": "Gemini",
            "bundle_ids": ["com.google.gemini"],
            "app_paths": ["/Applications/Gemini.app"],
            "process_names": ["Gemini"],
        },
        "whatsapp": {
            "app_name": "WhatsApp",
            "bundle_ids": ["net.whatsapp.WhatsApp"],
            "app_paths": ["/Applications/WhatsApp.app"],
            "process_names": ["WhatsApp"],
        },
    }

    def __init__(
        self,
        roots: Optional[List[str]] = None,
        app_dirs: Optional[List[str]] = None,
        rules: Optional[List[Dict[str, Any]]] = None,
        stale_days: int = DEFAULT_STALE_DAYS,
        now: Optional[float] = None,
        use_spotlight: bool = True,
        running_processes: Optional[List[str]] = None,
        extra_signatures: Optional[Dict[str, Dict[str, Any]]] = None,
    ):
        self.roots = roots if roots is not None else list(self.DEFAULT_ROOTS)
        self.app_dirs = app_dirs if app_dirs is not None else list(self.DEFAULT_APP_DIRS)
        self.rules = rules or []
        self.stale_days = stale_days
        self.now = now
        self.use_spotlight = use_spotlight
        self._injected_processes = running_processes
        self._process_snapshot: Optional[List[str]] = None
        self._spotlight_cache: Dict[str, bool] = {}

        self.signatures: Dict[str, Dict[str, Any]] = {
            k.lower(): dict(v) for k, v in self.KNOWN_APP_SIGNATURES.items()
        }
        if extra_signatures:
            for k, v in extra_signatures.items():
                self.signatures[k.lower()] = dict(v)

        self._bundle_index: Dict[str, InstalledAppInfo] = {}
        self._name_index: Dict[str, InstalledAppInfo] = {}
        self._apps_indexed = False
        self._covered_prefixes: List[str] = self._extract_covered_prefixes(self.rules)

    @staticmethod
    def _normalize_key(name: str) -> str:
        """归一化应用/目录名称（忽略大小写、空格及连字符）"""
        return re.sub(r"[^a-z0-9]", "", name.lower())

    @staticmethod
    def _extract_covered_prefixes(rules: List[Dict[str, Any]]) -> List[str]:
        """提取已有 YAML 规则覆盖的目标及锁文件路径前缀，避免与 RuleScanner 重复报告"""
        prefixes: Set[str] = set()
        for rule in rules:
            for lf in rule.get("protection", {}).get("lock_files", []):
                if lf:
                    prefixes.add(os.path.dirname(normalize_path(lf)))
            for ch in rule.get("channels", {}).get("related_channels", []):
                if isinstance(ch, dict) and ch.get("data_path"):
                    prefixes.add(normalize_path(ch["data_path"]))
            for items in rule.get("targets", {}).values():
                if not isinstance(items, list):
                    continue
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    raw = item.get("path", "")
                    if not raw:
                        continue
                    prefix = raw.split("*", 1)[0].rstrip("/\\")
                    if prefix:
                        prefixes.add(normalize_path(prefix))
        return sorted(prefixes)

    def _is_covered_by_rules(self, dirpath: str) -> bool:
        """判定目录是否已被内置 YAML 规则或通道矩阵直接覆盖（含其父级容器目录）"""
        norm = normalize_path(dirpath)
        for cov in self._covered_prefixes:
            if norm == cov or norm.startswith(cov + os.sep) or cov.startswith(norm + os.sep):
                return True
        return False

    @staticmethod
    def _read_info_plist(plist_path: str) -> Optional[Dict[str, Any]]:
        """安全读取 XML / Binary Info.plist"""
        try:
            with open(plist_path, "rb") as f:
                data = plistlib.load(f)
            return data if isinstance(data, dict) else None
        except Exception:
            return None

    def build_installed_apps_index(self) -> Tuple[Dict[str, InstalledAppInfo], Dict[str, InstalledAppInfo]]:
        """遍历应用目录构建本地 .app 的 Bundle ID 与应用名索引"""
        if self._apps_indexed:
            return self._bundle_index, self._name_index

        bundle_idx: Dict[str, InstalledAppInfo] = {}
        name_idx: Dict[str, InstalledAppInfo] = {}

        def _scan_app_dir(directory: str, depth: int):
            if depth > 2 or not os.path.isdir(directory):
                return
            try:
                with os.scandir(directory) as it:
                    for entry in it:
                        if not entry.is_dir(follow_symlinks=True):
                            continue
                        if entry.name.endswith(".app"):
                            app_stem = entry.name[:-4]
                            plist_path = os.path.join(entry.path, "Contents", "Info.plist")
                            plist_data = self._read_info_plist(plist_path) if os.path.isfile(plist_path) else None
                            bid = ""
                            exe = ""
                            disp = ""
                            cf_name = ""
                            if plist_data:
                                bid = str(plist_data.get("CFBundleIdentifier") or "").strip()
                                exe = str(plist_data.get("CFBundleExecutable") or "").strip()
                                disp = str(plist_data.get("CFBundleDisplayName") or "").strip()
                                cf_name = str(plist_data.get("CFBundleName") or "").strip()

                            info = InstalledAppInfo(
                                name=disp or cf_name or app_stem,
                                app_path=entry.path,
                                bundle_id=bid,
                                executable=exe,
                                display_name=app_stem,
                            )
                            if bid:
                                bundle_idx[bid.lower()] = info
                            for alias in (app_stem, disp, cf_name, exe):
                                if alias:
                                    nkey = self._normalize_key(alias)
                                    if nkey and nkey not in name_idx:
                                        name_idx[nkey] = info
                        elif depth < 2 and not entry.name.startswith("."):
                            _scan_app_dir(entry.path, depth + 1)
            except OSError:
                pass

        for raw_app_dir in self.app_dirs:
            _scan_app_dir(normalize_path(raw_app_dir), 0)

        self._bundle_index = bundle_idx
        self._name_index = name_idx
        self._apps_indexed = True
        return bundle_idx, name_idx

    def _get_process_snapshot(self) -> List[str]:
        """获取当前活跃进程命令快照（每个扫描周期仅采集一次）"""
        if self._injected_processes is not None:
            return self._injected_processes
        if self._process_snapshot is not None:
            return self._process_snapshot
        procs: List[str] = []
        try:
            res = subprocess.run(["ps", "-eo", "comm="], capture_output=True, text=True, timeout=3)
            if res.returncode == 0:
                procs = [line.strip() for line in res.stdout.splitlines() if line.strip()]
        except Exception:
            procs = []
        self._process_snapshot = procs
        return procs

    def _is_process_active(self, candidates: List[str]) -> bool:
        """核对候选应用名或可执行名是否在活跃进程快照中"""
        procs = self._get_process_snapshot()
        if not procs:
            return False
        lowered_procs = [p.lower() for p in procs]
        for cand in candidates:
            if not cand or len(cand) < 2:
                continue
            cl = cand.lower()
            for pl in lowered_procs:
                base = os.path.basename(pl)
                if cl == base or cl in pl:
                    return True
        return False

    def _has_active_lock(self, dirpath: str) -> bool:
        """检查目录下是否存在运行锁文件/套接字"""
        for lock_name in self.LOCK_INDICATORS:
            if lock_name.startswith("."):
                try:
                    with os.scandir(dirpath) as it:
                        for entry in it:
                            if entry.name.endswith(lock_name):
                                return True
                except OSError:
                    pass
            else:
                if os.path.lexists(os.path.join(dirpath, lock_name)):
                    return True
        return False

    def _is_bundle_id_installed(self, bundle_id: str) -> Optional[InstalledAppInfo]:
        """检查 Bundle ID 是否对应已安装的本地应用（支持直连、辅助后缀前缀匹配及 Spotlight 查询）"""
        if not bundle_id:
            return None
        bundle_idx, _ = self.build_installed_apps_index()
        low = bundle_id.lower()
        if low in bundle_idx:
            return bundle_idx[low]

        # 辅助组件/启动器 Bundle ID 前缀回溯（例如 com.google.GeminiMacOS.launcher -> com.google.GeminiMacOS）
        for installed_bid, info in bundle_idx.items():
            if low.startswith(installed_bid + "."):
                return info

        if not self.use_spotlight:
            return None

        if low in self._spotlight_cache:
            if self._spotlight_cache[low]:
                return InstalledAppInfo(name=bundle_id, app_path="", bundle_id=bundle_id)
            return None

        found = False
        app_path = ""
        try:
            res = subprocess.run(
                ["mdfind", f"kMDItemCFBundleIdentifier == '{bundle_id}'"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            if res.returncode == 0 and res.stdout.strip():
                found = True
                app_path = res.stdout.strip().splitlines()[0].strip()
        except Exception:
            found = False

        self._spotlight_cache[low] = found
        if found:
            app_name = os.path.basename(app_path)[:-4] if app_path.endswith(".app") else bundle_id
            return InstalledAppInfo(name=app_name, app_path=app_path, bundle_id=bundle_id)
        return None

    def _probe_tier1_plist(self, dirpath: str) -> Optional[Tuple[str, str, str]]:
        """
        一级反查：扫描目录下 Info.plist 或反向域名 (CFBundleIdentifier) 目录名
        返回: (bundle_id, app_name, executable) 或 None
        """
        plist_candidates: List[str] = [
            os.path.join(dirpath, "Info.plist"),
            os.path.join(dirpath, "Contents", "Info.plist"),
        ]
        try:
            with os.scandir(dirpath) as it:
                for entry in it:
                    if entry.is_dir(follow_symlinks=False) and not entry.name.startswith("."):
                        plist_candidates.append(os.path.join(entry.path, "Info.plist"))
                        plist_candidates.append(os.path.join(entry.path, "Contents", "Info.plist"))
                    elif entry.is_file(follow_symlinks=False) and entry.name.endswith(".plist"):
                        plist_candidates.append(entry.path)
        except OSError:
            pass

        for plist_path in plist_candidates:
            if not os.path.isfile(plist_path):
                continue
            data = self._read_info_plist(plist_path)
            if not data:
                continue
            bid = str(data.get("CFBundleIdentifier") or "").strip()
            if not bid:
                continue
            app_name = str(
                data.get("CFBundleDisplayName")
                or data.get("CFBundleName")
                or data.get("CFBundleExecutable")
                or bid
            ).strip()
            exe = str(data.get("CFBundleExecutable") or "").strip()
            return bid, app_name, exe

        base = os.path.basename(dirpath)
        if self.BUNDLE_ID_REGEX.match(base) and not base.lower().startswith("com.apple."):
            sig = self.signatures.get(base.lower())
            app_name = sig["app_name"] if sig else base
            return base, app_name, ""

        return None

    @classmethod
    def get_last_access_and_idle_days(
        cls,
        dirpath: str,
        now_ts: float,
        max_entries: int = 300,
    ) -> Tuple[Optional[float], Optional[int]]:
        """
        计算目录及其浅层条目的最近访问/修改时间戳 (max(mtime, atime)) 与闲置天数。
        在调用 scandir 前先记录根目录 lstat，避免扫描本身污染目录 atime。
        """
        try:
            root_st = os.lstat(dirpath)
        except OSError:
            return None, None

        latest_ts = max(root_st.st_mtime, root_st.st_atime)
        checked = 0
        stack = [dirpath]

        try:
            while stack and checked < max_entries:
                current = stack.pop()
                try:
                    with os.scandir(current) as it:
                        for entry in it:
                            checked += 1
                            if checked > max_entries:
                                break
                            try:
                                st = entry.stat(follow_symlinks=False)
                                latest_ts = max(latest_ts, st.st_mtime, st.st_atime)
                            except OSError:
                                pass
                            if entry.is_dir(follow_symlinks=False) and current == dirpath:
                                stack.append(entry.path)
                except OSError:
                    continue
        except OSError:
            pass

        idle_days = max(0, int((now_ts - latest_ts) // 86400))
        return latest_ts, idle_days

    def resolve_directory(self, dirpath: str) -> AssociationResult:
        """
        对单个候选数据目录执行三级反向映射推导:
          Tier 1 -> Info.plist / CFBundleIdentifier
          Tier 2 -> 内置高频特征字典 (KNOWN_APP_SIGNATURES)
          Tier 3 -> 逆向启发式探测 (无对应应用/进程且超过 180 天未访问)
        """
        norm = normalize_path(dirpath)
        dir_name = os.path.basename(norm)
        now_ts = self.now if self.now is not None else time.time()

        # 前置安全与系统红线过滤
        is_redline, redline_reason = is_system_redline_path(norm)
        if is_redline:
            return AssociationResult(norm, dir_name, None, "protected", "skipped", reason=redline_reason)

        is_safe, safety_reason = validate_target_safety(norm)
        if not is_safe:
            return AssociationResult(norm, dir_name, None, "protected", "skipped", reason=safety_reason)

        if (
            dir_name in RootOrphanScanner.IGNORED_ROOT_ENTRIES
            or dir_name in RootOrphanScanner.MACOS_SYSTEM_APP_SUPPORT_DIRS
            or dir_name in self.SHARED_INFRA_DIRS
            or dir_name.startswith(".")
            or dir_name.startswith("com.apple.")
            or RootOrphanScanner.ABNORMAL_NAME_REGEX.match(dir_name)
        ):
            return AssociationResult(norm, dir_name, None, "protected", "skipped", reason="系统/共享框架或已由 RootOrphanScanner 覆盖")

        if self._is_covered_by_rules(norm):
            return AssociationResult(norm, dir_name, None, "protected", "skipped", reason="已由内置 YAML 规则或通道矩阵直接覆盖")

        is_skeleton, _, _ = RootOrphanScanner.inspect_skeleton_dir(norm)
        if is_skeleton:
            return AssociationResult(norm, dir_name, None, "protected", "skipped", reason="骨架空目录已归属 RootOrphanScanner L1")

        bundle_idx, name_idx = self.build_installed_apps_index()
        _, idle_days = self.get_last_access_and_idle_days(norm, now_ts)

        # ── 一级 (Tier 1): Info.plist / CFBundleIdentifier 反查 ──────────────────────────
        t1 = self._probe_tier1_plist(norm)
        if t1 is not None:
            bid, app_name, exe = t1
            matched_app = self._is_bundle_id_installed(bid)
            sig = self.signatures.get(bid.lower())
            if matched_app is None and app_name and app_name != bid:
                matched_app = name_idx.get(self._normalize_key(app_name))
            if matched_app is None and sig is not None:
                for alt_bid in sig.get("bundle_ids", []):
                    matched_app = self._is_bundle_id_installed(alt_bid)
                    if matched_app is not None:
                        break
                if matched_app is None:
                    for ap in sig.get("app_paths", []):
                        if ap and os.path.exists(normalize_path(ap)):
                            matched_app = InstalledAppInfo(name=sig["app_name"], app_path=normalize_path(ap), bundle_id=bid)
                            break

            proc_candidates = [
                c for c in (
                    app_name,
                    exe,
                    matched_app.name if matched_app else "",
                    matched_app.executable if matched_app else "",
                    *(sig.get("process_names", []) if sig else []),
                )
                if c
            ]
            if self._is_process_active(proc_candidates) or self._has_active_lock(norm):
                return AssociationResult(
                    norm, dir_name, 1, "plist_bundle_id", "running",
                    app_name=matched_app.name if matched_app else app_name,
                    bundle_id=bid,
                    inactive_days=idle_days,
                    reason=f"一级 Plist/BundleID ({bid}) 命中运行中应用",
                )
            if matched_app is not None:
                return AssociationResult(
                    norm, dir_name, 1, "plist_bundle_id", "installed",
                    app_name=matched_app.name,
                    bundle_id=bid,
                    inactive_days=idle_days,
                    reason=f"一级 Plist/BundleID ({bid}) 关联至已安装应用 {matched_app.name}",
                )
            return AssociationResult(
                norm, dir_name, 1, "plist_bundle_id", "orphaned",
                app_name=app_name,
                bundle_id=bid,
                inactive_days=idle_days,
                reason=f"一级反向映射 (Info.plist / CFBundleIdentifier: {bid}) 判定应用 [{app_name}] 已卸载",
            )

        # ── 二级 (Tier 2): 内置高频特征字典反查 ───────────────────────────────────────
        sig = self.signatures.get(dir_name.lower())
        if sig is not None:
            sig_app_name = sig["app_name"]
            sig_bids = sig.get("bundle_ids", [])
            sig_app_paths = sig.get("app_paths", [])
            sig_procs = sig.get("process_names", [])

            matched_app = None
            matched_bid = sig_bids[0] if sig_bids else ""
            for bid in sig_bids:
                found = self._is_bundle_id_installed(bid)
                if found is not None:
                    matched_app = found
                    matched_bid = bid
                    break

            app_path_exists = any(os.path.exists(normalize_path(ap)) for ap in sig_app_paths if ap)
            proc_candidates = list(sig_procs) + [sig_app_name]
            if self._is_process_active(proc_candidates) or self._has_active_lock(norm):
                return AssociationResult(
                    norm, dir_name, 2, "signature_db", "running",
                    app_name=sig_app_name,
                    bundle_id=matched_bid or None,
                    inactive_days=idle_days,
                    reason=f"二级特征字典关联 [{sig_app_name}] 正在运行中",
                )
            if matched_app is not None or app_path_exists:
                return AssociationResult(
                    norm, dir_name, 2, "signature_db", "installed",
                    app_name=matched_app.name if matched_app else sig_app_name,
                    bundle_id=matched_bid or None,
                    inactive_days=idle_days,
                    reason=f"二级特征字典关联至已安装应用 [{sig_app_name}]",
                )
            return AssociationResult(
                norm, dir_name, 2, "signature_db", "orphaned",
                app_name=sig_app_name,
                bundle_id=matched_bid or None,
                inactive_days=idle_days,
                reason=f"二级特征字典反向映射：目录 [{dir_name}] 对应应用 [{sig_app_name}] 已卸载",
            )

        # ── 三级 (Tier 3): 启发式探测（应用名归一化反查 + 进程追踪 + >180 天未访问）───
        norm_dir_key = self._normalize_key(dir_name)
        matched_by_name = name_idx.get(norm_dir_key) if norm_dir_key else None
        if matched_by_name is None and norm_dir_key and len(norm_dir_key) >= 4:
            for app_key, app_info in name_idx.items():
                if len(app_key) >= 4 and (norm_dir_key == app_key or (len(norm_dir_key) >= 6 and (norm_dir_key in app_key or app_key in norm_dir_key))):
                    matched_by_name = app_info
                    break

        proc_probe_names = [dir_name]
        if matched_by_name is not None:
            proc_probe_names.extend([matched_by_name.name, matched_by_name.executable, matched_by_name.display_name])

        if self._is_process_active(proc_probe_names) or self._has_active_lock(norm):
            return AssociationResult(
                norm, dir_name, 3, "heuristic", "running",
                app_name=matched_by_name.name if matched_by_name else dir_name,
                bundle_id=matched_by_name.bundle_id if matched_by_name else None,
                inactive_days=idle_days,
                reason=f"三级启发式探测到活跃进程或锁文件 ({dir_name})",
            )

        if matched_by_name is not None:
            return AssociationResult(
                norm, dir_name, 3, "heuristic", "installed",
                app_name=matched_by_name.name,
                bundle_id=matched_by_name.bundle_id or None,
                inactive_days=idle_days,
                reason=f"三级名称归一化匹配到已安装应用 [{matched_by_name.name}]",
            )

        if idle_days is not None and idle_days >= self.stale_days:
            return AssociationResult(
                norm, dir_name, 3, "heuristic", "orphaned",
                app_name=dir_name,
                bundle_id=None,
                inactive_days=idle_days,
                reason=f"三级启发式探测：无对应已安装应用或活跃进程，且已超过 {idle_days} 天未被访问 (阈值 {self.stale_days} 天)",
            )

        return AssociationResult(
            norm, dir_name, 3, "heuristic", "active_unknown",
            app_name=dir_name,
            inactive_days=idle_days,
            reason=f"近期仍有访问记录 ({idle_days if idle_days is not None else 0} 天前)，安全跳过",
        )

    def scan(self) -> ToolScanReport:
        """执行三级反向映射孤儿目录扫描"""
        targets: List[TargetMatch] = []
        detection_matches: List[str] = []
        seen_paths: Set[str] = set()

        for raw_root in self.roots:
            root_path = normalize_path(raw_root)
            if not os.path.isdir(root_path):
                continue
            detection_matches.append(f"三级反向映射扫描: {raw_root}")
            try:
                with os.scandir(root_path) as it:
                    entries = sorted(
                        (e for e in it if e.is_dir(follow_symlinks=False)),
                        key=lambda e: e.name,
                    )
            except OSError:
                continue

            for entry in entries:
                if entry.path in seen_paths:
                    continue
                res = self.resolve_directory(entry.path)
                if res.status != "orphaned":
                    continue

                size_bytes, file_count = ChannelRedundancyScanner._compute_path_size_and_count(entry.path)
                secret_res = SecretLeakAuditor.inspect_path(entry.path)
                risk_lvl, is_safe, safety_reason = assess_risk_level(
                    target_path=entry.path,
                    software_status="orphaned",
                    contains_secrets=secret_res.contains_secrets,
                    category="data_and_history",
                )
                if not is_safe or risk_lvl == RiskLevel.L4_DANGER:
                    continue

                seen_paths.add(entry.path)
                targets.append(TargetMatch(
                    category="data_and_history",
                    raw_path=entry.path,
                    resolved_path=entry.path,
                    description=res.reason,
                    size_bytes=size_bytes,
                    file_count=file_count,
                    contains_secrets=secret_res.contains_secrets,
                    is_model_weight=False,
                    default_selected=not secret_res.contains_secrets,
                    is_safe=is_safe,
                    safety_reason=safety_reason,
                    risk_level=risk_lvl.value if isinstance(risk_lvl, RiskLevel) else str(risk_lvl),
                    prunable=False,
                    regenerable=False,
                    inactive_days=res.inactive_days,
                    tool_id="orphan-associations",
                    tool_name=res.app_name or entry.name,
                    association_tier=res.tier,
                    association_method=res.method,
                    associated_app=res.app_name,
                    associated_bundle_id=res.bundle_id,
                    secret_findings=secret_res.findings,
                    secret_severity=secret_res.severity,
                ))

        total_size = sum(t.size_bytes for t in targets)
        safe_size = sum(t.size_bytes for t in targets if t.is_safe)

        return ToolScanReport(
            tool_id="orphan-associations",
            name="孤儿目录反向映射 (Association Engine)",
            category="other",
            vendor="Three-Tier Reverse Association",
            homepage="",
            status="orphaned" if targets else "clean",
            detection_matches=detection_matches,
            targets=targets,
            total_size_bytes=total_size,
            safe_size_bytes=safe_size,
            model_weight_size_bytes=0,
        )


class RuleScanner:
    def __init__(self, rules_dir: Optional[str] = None):
        self.rules_dirs = []
        if rules_dir:
            self.rules_dirs.append(rules_dir)
        else:
            # 1. 环境变量自定义规则目录
            env_dir = os.environ.get("SEA_OTTER_RULES_DIR")
            if env_dir and os.path.isdir(env_dir):
                self.rules_dirs.append(env_dir)

            # 2. 包内置规则目录 (pip 安装后)
            pkg_rules = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")
            if os.path.isdir(pkg_rules):
                self.rules_dirs.append(pkg_rules)

            # 3. 源码开发根目录 rules
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            repo_rules = os.path.join(base_dir, "rules")
            if os.path.isdir(repo_rules) and repo_rules not in self.rules_dirs:
                self.rules_dirs.append(repo_rules)

            # 4. 用户家目录自定义规则 (~/.config/sea-otter/rules)
            user_rules = os.path.expanduser("~/.config/sea-otter/rules")
            if os.path.isdir(user_rules) and user_rules not in self.rules_dirs:
                self.rules_dirs.append(user_rules)

        self._bundle_cache: Optional[Dict[str, str]] = None

    def load_rules(self, filter_ids: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """加载所有或指定 ID 的 YAML 规则，支持多目录合并与 ID 去重"""
        rule_map = {}
        for r_dir in self.rules_dirs:
            if not os.path.isdir(r_dir):
                continue
            rule_files = sorted(glob.glob(os.path.join(r_dir, "*.yaml")))
            for rf in rule_files:
                try:
                    with open(rf, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                        if data and isinstance(data, dict):
                            rule_id = data.get("id")
                            if not rule_id:
                                continue
                            if filter_ids and rule_id not in filter_ids:
                                continue
                            # 后面的规则目录覆盖前面的同名规则
                            rule_map[rule_id] = data
                except Exception as e:
                    print(f"警告: 读取规则文件 {rf} 失败: {e}")
        return list(rule_map.values())

    def _get_path_size_and_count(self, path: str) -> tuple[int, int]:
        """计算单个文件或目录的大小与文件总数"""
        if not os.path.exists(path):
            return 0, 0
        if os.path.islink(path) or os.path.isfile(path):
            try:
                return os.path.getsize(path), 1
            except OSError:
                return 0, 1
        
        total_size = 0
        file_count = 0
        try:
            for root, dirs, files in os.walk(path):
                for f in files:
                    fp = os.path.join(root, f)
                    try:
                        # 忽略软链接指向的目标体积，仅统计自身
                        st = os.lstat(fp)
                        total_size += st.st_size
                        file_count += 1
                    except OSError:
                        pass
        except OSError:
            pass
        return total_size, file_count

    def _check_bundle_id_installed(self, bundle_id: str) -> bool:
        """检查 macOS 上是否存在该 Bundle ID 的应用"""
        try:
            cmd = ["mdfind", f"kMDItemCFBundleIdentifier == '{bundle_id}'"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
            if res.returncode == 0 and res.stdout.strip():
                return True
        except Exception:
            pass
        return False

    def detect_software_installed(self, rule: Dict[str, Any]) -> tuple[bool, List[str]]:
        """判定软件是否当前已安装，并返回命中凭证"""
        matches = []
        det = rule.get("detection", {})
        
        # 1. 检查 app_paths
        for app_path in det.get("app_paths", []):
            expanded = normalize_path(app_path)
            if os.path.exists(expanded):
                matches.append(f"App 存在: {app_path}")
                return True, matches

        # 2. 检查 cli_binaries
        for cli in det.get("cli_binaries", []):
            expanded = normalize_path(cli)
            if os.path.exists(expanded):
                matches.append(f"CLI 二进制存在: {cli}")
                return True, matches

        # 3. 检查 app_bundle_id (通过 Spotlight 元数据快速判定)
        for bid in det.get("app_bundle_id", []):
            if self._check_bundle_id_installed(bid):
                matches.append(f"Bundle ID 已注册: {bid}")
                return True, matches

        return False, []

    def _check_running_processes(self, process_names: List[str]) -> List[str]:
        """检查系统进程表中是否存在指定的活跃进程 (pgrep 快速核对)"""
        matched = []
        for pname in process_names:
            if not pname:
                continue
            try:
                # 使用 pgrep 匹配进程命令行
                res = subprocess.run(["pgrep", "-fl", pname], capture_output=True, text=True, timeout=2)
                if res.returncode == 0 and res.stdout.strip():
                    lines = [line.strip() for line in res.stdout.strip().splitlines()]
                    for l in lines[:2]:
                        matched.append(l)
            except Exception:
                pass
        return matched

    def _check_active_locks(self, lock_files: List[str]) -> List[str]:
        """检查是否存在活跃的单例运行锁文件或套接字"""
        matched = []
        for lf in lock_files:
            exp = normalize_path(lf)
            if os.path.exists(exp):
                matched.append(lf)
        return matched

    def scan_tool(self, rule: Dict[str, Any]) -> ToolScanReport:
        """针对单个工具规则执行完整扫描 (融入 v1.1 存活交叉验证与安全防线)"""
        tool_id = rule.get("id", "unknown")
        name = rule.get("name", tool_id)
        category = rule.get("category", "other")
        vendor = rule.get("vendor", "")
        homepage = rule.get("homepage", "")
        safety_config = rule.get("safety", {})
        protection_config = rule.get("protection", {})

        # 1. 活跃保护存活检测 (铁律一：多维存活状态交叉验证)
        proc_names = protection_config.get("process_names", [])
        active_processes = self._check_running_processes(proc_names)

        lock_files = protection_config.get("lock_files", [])
        active_locks = self._check_active_locks(lock_files)

        is_running = bool(active_processes or active_locks)

        # 2. 安装状态检测
        is_installed, det_matches = self.detect_software_installed(rule)
        preliminary_status = "running" if is_running else ("installed" if is_installed else "orphaned")
        
        targets: List[TargetMatch] = []
        total_size = 0
        safe_size = 0
        model_weight_size = 0

        target_categories = rule.get("targets", {})
        for cat_name, items in target_categories.items():
            if not isinstance(items, list):
                continue
            for item in items:
                raw_path = item.get("path", "")
                if not raw_path:
                    continue
                
                expanded_pattern = normalize_path(raw_path)
                # 支持 glob 通配符
                matched_paths = glob.glob(expanded_pattern)
                if not matched_paths and os.path.exists(expanded_pattern):
                    matched_paths = [expanded_pattern]

                for p in matched_paths:
                    if not os.path.exists(p):
                        continue
                    
                    size, count = self._get_path_size_and_count(p)
                    # 执行端侧 AI 模型与权重专项嗅探 (AIModelScanner)
                    model_res = AIModelScanner.inspect_path(p)
                    is_model = item.get("is_model_weight", False) or cat_name == "ai_models" or model_res.is_model_weight
                    detected_model_name = item.get("model_name") or model_res.model_name
                    detected_model_format = item.get("model_format") or model_res.model_format

                    declared_secret = item.get("contains_secrets", False)
                    if cat_name in ("caches", "ai_models", "binaries_and_scripts") or is_model:
                        secret_res = SecretAuditResult(
                            contains_secrets=declared_secret,
                            severity="medium" if declared_secret else None,
                            findings=["规则声明包含敏感认证凭据"] if declared_secret else [],
                        )
                    else:
                        secret_res = SecretLeakAuditor.inspect_path(p, declared_contains_secrets=declared_secret)

                    has_secret = secret_res.contains_secrets
                    declared_level = item.get("risk_level")

                    # 四级安全矩阵评估
                    risk_lvl, is_safe, reason = assess_risk_level(
                        target_path=p,
                        software_status=preliminary_status,
                        rule_safety=safety_config,
                        is_model_weight=is_model,
                        contains_secrets=has_secret,
                        category=cat_name,
                        declared_risk_level=declared_level
                    )

                    # 默认勾选逻辑:
                    # L1 (极低风险): 默认勾选归档
                    # L2 (明确已卸载): 默认勾选隔离（含敏感凭据时默认取消勾选以提示备份/确认）
                    # L3 (在用软件减负): 默认不勾选，需用户确认
                    # L4 (绝对系统红线): 硬编码阻断，不可勾选
                    if risk_lvl == RiskLevel.L4_DANGER:
                        default_selected = False
                        is_safe = False
                    elif has_secret:
                        default_selected = False
                    elif risk_lvl == RiskLevel.L3_IN_USE:
                        default_selected = False
                    elif risk_lvl in [RiskLevel.L1_SAFE, RiskLevel.L2_ORPHAN]:
                        default_selected = item.get("default_selected", True)
                    else:
                        default_selected = False

                    prunable = item.get("prunable", False)
                    regenerable = item.get("regenerable", True)

                    t_match = TargetMatch(
                        category=cat_name,
                        raw_path=raw_path,
                        resolved_path=p,
                        description=item.get("description", ""),
                        size_bytes=size,
                        file_count=count,
                        contains_secrets=has_secret,
                        is_model_weight=is_model,
                        default_selected=default_selected,
                        is_safe=is_safe,
                        safety_reason=reason,
                        risk_level=risk_lvl.value if isinstance(risk_lvl, RiskLevel) else str(risk_lvl),
                        model_name=detected_model_name,
                        model_format=detected_model_format,
                        prunable=prunable,
                        regenerable=regenerable,
                        tool_id=tool_id,
                        tool_name=name,
                        secret_findings=secret_res.findings,
                        secret_severity=secret_res.severity,
                    )
                    targets.append(t_match)

                    # 处理嵌套细粒度子项目 (sub_targets)
                    sub_items = item.get("sub_targets", [])
                    for sub in sub_items:
                        sub_raw_path = sub.get("path", "")
                        if not sub_raw_path:
                            continue
                        sub_expanded = normalize_path(sub_raw_path)
                        sub_matched = glob.glob(sub_expanded)
                        if not sub_matched and os.path.exists(sub_expanded):
                            sub_matched = [sub_expanded]
                        for sp in sub_matched:
                            if not os.path.exists(sp):
                                continue
                            sp_size, sp_count = self._get_path_size_and_count(sp)
                            sp_model_res = AIModelScanner.inspect_path(sp)
                            sp_is_model = sub.get("is_model_weight", False) or cat_name == "ai_models" or sp_model_res.is_model_weight
                            sp_model_name = sub.get("model_name") or sp_model_res.model_name
                            sp_model_format = sub.get("model_format") or sp_model_res.model_format
                            sp_declared_secret = sub.get("contains_secrets", False)
                            if cat_name in ("caches", "ai_models") or sp_is_model or sub.get("prunable", False):
                                sp_secret_res = SecretAuditResult(
                                    contains_secrets=sp_declared_secret,
                                    severity="medium" if sp_declared_secret else None,
                                    findings=["规则声明包含敏感认证凭据"] if sp_declared_secret else [],
                                )
                            else:
                                sp_secret_res = SecretLeakAuditor.inspect_path(sp, declared_contains_secrets=sp_declared_secret)
                            sp_secret = sp_secret_res.contains_secrets
                            sp_declared_lvl = sub.get("risk_level")
                            sp_risk_lvl, sp_safe, sp_reason = assess_risk_level(
                                target_path=sp,
                                software_status=preliminary_status,
                                rule_safety=safety_config,
                                is_model_weight=sp_is_model,
                                contains_secrets=sp_secret,
                                category=cat_name,
                                declared_risk_level=sp_declared_lvl
                            )
                            targets.append(TargetMatch(
                                category=cat_name,
                                raw_path=sub_raw_path,
                                resolved_path=sp,
                                description=sub.get("description", ""),
                                size_bytes=sp_size,
                                file_count=sp_count,
                                contains_secrets=sp_secret,
                                is_model_weight=sp_is_model,
                                default_selected=False,
                                is_safe=sp_safe,
                                safety_reason=sp_reason,
                                risk_level=sp_risk_lvl.value if isinstance(sp_risk_lvl, RiskLevel) else str(sp_risk_lvl),
                                model_name=sp_model_name,
                                model_format=sp_model_format,
                                prunable=sub.get("prunable", True),
                                sub_target_of=p,
                                regenerable=sub.get("regenerable", True),
                                tool_id=tool_id,
                                tool_name=name,
                                secret_findings=sp_secret_res.findings,
                                secret_severity=sp_secret_res.severity,
                            ))

        # 处理规则中声明的 ghost_rules.root_patterns (Schema v1.2)
        ghost_rules = rule.get("ghost_rules", {})
        root_patterns = ghost_rules.get("root_patterns", []) if isinstance(ghost_rules, dict) else []
        existing_resolved = {t.resolved_path for t in targets}
        for gp in root_patterns:
            regex_str = gp.get("regex", "")
            if not regex_str:
                continue
            try:
                compiled = re.compile(regex_str)
            except re.error:
                continue

            gp_roots = gp.get("target_roots") or ["~/Library/Application Support"]
            gp_desc = gp.get("description", "规则声明的幽灵残留")
            gp_risk = gp.get("risk_level", RiskLevel.L1_SAFE.value)

            for raw_root in gp_roots:
                norm_root = normalize_path(raw_root)
                if not os.path.isdir(norm_root):
                    continue
                try:
                    with os.scandir(norm_root) as it:
                        for entry in it:
                            if entry.path in existing_resolved:
                                continue
                            if compiled.match(entry.name):
                                g_size, g_count = self._get_path_size_and_count(entry.path)
                                g_risk_lvl, g_safe, g_reason = assess_risk_level(
                                    target_path=entry.path,
                                    software_status=preliminary_status,
                                    rule_safety=safety_config,
                                    category="ghost",
                                    declared_risk_level=gp_risk,
                                )
                                g_default_sel = (
                                    g_risk_lvl in [RiskLevel.L1_SAFE, RiskLevel.L2_ORPHAN]
                                    and g_safe
                                )
                                targets.append(TargetMatch(
                                    category="ghost",
                                    raw_path=f"{raw_root}/{entry.name}",
                                    resolved_path=entry.path,
                                    description=gp_desc,
                                    size_bytes=g_size,
                                    file_count=g_count,
                                    contains_secrets=False,
                                    is_model_weight=False,
                                    default_selected=g_default_sel,
                                    is_safe=g_safe,
                                    safety_reason=g_reason,
                                    risk_level=g_risk_lvl.value if isinstance(g_risk_lvl, RiskLevel) else str(g_risk_lvl),
                                    prunable=False,
                                    regenerable=False,
                                    ghost_type="rule_ghost",
                                    tool_id=tool_id,
                                    tool_name=name,
                                ))
                                existing_resolved.add(entry.path)
                except OSError:
                    continue

        # 对命中的路径进行容量去重计算（如果父目录已被包含，不重复累加总大小）
        resolved_dirs = set()
        for t in targets:
            if os.path.isdir(t.resolved_path):
                resolved_dirs.add(t.resolved_path)

        for t in targets:
            is_nested = False
            for d in resolved_dirs:
                if d != t.resolved_path and t.resolved_path.startswith(d + os.sep):
                    is_nested = True
                    break
            
            if not is_nested:
                total_size += t.size_bytes
                if t.is_safe:
                    safe_size += t.size_bytes
                if t.is_model_weight:
                    model_weight_size += t.size_bytes

        # 状态判定状态机
        if is_running:
            status = "running"
        elif is_installed:
            status = "installed"
        elif len(targets) > 0:
            status = "orphaned"
        else:
            status = "clean"

        return ToolScanReport(
            tool_id=tool_id,
            name=name,
            category=category,
            vendor=vendor,
            homepage=homepage,
            status=status,
            detection_matches=det_matches,
            running_processes=active_processes,
            active_locks=active_locks,
            targets=targets,
            total_size_bytes=total_size,
            safe_size_bytes=safe_size,
            model_weight_size_bytes=model_weight_size
        )

    def scan_all(
        self,
        filter_ids: Optional[List[str]] = None,
        include_root_orphans: bool = True,
        include_channel_redundancy: bool = True,
        include_associations: bool = True,
    ) -> List[ToolScanReport]:
        """扫描所有规则，并默认联动 RootOrphanScanner、ChannelRedundancyScanner 与 AssociationEngine"""
        all_rules = self.load_rules()
        rules = [r for r in all_rules if not filter_ids or r.get("id") in filter_ids]
        reports = []
        for r in rules:
            reports.append(self.scan_tool(r))

        if include_root_orphans and (filter_ids is None or "root-orphans" in filter_ids):
            reports.append(RootOrphanScanner().scan())

        if include_channel_redundancy and (filter_ids is None or "channel-redundancy" in filter_ids):
            reports.append(ChannelRedundancyScanner(rules=all_rules, use_builtin_defaults=True).scan())

        if include_associations and (filter_ids is None or "orphan-associations" in filter_ids):
            reports.append(AssociationEngine(rules=all_rules).scan())

        return reports
