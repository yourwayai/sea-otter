"""
扫描引擎核心模块 (Scanner Engine)
解析规则库，判定软件安装状态，递归计算文件空间与安全状态。
"""

import os
import re
import glob
import json
import time
import subprocess
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
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
        "Preview",
        "SyncedPreferences",
        "System Preferences",
        "TrustedPeersHelper",
        "accountsd",
        "familycircled",
        "homeenergyd",
        "icdd",
        "iCloud",
        "locationaccessstored",
        "syncdefaultsd",
        "transparencyd",
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

                    has_secret = item.get("contains_secrets", False)
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
                    # L2 (明确已卸载): 默认勾选隔离
                    # L3 (在用软件减负): 默认不勾选，需用户确认
                    # L4 (绝对系统红线): 硬编码阻断，不可勾选
                    if risk_lvl == RiskLevel.L4_DANGER:
                        default_selected = False
                        is_safe = False
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
                            sp_secret = sub.get("contains_secrets", False)
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
    ) -> List[ToolScanReport]:
        """扫描所有规则，并默认联动 RootOrphanScanner 与 ChannelRedundancyScanner"""
        all_rules = self.load_rules()
        rules = [r for r in all_rules if not filter_ids or r.get("id") in filter_ids]
        reports = []
        for r in rules:
            reports.append(self.scan_tool(r))

        if include_root_orphans and (filter_ids is None or "root-orphans" in filter_ids):
            reports.append(RootOrphanScanner().scan())

        if include_channel_redundancy and (filter_ids is None or "channel-redundancy" in filter_ids):
            reports.append(ChannelRedundancyScanner(rules=all_rules, use_builtin_defaults=True).scan())

        return reports
