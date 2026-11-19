"""
扫描引擎核心模块 (Scanner Engine)
解析规则库，判定软件安装状态，递归计算文件空间与安全状态。
"""

import os
import glob
import json
import subprocess
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
import yaml

from sea_otter.safety import normalize_path, validate_target_safety, assess_risk_level, RiskLevel

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
                        regenerable=regenerable
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
                                regenerable=sub.get("regenerable", True)
                            ))

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

    def scan_all(self, filter_ids: Optional[List[str]] = None) -> List[ToolScanReport]:
        """扫描所有规则"""
        rules = self.load_rules(filter_ids)
        reports = []
        for r in rules:
            reports.append(self.scan_tool(r))
        return reports
