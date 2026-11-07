"""
扫描引擎核心模块 (Scanner Engine)
解析规则库，判定软件安装状态，递归计算文件空间与安全状态。
"""

import os
import glob
import subprocess
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
import yaml

from sea_otter.safety import normalize_path, validate_target_safety

@dataclass
class TargetMatch:
    category: str
    raw_path: str
    resolved_path: str
    description: str
    size_bytes: int
    file_count: int
    contains_secrets: bool
    default_selected: bool
    is_safe: bool
    safety_reason: str

@dataclass
class ToolScanReport:
    tool_id: str
    name: str
    category: str
    vendor: str
    homepage: str
    status: str  # "installed" | "orphaned" | "clean"
    detection_matches: List[str] = field(default_factory=list)
    targets: List[TargetMatch] = field(default_factory=list)
    total_size_bytes: int = 0
    safe_size_bytes: int = 0

    @property
    def has_residuals(self) -> bool:
        return len(self.targets) > 0

    @property
    def secret_count(self) -> int:
        return sum(1 for t in self.targets if t.contains_secrets)

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

    def scan_tool(self, rule: Dict[str, Any]) -> ToolScanReport:
        """针对单个工具规则执行完整扫描"""
        tool_id = rule.get("id", "unknown")
        name = rule.get("name", tool_id)
        category = rule.get("category", "other")
        vendor = rule.get("vendor", "")
        homepage = rule.get("homepage", "")
        safety_config = rule.get("safety", {})

        is_installed, det_matches = self.detect_software_installed(rule)
        
        targets: List[TargetMatch] = []
        total_size = 0
        safe_size = 0

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
                    is_safe, reason = validate_target_safety(p, safety_config)

                    t_match = TargetMatch(
                        category=cat_name,
                        raw_path=raw_path,
                        resolved_path=p,
                        description=item.get("description", ""),
                        size_bytes=size,
                        file_count=count,
                        contains_secrets=item.get("contains_secrets", False),
                        default_selected=item.get("default_selected", True),
                        is_safe=is_safe,
                        safety_reason=reason
                    )
                    targets.append(t_match)

        # 对命中的路径进行容量去重计算（如果父目录已被包含，不重复累加总大小）
        # 首先按路径长度正序排序，先处理父目录
        resolved_dirs = set()
        for t in targets:
            if os.path.isdir(t.resolved_path):
                resolved_dirs.add(t.resolved_path)

        for t in targets:
            # 判断当前路径是否被已经在 targets 中的某个父目录包含
            is_nested = False
            for d in resolved_dirs:
                if d != t.resolved_path and t.resolved_path.startswith(d + os.sep):
                    is_nested = True
                    break
            
            # 如果不是被更大父目录包含的子项，则计入总容量
            if not is_nested:
                total_size += t.size_bytes
                if t.is_safe:
                    safe_size += t.size_bytes

        if is_installed:
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
            targets=targets,
            total_size_bytes=total_size,
            safe_size_bytes=safe_size
        )

    def scan_all(self, filter_ids: Optional[List[str]] = None) -> List[ToolScanReport]:
        """扫描所有规则"""
        rules = self.load_rules(filter_ids)
        reports = []
        for r in rules:
            reports.append(self.scan_tool(r))
        return reports
