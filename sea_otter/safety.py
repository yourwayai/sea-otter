"""
安全防线与保护策略模块 (Safety Guard)
确保不会误删系统关键目录、用户工作区或 Git 仓库。
"""

import os
from typing import Tuple, List, Optional

# 系统核心保护目录（绝对路径）
PROTECTED_SYSTEM_PATHS = {
    "/",
    "/System",
    "/Library",
    "/usr",
    "/usr/bin",
    "/usr/local",
    "/usr/local/bin",
    "/opt",
    "/Applications",
    "/bin",
    "/sbin",
    "/private",
    "/etc",
    "/var",
}

# 用户主目录核心保护目录
def get_protected_user_roots() -> List[str]:
    home = os.path.expanduser("~")
    return [
        home,
        os.path.join(home, "Desktop"),
        os.path.join(home, "Documents"),
        os.path.join(home, "Downloads"),
        os.path.join(home, "Pictures"),
        os.path.join(home, "Music"),
        os.path.join(home, "Movies"),
        os.path.join(home, "Applications"),
        os.path.join(home, "Library"),
    ]

def normalize_path(path: str) -> str:
    """展开并标准化路径"""
    return os.path.abspath(os.path.expanduser(path))

def contains_git_repo(path: str) -> bool:
    """检查指定路径自身或其直接内部是否是 Git 仓库"""
    normalized = normalize_path(path)
    if not os.path.exists(normalized):
        return False
    
    # 路径本身包含 .git (比如 /foo/bar/.git)
    if normalized.endswith("/.git") or os.path.basename(normalized) == ".git":
        return True
        
    # 目标目录内是否含有 .git
    if os.path.isdir(normalized):
        if os.path.exists(os.path.join(normalized, ".git")):
            return True
    return False

def validate_target_safety(target_path: str, rule_safety: Optional[dict] = None) -> Tuple[bool, str]:
    """
    全面校验目标路径清理的安全性
    返回: (is_safe: bool, reason: str)
    """
    normalized = normalize_path(target_path)

    # 1. 系统核心路径防线
    if normalized in PROTECTED_SYSTEM_PATHS:
        return False, f"拒绝清理系统核心根路径: {normalized}"

    # 2. 用户家目录及其一级核心系统目录保护
    protected_user_roots = get_protected_user_roots()
    if normalized in protected_user_roots:
        return False, f"拒绝清理受保护的用户根目录: {normalized}"

    # 3. 根路径层级过浅保护（如 /Users/xxx 本身）
    parts = [p for p in normalized.split(os.sep) if p]
    if len(parts) <= 2 and not normalized.startswith("/Volumes"):
        return False, f"路径层级过浅，存在全盘删除风险: {normalized}"

    # 4. 规则特定的排除路径 (exclude_paths)
    if rule_safety:
        exclude_paths = rule_safety.get("exclude_paths", [])
        for ex in exclude_paths:
            ex_norm = normalize_path(ex)
            # 如果目标路径与排除路径完全匹配，或目标路径是排除路径的父目录/包含排除路径
            if normalized == ex_norm or ex_norm.startswith(normalized + os.sep):
                return False, f"命中了规则中配置的严格排除路径: {ex}"

    # 5. Git 仓库强保护检测
    protect_git = True
    if rule_safety is not None and "protect_git_repos" in rule_safety:
        protect_git = rule_safety["protect_git_repos"]

    if protect_git and contains_git_repo(normalized):
        return False, f"检测到 Git 代码仓库 (.git)，安全策略已阻断清理: {normalized}"

    return True, "安全校验通过"
