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

WORKSPACE_INDICATORS = {".git", ".svn", ".hg", ".obsidian"}

def contains_workspace_or_repo(path: str) -> Tuple[bool, str]:
    """检查指定路径自身或其内部是否是 Git/SVN/Obsidian 等工作区资产"""
    normalized = normalize_path(path)
    if not os.path.exists(normalized):
        return False, ""
    
    # 路径本身就是版本控制或笔记库标识
    base = os.path.basename(normalized)
    if base in WORKSPACE_INDICATORS:
        return True, base
        
    # 目标目录内是否直接含有工作区标识
    if os.path.isdir(normalized):
        for ind in WORKSPACE_INDICATORS:
            if os.path.exists(os.path.join(normalized, ind)):
                return True, ind
    return False, ""

def validate_target_safety(target_path: str, rule_safety: Optional[dict] = None) -> Tuple[bool, str]:
    """
    全面校验目标路径清理的安全性 (严格实施零误伤防线)
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
            # 如果目标路径与排除路径完全匹配，或者目标路径在排除路径内部，或者目标路径是排除路径的父目录
            if normalized == ex_norm or normalized.startswith(ex_norm + os.sep) or ex_norm.startswith(normalized + os.sep):
                return False, f"命中了规则中配置的严格排除路径: {ex}"

    # 5. 代码工程与工作区“强制免疫”（.git / .svn / .obsidian）
    protect_git = True
    protect_workspaces = True
    if rule_safety is not None:
        protect_git = rule_safety.get("protect_git_repos", True)
        protect_workspaces = rule_safety.get("protect_workspaces", True)

    if protect_git or protect_workspaces:
        has_ws, ind_name = contains_workspace_or_repo(normalized)
        if has_ws:
            return False, f"检测到工作区/工程资产 ({ind_name})，强制免疫阻断清理: {normalized}"

    return True, "安全校验通过"
