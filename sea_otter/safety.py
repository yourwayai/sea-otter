"""
安全防线与保护策略模块 (Safety Guard)
确保不会误删系统关键目录、用户工作区或 Git 仓库。
"""

import os
from typing import Tuple, List, Optional

from enum import Enum

class RiskLevel(str, Enum):
    """
    四级安全防护矩阵定义 (Four-Tier Safety Risk Matrix)
    """
    L1_SAFE = "L1_SAFE"          # 极低风险 (Zero-Impact Junk): 空锁、散落图片、(null) 目录，默认勾选归档
    L2_ORPHAN = "L2_ORPHAN"      # 明确已卸载 (Orphaned Apps): 软件已删除的孤儿配置，默认勾选隔离
    L3_IN_USE = "L3_IN_USE"      # 在用软件减负 (Bloatware/Cache): 正在使用的软件模型/缓存，默认不勾选，提示确认
    L4_DANGER = "L4_DANGER"      # 绝对系统红线 (Protected System): 系统原生关键库、工程资产，硬编码阻断

# 风险级别中文语义与说明
RISK_LEVEL_LABELS = {
    RiskLevel.L1_SAFE: "极低风险 (Zero-Impact Junk)",
    RiskLevel.L2_ORPHAN: "明确已卸载 (Orphaned Apps)",
    RiskLevel.L3_IN_USE: "在用软件减负 (Bloatware/Cache)",
    RiskLevel.L4_DANGER: "绝对系统红线 (Protected System)",
}

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

# 系统红线库 (System Redline Vault): 绝对禁止触碰的原生关键服务与权限数据库
SYSTEM_REDLINE_BASENAMES = {
    "com.apple.TCC",             # 隐私与权限核心数据库 (麦克风/摄像头/完全磁盘访问)
    "AddressBook",               # 系统联系人数据库
    "CallHistoryDB",             # 通话记录数据库
    "CloudDocs",                 # iCloud 云盘元数据与同步层
    "Keychain",                  # 系统钥匙串
    "com.apple.sharedfilelist",  # 系统共享与快速访问列表
    "Safari",                    # 原生浏览器关键偏好
    "Mail",                      # 原生邮件库
    "Photos",                    # 原生相册元数据
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

def is_system_redline_path(path: str) -> Tuple[bool, str]:
    """
    检查路径是否命中了 macOS 系统红线服务或核心系统组件 (L4 硬编码保护)
    """
    normalized = normalize_path(path)
    base = os.path.basename(normalized)

    # 1. 命中关键服务名称
    if base in SYSTEM_REDLINE_BASENAMES:
        return True, f"命中绝对系统红线服务: {base}"

    # 2. 检查是否在系统关键库的子目录中
    for redline in SYSTEM_REDLINE_BASENAMES:
        if f"{os.sep}{redline}{os.sep}" in normalized or normalized.endswith(f"{os.sep}{redline}"):
            return True, f"命中绝对系统红线子路径: {redline}"

    # 3. 拦截 com.apple 原生系统级配置
    if base.startswith("com.apple.") and "Application Support" in normalized:
        return True, f"命中 Apple 系统原生服务配置: {base}"

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

    # 4. 系统红线库 (System Redline Vault) 强阻断
    is_redline, redline_reason = is_system_redline_path(normalized)
    if is_redline:
        return False, f"触发系统红线硬白名单保护: {redline_reason}"

    # 5. 规则特定的排除路径 (exclude_paths)
    if rule_safety:
        exclude_paths = rule_safety.get("exclude_paths", [])
        for ex in exclude_paths:
            ex_norm = normalize_path(ex)
            # 如果目标路径与排除路径完全匹配，或者目标路径在排除路径内部，或者目标路径是排除路径的父目录
            if normalized == ex_norm or normalized.startswith(ex_norm + os.sep) or ex_norm.startswith(normalized + os.sep):
                return False, f"命中了规则中配置的严格排除路径: {ex}"

    # 6. 代码工程与工作区“强制免疫”（.git / .svn / .obsidian）
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

def assess_risk_level(
    target_path: str,
    software_status: str,
    rule_safety: Optional[dict] = None,
    is_model_weight: bool = False,
    contains_secrets: bool = False,
    category: str = "",
    declared_risk_level: Optional[str] = None
) -> Tuple[RiskLevel, bool, str]:
    """
    四级安全防护矩阵综合仲裁器 (Four-Tier Safety Risk Arbiter)
    返回: (risk_level: RiskLevel, is_safe: bool, reason: str)
    
    矩阵定义:
      • L1 (极低风险): 空锁、散落图片、(null) 目录、纯日志/下载缓存，默认勾选归档
      • L2 (明确已卸载): 软件已删除的孤儿配置/历史数据，默认勾选隔离
      • L3 (在用软件减负): 正在使用的软件模型/缓存/工作区，默认不勾选，提示确认
      • L4 (绝对系统红线): 系统原生关键库、工作区Git工程、正在运行的进程，硬编码阻断
    """
    normalized = normalize_path(target_path)
    base_name = os.path.basename(normalized)

    # 1. 优先校验绝对红线 (L4 绝对系统红线)
    is_safe, safety_reason = validate_target_safety(normalized, rule_safety=rule_safety)
    if not is_safe:
        return RiskLevel.L4_DANGER, False, safety_reason

    # 2. 进程活跃锁定：运行中的软件归为 L4 阻断
    if software_status == "running":
        return RiskLevel.L4_DANGER, False, "软件正在运行中，安全防线强制锁定保护"

    # 3. 显式指定的规则风险等级校验（如果规则显式指定了且不是 L4）
    if declared_risk_level:
        try:
            matched_level = RiskLevel(declared_risk_level)
            if matched_level == RiskLevel.L4_DANGER:
                return RiskLevel.L4_DANGER, False, "规则声明为 L4 绝对红线"
            # 规则指定 L1/L2/L3 时：如果是已安装在用软件，安全降级至最少 L3
            if software_status == "installed" and matched_level in [RiskLevel.L1_SAFE, RiskLevel.L2_ORPHAN]:
                return RiskLevel.L3_IN_USE, True, "软件处于已安装在用状态，执行在用软件减负 (需明确确认)"
            is_def_selected = (matched_level in [RiskLevel.L1_SAFE, RiskLevel.L2_ORPHAN])
            return matched_level, True, RISK_LEVEL_LABELS[matched_level]
        except ValueError:
            pass

    # 4. L1 判定：极低风险项 (Bug 幽灵目录、历史散落单文件、死锁标记、骨架空目录)
    is_ghost_pattern = (
        base_name in ["(null)", "null", "undefined"]
        or base_name.startswith(".ACCC_Lock")
        or base_name.startswith(".ADCS_Lock")
        or base_name.startswith("2052-TM")
        or category in ["ghost", "skeleton", "locks", "temp_images"]
    )
    if is_ghost_pattern:
        return RiskLevel.L1_SAFE, True, "极低风险冗余 (代码Bug/散落锁/引导图，默认勾选)"

    # 5. L3 判定：在用软件减负 (端侧大模型、包含密钥凭证、或宿主软件仍在安装使用)
    if software_status == "installed":
        reason = "软件正在使用中，属于在用软件减负 (需用户确认)"
        if is_model_weight:
            reason = "端侧大模型/权重文件，属于在用软件减负 (需用户确认)"
        elif contains_secrets:
            reason = "包含敏感认证凭证 (Token/Key)，需显式授权确认"
        return RiskLevel.L3_IN_USE, True, reason

    if is_model_weight:
        return RiskLevel.L3_IN_USE, True, "本地模型权重文件 (需用户确认)"

    if contains_secrets:
        return RiskLevel.L3_IN_USE, True, "包含敏感认证凭据 (Token/Key，需显式授权确认)"

    # 6. L2 判定：明确已卸载的孤儿配置 (Orphaned Apps)
    if software_status == "orphaned":
        return RiskLevel.L2_ORPHAN, True, "明确已卸载软件的历史孤儿残留 (默认勾选隔离)"

    # 默认兜底
    return RiskLevel.L2_ORPHAN, True, "孤儿残留项 (默认勾选)"

