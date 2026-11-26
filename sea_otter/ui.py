"""
终端视觉与 UI 格式化模块 (Terminal UI)
提供色彩高亮、表格对齐、容量格式化及交互渲染。
"""

import os
import sys
from typing import Optional

# 终端 ANSI 色彩代码
class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"
    
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"

# 检测是否支持终端色彩
USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

def c(text: str, *styles: str) -> str:
    """包装色彩与样式"""
    if not USE_COLOR or not styles:
        return text
    prefix = "".join(styles)
    return f"{prefix}{text}{Color.RESET}"

def format_size(size_bytes: int) -> str:
    """人性化格式化文件大小"""
    if size_bytes <= 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    val = float(size_bytes)
    for unit in units:
        if val < 1024.0 or unit == units[-1]:
            if unit in ["B"]:
                return f"{int(val)} {unit}"
            return f"{val:.1f} {unit}"
        val /= 1024.0
    return f"{val:.1f} PB"

def print_banner(full: bool = False):
    """打印 Sea-Otter 极简科技感文本大字横幅 (Gemini CLI / Developer CLI 风格)"""
    C1 = Color.BRIGHT_CYAN
    C2 = Color.CYAN
    C3 = Color.BLUE
    DIM = Color.DIM
    BOLD = Color.BOLD
    W = Color.BRIGHT_WHITE
    Y = Color.YELLOW

    if full:
        lines = [
            c("   _____                  ____  __  __           ", C1, BOLD),
            c("  / ___/___  ____ _      / __ \\/ /_/ /____  _____", C1, BOLD),
            c("  \\__ \\/ _ \\/ __ `/_____/ / / / __/ __/ _ \\/ ___/", C2, BOLD),
            c(" ___/ /  __/ /_/ /_____/ /_/ / /_/ /_/  __/ /    ", C2),
            c("/____/\\___/\\__,_/      \\____/\\__/\\__/\\___/_/     ", C3),
        ]
        divider = c("  " + "─" * 50, DIM)
        print("\n" + "\n".join(lines))
        print(divider)
        print(f"  {c('🦦 DevSweep Engine', BOLD, W)} {c('· AI & Developer Tools Cleanup', Y)} {c('v1.0.0', DIM)}")
        print(f"  {c('Safe Recycle · Process Guard · Workspace Immunity · Secrets Audit', DIM)}")
        print(divider + "\n")
    else:
        banner = f"""
{c("  🦦 Sea-Otter DevSweep Engine", Color.BOLD, Color.BRIGHT_CYAN)} {c("v1.0.0", Color.DIM)}
{c("  面向新一代 AI 编程工具与 Agent CLI 的精细化清理与体检工具", Color.DIM)}
"""
        print(banner)

CATEGORY_NAMES = {
    "caches": "纯缓存 (Cache)",
    "preferences": "偏好设置 (Preferences)",
    "credentials": "认证凭据 (Credentials)",
    "ai_models": "本地 AI 模型 (Models)",
    "data_and_history": "数据与会话 (Data/History)",
    "configs": "配置文件 (Configs)",
    "binaries_and_scripts": "CLI 二进制 (Binaries)",
    "ghost": "幽灵目录 (Ghost Bug)",
    "skeleton": "骨架空目录 (Skeleton Dir)",
    "locks": "过期死锁 (Dead Lock)",
    "temp_images": "散落引导图 (Scattered File)",
}

def get_status_badge(status: str) -> str:
    """获取状态标签"""
    if status == "running":
        return c("🔵 正在运行 (Running - 保护锁定)", Color.BOLD, Color.BRIGHT_BLUE)
    elif status == "installed":
        return c("🟢 已安装 (Installed)", Color.BOLD, Color.BRIGHT_GREEN)
    elif status == "orphaned":
        return c("🟠 孤儿残留 (Orphaned)", Color.BOLD, Color.BRIGHT_YELLOW)
    elif status == "clean":
        return c("⚪️ 环境整洁 (Clean)", Color.DIM)
    return c(status, Color.WHITE)

def get_risk_badge(risk_level: str) -> str:
    """获取四级安全风险徽标 (Four-Tier Safety Risk Matrix Badge)"""
    if risk_level == "L1_SAFE":
        return c("[L1 极低风险]", Color.BOLD, Color.BRIGHT_GREEN)
    elif risk_level == "L2_ORPHAN":
        return c("[L2 明确已卸载]", Color.BOLD, Color.YELLOW)
    elif risk_level == "L3_IN_USE":
        return c("[L3 在用减负·需确认]", Color.BOLD, Color.BRIGHT_YELLOW)
    elif risk_level == "L4_DANGER":
        return c("[L4 绝对红线·硬阻断]", Color.BOLD, Color.BRIGHT_RED)
    return c(f"[{risk_level}]", Color.DIM)

def get_model_badge(is_model: bool, size_bytes: int = 0, model_name: Optional[str] = None) -> str:
    """获取端侧大模型高亮徽标 (含容量高亮提示)"""
    if not is_model:
        return ""
    size_str = f" ({format_size(size_bytes)})" if size_bytes > 0 else ""
    return c(f" 🧠[本地模型权重{size_str}]", Color.BOLD, Color.BRIGHT_CYAN)

def get_prunable_badge(is_prunable: bool, path: str = "", description: str = "") -> str:
    """获取减负裁剪标识徽标 (会话大附件/运行时减负)"""
    if not is_prunable:
        return ""
    lower_path = path.lower()
    lower_desc = description.lower()
    if "files" in lower_path or "attachment" in lower_desc or "附件" in lower_desc:
        return c(" 📎[会话大附件]", Color.BOLD, Color.BRIGHT_MAGENTA)
    if "toolchain" in lower_path:
        return c(" 🛠️[运行时组件]", Color.BOLD, Color.CYAN)
    return c(" ✂️[可减负]", Color.BOLD, Color.CYAN)

def get_ghost_badge(ghost_type: Optional[str] = None, category: str = "") -> str:
    """获取根目录散落与幽灵异常高亮徽标"""
    if not ghost_type and category not in ["ghost", "skeleton", "locks", "temp_images"]:
        return ""
    if ghost_type == "bug_name":
        return c(" 👻[空指针幽灵]", Color.BOLD, Color.BRIGHT_GREEN)
    if ghost_type == "dead_lock" or category == "locks":
        return c(" 🔒[过期死锁标记]", Color.BOLD, Color.BRIGHT_GREEN)
    if ghost_type == "scattered_file" or category == "temp_images":
        return c(" 📄[根目录散落单文件]", Color.BOLD, Color.BRIGHT_GREEN)
    if ghost_type == "skeleton_dir" or category == "skeleton":
        return c(" 🦴[骨架空目录]", Color.BOLD, Color.BRIGHT_GREEN)
    return c(" 👻[幽灵残留]", Color.BOLD, Color.BRIGHT_GREEN)

def get_channel_badge(channel_name: Optional[str] = None, inactive_days: Optional[int] = None) -> str:
    """获取多通道发布孤岛徽标 (Canary/Dev/Beta 停用测试通道)"""
    if not channel_name:
        return ""
    days_part = f" {inactive_days}天未用" if inactive_days is not None else ""
    return c(f" 🏝️[停用测试通道·{channel_name.upper()}{days_part}]", Color.BOLD, Color.BRIGHT_YELLOW)


def get_association_badge(
    association_tier: Optional[int] = None,
    associated_app: Optional[str] = None,
    inactive_days: Optional[int] = None,
) -> str:
    """获取三级反向映射孤儿推导徽标 (Plist / 特征字典 / 启发式)"""
    if not association_tier:
        return ""
    app_label = associated_app or "未知应用"
    if association_tier == 1:
        return c(f" 🔗[L1 Plist反查·{app_label}]", Color.BOLD, Color.BRIGHT_CYAN)
    if association_tier == 2:
        return c(f" 🔗[L2 特征库·{app_label}]", Color.BOLD, Color.BRIGHT_YELLOW)
    days_part = f"·{inactive_days}天未访问" if inactive_days is not None else ""
    return c(f" 🕰️[L3 启发式孤儿{days_part}]", Color.BOLD, Color.YELLOW)



