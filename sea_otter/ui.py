"""
终端视觉与 UI 格式化模块 (Terminal UI)
提供色彩高亮、表格对齐、容量格式化及交互渲染。
"""

import os
import sys

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
    """打印 Sea-Otter 终端吉祥物与标题横幅"""
    if full:
        line1 = c("      .-'\"\"'-.", Color.BRIGHT_YELLOW)
        line2 = c("     / #     # \\", Color.BRIGHT_YELLOW)
        line3 = c("    : #       # :", Color.BRIGHT_YELLOW) + "     " + c("🦦 Sea-Otter DevSweep Engine", Color.BOLD, Color.BRIGHT_CYAN) + " " + c("v1.0.0", Color.DIM)
        line4 = c("     \\  (o) (o) /", Color.BRIGHT_YELLOW) + "     " + c("像海獭梳理皮毛一样，时刻保持开发者环境的整洁与安全", Color.YELLOW)
        line5 = c("      :   (_)   :", Color.BRIGHT_YELLOW)
        line6 = c("       \\   -   /", Color.BRIGHT_YELLOW) + "      " + c("https://github.com/yourwayai/sea-otter", Color.DIM)
        line7 = c("      .-'     '-.", Color.BRIGHT_CYAN)
        line8 = c("     /   ", Color.BRIGHT_CYAN) + c("[ >_ ]", Color.BOLD, Color.GREEN) + c("  \\", Color.BRIGHT_CYAN)
        line9 = c("    :             :", Color.BRIGHT_CYAN)
        line10 = c("   ~\"\"~\"\"~\"\"~\"\"~\"\"~\"\"~", Color.CYAN)
        print(f"\n{line1}\n{line2}\n{line3}\n{line4}\n{line5}\n{line6}\n{line7}\n{line8}\n{line9}\n{line10}\n")
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
