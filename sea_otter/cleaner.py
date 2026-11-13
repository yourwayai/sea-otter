"""
清理执行引擎模块 (Cleaner Engine)
负责安全地将指定目标移入 macOS 废纸篓 (Trash)，并支持 Dry-run 预览模式。
"""

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Tuple, Optional

from sea_otter.scanner import TargetMatch
from sea_otter.safety import validate_target_safety, RiskLevel

@dataclass
class CleanActionResult:
    target: TargetMatch
    success: bool
    size_freed: int
    is_dry_run: bool
    method_used: str
    message: str

class SafeCleaner:
    def __init__(self, use_trash: bool = True):
        self.use_trash = use_trash
        self._trash_bin = "/usr/bin/trash" if os.path.exists("/usr/bin/trash") else shutil.which("trash")

    def _move_to_trash(self, path: str) -> Tuple[bool, str]:
        """将文件或目录安全移入系统废纸篓 (Trash)"""
        if not os.path.exists(path):
            return True, "目标已不存在"

        # 优先方式: 使用系统的 trash CLI 工具
        if self._trash_bin:
            try:
                cmd = [self._trash_bin, path]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if proc.returncode == 0:
                    return True, "已移入系统废纸篓 (via trash)"
                # 如果 exit code 不为 0，尝试备用方案
            except Exception as e:
                pass

        # 备用方式 1: 使用 Linux gio trash (Freedesktop Trash 规范)
        gio_bin = shutil.which("gio")
        if gio_bin:
            try:
                cmd = [gio_bin, "trash", path]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if proc.returncode == 0:
                    return True, "已移入系统废纸篓 (via gio trash)"
            except Exception:
                pass

        # 备用方式 2: 使用 AppleScript 调用 Finder 将其移至废纸篓 (macOS)
        try:
            # 区分文件和文件夹
            item_type = "folder" if os.path.isdir(path) else "file"
            escaped_path = path.replace('"', '\\"')
            script = f'tell application "Finder" to delete POSIX {item_type} "{escaped_path}"'
            proc = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=10)
            if proc.returncode == 0:
                return True, "已移入系统废纸篓 (via Finder AppleScript)"
            return False, f"移入废纸篓失败: {proc.stderr.strip() or '权限不足或被锁定'}"
        except Exception as e:
            return False, f"执行移入废纸篓异常: {e}"

    def clean_target(self, target: TargetMatch, dry_run: bool = False, force_secret: bool = False) -> CleanActionResult:
        """执行单个目标的清理"""
        path = target.resolved_path

        # 0. L4 绝对系统红线硬编码绝对阻断
        if target.risk_level == RiskLevel.L4_DANGER.value or not target.is_safe:
            return CleanActionResult(
                target=target,
                success=False,
                size_freed=0,
                is_dry_run=dry_run,
                method_used="blocked",
                message=f"触发 L4 绝对系统红线硬编码阻断: {target.safety_reason}"
            )

        # 1. 安全合规再次拦截校验
        is_safe, reason = validate_target_safety(path)
        if not is_safe:
            return CleanActionResult(
                target=target,
                success=False,
                size_freed=0,
                is_dry_run=dry_run,
                method_used="blocked",
                message=f"触发安全防线拦截: {reason}"
            )

        if not os.path.exists(path):
            return CleanActionResult(
                target=target,
                success=True,
                size_freed=0,
                is_dry_run=dry_run,
                method_used="skipped",
                message="路径已不存在，无需清理"
            )

        # 2. 如果是敏感凭证且未显式允许
        if target.contains_secrets and not force_secret:
            return CleanActionResult(
                target=target,
                success=False,
                size_freed=0,
                is_dry_run=dry_run,
                method_used="skipped_secret",
                message="涉及敏感认证凭证 (Token/密钥)，未确认授权已跳过"
            )

        # 3. Dry-run 模式
        if dry_run:
            return CleanActionResult(
                target=target,
                success=True,
                size_freed=target.size_bytes,
                is_dry_run=True,
                method_used="dry_run",
                message="[Dry-run] 模拟移入废纸篓成功"
            )

        # 4. 真实执行：移入废纸篓
        ok, msg = self._move_to_trash(path)
        freed = target.size_bytes if ok else 0
        return CleanActionResult(
            target=target,
            success=ok,
            size_freed=freed,
            is_dry_run=False,
            method_used="trash" if ok else "failed",
            message=msg
        )

    def clean_targets(
        self,
        targets: List[TargetMatch],
        dry_run: bool = False,
        force_secret: bool = False
    ) -> List[CleanActionResult]:
        """批量清理目标项"""
        results = []
        for t in targets:
            results.append(self.clean_target(t, dry_run=dry_run, force_secret=force_secret))
        return results
