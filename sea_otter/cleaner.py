"""
清理执行引擎与原子回滚模块 (Cleaner & Quarantine Rollback Engine)
负责安全地将指定目标归档至带元数据清单 (manifest.json) 的时间戳隔离区 (~/.Trash/AppSupport_Cleanup_<timestamp>/)，
支持 Dry-run 预览及一键无损回滚 (`sea-otter rollback`)。
"""

import os
import json
import shutil
import subprocess
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Dict, Any

from sea_otter.scanner import TargetMatch
from sea_otter.safety import validate_target_safety, normalize_path, RiskLevel

MANIFEST_VERSION = "1.2.0"
DEFAULT_QUARANTINE_BASE = "~/.Trash"
QUARANTINE_DIR_PREFIX = "AppSupport_Cleanup_"


@dataclass
class CleanActionResult:
    target: TargetMatch
    success: bool
    size_freed: int
    is_dry_run: bool
    method_used: str
    message: str
    quarantine_path: Optional[str] = None
    session_id: Optional[str] = None


@dataclass
class RollbackItemResult:
    name: str
    original_path: str
    quarantine_path: str
    size_bytes: int
    success: bool
    skipped: bool
    message: str


@dataclass
class RollbackReport:
    session_id: str
    quarantine_dir: str
    manifest_path: str
    created_at: str
    is_dry_run: bool
    results: List[RollbackItemResult] = field(default_factory=list)

    @property
    def restored_count(self) -> int:
        return sum(1 for r in self.results if r.success and not r.skipped)

    @property
    def restored_bytes(self) -> int:
        return sum(r.size_bytes for r in self.results if r.success and not r.skipped)

    @property
    def failed_count(self) -> int:
        return sum(1 for r in self.results if not r.success)


class QuarantineManager:
    """
    原子隔离区与一键无损回滚管理器
    管理 ~/.Trash/AppSupport_Cleanup_<timestamp>/ 目录及其 manifest.json 清单。
    """

    def __init__(self, quarantine_base_dir: Optional[str] = None):
        base = quarantine_base_dir or DEFAULT_QUARANTINE_BASE
        self.base_dir = normalize_path(base)

    def create_session_paths(self, now: Optional[datetime] = None) -> Tuple[str, str, str]:
        """
        生成不冲突的时间戳隔离区路径:
        返回 (session_id, session_dir, created_at_iso)
        """
        dt = now or datetime.now().astimezone()
        ts = dt.strftime("%Y%m%d_%H%M%S")
        session_id = f"cleanup_{ts}"
        session_dir = os.path.join(self.base_dir, f"{QUARANTINE_DIR_PREFIX}{ts}")

        suffix = 1
        while os.path.exists(session_dir):
            suffix += 1
            session_id = f"cleanup_{ts}_{suffix}"
            session_dir = os.path.join(self.base_dir, f"{QUARANTINE_DIR_PREFIX}{ts}_{suffix}")

        os.makedirs(session_dir, exist_ok=True)
        return session_id, session_dir, dt.isoformat(timespec="seconds")

    @staticmethod
    def write_manifest(session_dir: str, manifest: Dict[str, Any]) -> str:
        """原子写入 manifest.json"""
        manifest_path = os.path.join(session_dir, "manifest.json")
        tmp_path = os.path.join(session_dir, ".manifest.json.tmp")
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False)
        os.replace(tmp_path, manifest_path)
        return manifest_path

    def list_sessions(self) -> List[Dict[str, Any]]:
        """列出隔离区根目录中所有合法的隔离会话 (按时间倒序)"""
        if not os.path.isdir(self.base_dir):
            return []

        sessions: List[Dict[str, Any]] = []
        try:
            with os.scandir(self.base_dir) as it:
                for entry in it:
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    if not entry.name.startswith(QUARANTINE_DIR_PREFIX):
                        continue
                    manifest_path = os.path.join(entry.path, "manifest.json")
                    if not os.path.isfile(manifest_path):
                        continue
                    try:
                        with open(manifest_path, "r", encoding="utf-8") as f:
                            data = json.load(f)
                        if isinstance(data, dict) and "items" in data:
                            data.setdefault("session_id", f"cleanup_{entry.name[len(QUARANTINE_DIR_PREFIX):]}")
                            data["quarantine_dir"] = entry.path
                            data["manifest_path"] = manifest_path
                            sessions.append(data)
                    except (OSError, json.JSONDecodeError):
                        continue
        except OSError:
            return []

        sessions.sort(key=lambda s: s.get("created_at", ""), reverse=True)
        return sessions

    def find_session(self, session_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        查找指定的隔离会话:
        - session_id 为 None 或 "latest" 时，优先返回最新未完全回滚的会话，否则返回最新会话；
        - 支持匹配 session_id、目录名或时间戳后缀。
        """
        sessions = self.list_sessions()
        if not sessions:
            return None

        if not session_id or session_id.lower() == "latest":
            for s in sessions:
                if s.get("status", "active") != "rolled_back":
                    return s
            return sessions[0]

        query = session_id.strip()
        for s in sessions:
            sid = s.get("session_id", "")
            dir_name = os.path.basename(s.get("quarantine_dir", ""))
            short_ts = sid[len("cleanup_"):] if sid.startswith("cleanup_") else sid
            if query in (sid, dir_name, short_ts):
                return s
        return None

    def rollback_session(
        self,
        session_id: Optional[str] = None,
        dry_run: bool = False,
        overwrite: bool = False,
    ) -> RollbackReport:
        """
        解析指定隔离会话的 manifest.json，并将隔离的文件/目录无损恢复至原路径。
        """
        session = self.find_session(session_id)
        if session is None:
            raise FileNotFoundError(
                f"未找到匹配的隔离会话: {session_id or 'latest'} (目录: {self.base_dir})"
            )

        sid = session.get("session_id", "unknown")
        session_dir = session["quarantine_dir"]
        manifest_path = session["manifest_path"]
        created_at = session.get("created_at", "")
        items = session.get("items", [])

        results: List[RollbackItemResult] = []
        any_restored = False

        for item in items:
            name = item.get("name", "unknown")
            orig_path = item.get("original_path", "")
            rel_path = item.get("target_relative_path", "")
            size_bytes = int(item.get("size_bytes", 0))

            if item.get("rolled_back"):
                results.append(RollbackItemResult(
                    name=name,
                    original_path=orig_path,
                    quarantine_path=os.path.join(session_dir, rel_path),
                    size_bytes=size_bytes,
                    success=True,
                    skipped=True,
                    message="该项此前已回滚，跳过",
                ))
                continue

            if not orig_path or not rel_path:
                results.append(RollbackItemResult(
                    name=name,
                    original_path=orig_path,
                    quarantine_path="",
                    size_bytes=size_bytes,
                    success=False,
                    skipped=False,
                    message="manifest 清单项缺失路径元数据",
                ))
                continue

            src_path = os.path.abspath(os.path.join(session_dir, rel_path))
            # 防止路径穿越攻击
            try:
                if os.path.commonpath([os.path.abspath(session_dir), src_path]) != os.path.abspath(session_dir):
                    results.append(RollbackItemResult(
                        name=name,
                        original_path=orig_path,
                        quarantine_path=src_path,
                        size_bytes=size_bytes,
                        success=False,
                        skipped=False,
                        message="拒绝非法越界相对路径",
                    ))
                    continue
            except ValueError:
                results.append(RollbackItemResult(
                    name=name,
                    original_path=orig_path,
                    quarantine_path=src_path,
                    size_bytes=size_bytes,
                    success=False,
                    skipped=False,
                    message="路径校验失败",
                ))
                continue

            if not os.path.lexists(src_path):
                results.append(RollbackItemResult(
                    name=name,
                    original_path=orig_path,
                    quarantine_path=src_path,
                    size_bytes=size_bytes,
                    success=False,
                    skipped=False,
                    message="隔离区中已找不到归档文件（可能已被手动清空废纸篓）",
                ))
                continue

            dest_path = os.path.abspath(orig_path)
            if os.path.lexists(dest_path):
                if not overwrite:
                    results.append(RollbackItemResult(
                        name=name,
                        original_path=dest_path,
                        quarantine_path=src_path,
                        size_bytes=size_bytes,
                        success=False,
                        skipped=False,
                        message="原路径已存在同名文件/目录，跳过覆盖 (可加 --force 强制覆盖)",
                    ))
                    continue

            if dry_run:
                results.append(RollbackItemResult(
                    name=name,
                    original_path=dest_path,
                    quarantine_path=src_path,
                    size_bytes=size_bytes,
                    success=True,
                    skipped=False,
                    message=f"[Dry-run] 模拟恢复至 {dest_path}",
                ))
                continue

            try:
                parent_dir = os.path.dirname(dest_path)
                if parent_dir:
                    os.makedirs(parent_dir, exist_ok=True)
                if os.path.lexists(dest_path) and overwrite:
                    if os.path.isdir(dest_path) and not os.path.islink(dest_path):
                        shutil.rmtree(dest_path)
                    else:
                        os.unlink(dest_path)

                shutil.move(src_path, dest_path)
                item["rolled_back"] = True
                item["rolled_back_at"] = datetime.now().astimezone().isoformat(timespec="seconds")
                any_restored = True
                results.append(RollbackItemResult(
                    name=name,
                    original_path=dest_path,
                    quarantine_path=src_path,
                    size_bytes=size_bytes,
                    success=True,
                    skipped=False,
                    message=f"已无损恢复至 {dest_path}",
                ))
            except Exception as e:
                results.append(RollbackItemResult(
                    name=name,
                    original_path=dest_path,
                    quarantine_path=src_path,
                    size_bytes=size_bytes,
                    success=False,
                    skipped=False,
                    message=f"恢复失败: {e}",
                ))

        if not dry_run and any_restored:
            all_done = all(it.get("rolled_back") for it in items)
            session["status"] = "rolled_back" if all_done else "partial"
            session["last_rollback_at"] = datetime.now().astimezone().isoformat(timespec="seconds")
            self.write_manifest(session_dir, session)

        return RollbackReport(
            session_id=sid,
            quarantine_dir=session_dir,
            manifest_path=manifest_path,
            created_at=created_at,
            is_dry_run=dry_run,
            results=results,
        )


class SafeCleaner:
    def __init__(
        self,
        use_trash: bool = True,
        use_quarantine: bool = True,
        quarantine_base_dir: Optional[str] = None,
    ):
        self.use_trash = use_trash
        self.use_quarantine = use_quarantine
        self.quarantine_manager = QuarantineManager(quarantine_base_dir=quarantine_base_dir)
        self._trash_bin = "/usr/bin/trash" if os.path.exists("/usr/bin/trash") else shutil.which("trash")
        self.last_session_id: Optional[str] = None
        self.last_quarantine_dir: Optional[str] = None
        self.last_manifest_path: Optional[str] = None

    def _move_to_trash(self, path: str) -> Tuple[bool, str]:
        """将文件或目录安全移入系统废纸篓 (Trash)（无隔离区时的兜底方案）"""
        if not os.path.exists(path) and not os.path.islink(path):
            return True, "目标已不存在"

        # 优先方式: 使用系统的 trash CLI 工具
        if self._trash_bin:
            try:
                cmd = [self._trash_bin, path]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if proc.returncode == 0:
                    return True, "已移入系统废纸篓 (via trash)"
            except Exception:
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
            item_type = "folder" if os.path.isdir(path) else "file"
            escaped_path = path.replace('"', '\\"')
            script = f'tell application "Finder" to delete POSIX {item_type} "{escaped_path}"'
            proc = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=10)
            if proc.returncode == 0:
                return True, "已移入系统废纸篓 (via Finder AppleScript)"
            return False, f"移入废纸篓失败: {proc.stderr.strip() or '权限不足或被锁定'}"
        except Exception as e:
            return False, f"执行移入废纸篓异常: {e}"

    @staticmethod
    def _allocate_relative_target(session_dir: str, original_path: str) -> str:
        """为隔离目标分配不冲突的相对名称（保留原文件名/目录名，重名时追加序号）"""
        base_name = os.path.basename(original_path) or "item"
        candidate = base_name
        counter = 2
        while os.path.lexists(os.path.join(session_dir, candidate)) or candidate == "manifest.json":
            candidate = f"{base_name}__{counter}"
            counter += 1
        return candidate

    def _validate_before_clean(
        self,
        target: TargetMatch,
        dry_run: bool,
        force_secret: bool,
    ) -> Optional[CleanActionResult]:
        """执行清理前安全阻断与存在性预检，若需跳过或阻断则返回 CleanActionResult"""
        path = target.resolved_path

        # 0. L4 绝对系统红线硬编码绝对阻断
        if target.risk_level == RiskLevel.L4_DANGER.value or not target.is_safe:
            return CleanActionResult(
                target=target,
                success=False,
                size_freed=0,
                is_dry_run=dry_run,
                method_used="blocked",
                message=f"触发 L4 绝对系统红线硬编码阻断: {target.safety_reason}",
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
                message=f"触发安全防线拦截: {reason}",
            )

        if not os.path.exists(path) and not os.path.islink(path):
            return CleanActionResult(
                target=target,
                success=True,
                size_freed=0,
                is_dry_run=dry_run,
                method_used="skipped",
                message="路径已不存在，无需清理",
            )

        # 2. 如果是敏感凭证且未显式允许
        if target.contains_secrets and not force_secret:
            return CleanActionResult(
                target=target,
                success=False,
                size_freed=0,
                is_dry_run=dry_run,
                method_used="skipped_secret",
                message="涉及敏感认证凭证 (Token/密钥)，未确认授权已跳过",
            )

        return None

    def _move_into_quarantine(
        self,
        target: TargetMatch,
        session_dir: str,
        session_id: str,
    ) -> Tuple[bool, str, Optional[str], Optional[Dict[str, Any]]]:
        """将单个目标移入时间戳隔离区并构造 manifest 条目"""
        path = target.resolved_path
        rel_target = self._allocate_relative_target(session_dir, path)
        dest_path = os.path.join(session_dir, rel_target)
        try:
            shutil.move(path, dest_path)
            item_entry = {
                "name": os.path.basename(path) or rel_target,
                "app_id": target.tool_id or "unknown",
                "app_name": target.tool_name or "Unknown",
                "category": target.category,
                "original_path": path,
                "target_relative_path": rel_target,
                "size_bytes": target.size_bytes,
                "risk_level": target.risk_level,
                "reason": target.description or target.safety_reason,
                "cleaned_at": datetime.now().astimezone().isoformat(timespec="seconds"),
                "rolled_back": False,
            }
            return True, f"已原子归档至隔离区 ({session_id}/{rel_target})", dest_path, item_entry
        except Exception as e:
            return False, f"移入隔离区失败: {e}", None, None

    def clean_target(self, target: TargetMatch, dry_run: bool = False, force_secret: bool = False) -> CleanActionResult:
        """执行单个目标的清理（默认创建单目标原子隔离会话并写入 manifest.json）"""
        results = self.clean_targets([target], dry_run=dry_run, force_secret=force_secret)
        return results[0]

    def clean_targets(
        self,
        targets: List[TargetMatch],
        dry_run: bool = False,
        force_secret: bool = False,
    ) -> List[CleanActionResult]:
        """批量清理目标项：在 ~/.Trash/AppSupport_Cleanup_<timestamp>/ 建立原子隔离区与 manifest.json"""
        self.last_session_id = None
        self.last_quarantine_dir = None
        self.last_manifest_path = None

        results: List[CleanActionResult] = []
        session_id: Optional[str] = None
        session_dir: Optional[str] = None
        created_at: Optional[str] = None
        quarantine_unavailable = False
        manifest_items: List[Dict[str, Any]] = []

        for target in targets:
            blocked_or_skipped = self._validate_before_clean(target, dry_run=dry_run, force_secret=force_secret)
            if blocked_or_skipped is not None:
                results.append(blocked_or_skipped)
                continue

            if dry_run:
                results.append(CleanActionResult(
                    target=target,
                    success=True,
                    size_freed=target.size_bytes,
                    is_dry_run=True,
                    method_used="dry_run",
                    message="[Dry-run] 模拟归档至原子隔离区成功",
                ))
                continue

            # 尝试使用时间戳原子隔离区归档
            if self.use_quarantine and not quarantine_unavailable:
                if session_dir is None:
                    try:
                        session_id, session_dir, created_at = self.quarantine_manager.create_session_paths()
                    except OSError:
                        quarantine_unavailable = True

                if session_dir is not None and session_id is not None:
                    ok, msg, q_path, item_entry = self._move_into_quarantine(target, session_dir, session_id)
                    if ok and item_entry is not None:
                        manifest_items.append(item_entry)
                        results.append(CleanActionResult(
                            target=target,
                            success=True,
                            size_freed=target.size_bytes,
                            is_dry_run=False,
                            method_used="quarantine",
                            message=msg,
                            quarantine_path=q_path,
                            session_id=session_id,
                        ))
                        continue
                    # 移动失败时记录错误
                    results.append(CleanActionResult(
                        target=target,
                        success=False,
                        size_freed=0,
                        is_dry_run=False,
                        method_used="failed",
                        message=msg,
                    ))
                    continue

            # 兜底：使用系统 trash CLI / AppleScript 移入废纸篓
            ok, msg = self._move_to_trash(target.resolved_path)
            freed = target.size_bytes if ok else 0
            results.append(CleanActionResult(
                target=target,
                success=ok,
                size_freed=freed,
                is_dry_run=False,
                method_used="trash" if ok else "failed",
                message=msg,
            ))

        # 仅当隔离区确实归档了条目时写入 manifest.json，否则清理空会话目录
        if session_dir is not None and session_id is not None:
            if manifest_items:
                manifest = {
                    "version": MANIFEST_VERSION,
                    "session_id": session_id,
                    "created_at": created_at,
                    "quarantine_dir": session_dir,
                    "total_reclaimed_bytes": sum(it["size_bytes"] for it in manifest_items),
                    "status": "active",
                    "items": manifest_items,
                }
                manifest_path = self.quarantine_manager.write_manifest(session_dir, manifest)
                self.last_session_id = session_id
                self.last_quarantine_dir = session_dir
                self.last_manifest_path = manifest_path
            else:
                try:
                    os.rmdir(session_dir)
                except OSError:
                    pass

        return results
