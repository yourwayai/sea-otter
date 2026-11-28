"""
Sea-Otter Agentic MCP Server (Model Context Protocol over stdio)
零外部依赖实现标准 JSON-RPC 2.0 MCP 服务端，向 Antigravity / Claude Code / Cursor 等 AI Agent
暴露 sea_otter_scan、sea_otter_clean、sea_otter_rollback 原生工具能力。
"""

import sys
import json
import contextlib
from typing import Any, Callable, Dict, List, Optional, TextIO, Tuple

from sea_otter.scanner import (
    RuleScanner,
    RootOrphanScanner,
    ChannelRedundancyScanner,
    AssociationEngine,
    ToolScanReport,
    TargetMatch,
)
from sea_otter.cleaner import SafeCleaner, QuarantineManager
from sea_otter.safety import RiskLevel
from sea_otter.ui import format_size

SERVER_NAME = "sea-otter-mcp"
SERVER_VERSION = "1.0.0"
SUPPORTED_PROTOCOL_VERSIONS = ("2025-03-26", "2024-11-05")
DEFAULT_PROTOCOL_VERSION = "2024-11-05"

VALID_SCAN_MODES = ("all", "models", "slim", "ghosts", "channels", "associations", "secrets")
VALID_CLEAN_MODES = ("default", "models", "slim", "ghosts", "channels", "associations")


def _serialize_target(t: TargetMatch) -> Dict[str, Any]:
    return {
        "tool_id": t.tool_id,
        "tool_name": t.tool_name,
        "category": t.category,
        "path": t.resolved_path,
        "description": t.description,
        "size_bytes": t.size_bytes,
        "size_human": format_size(t.size_bytes),
        "file_count": t.file_count,
        "risk_level": t.risk_level,
        "default_selected": t.default_selected,
        "is_safe": t.is_safe,
        "safety_reason": t.safety_reason,
        "contains_secrets": t.contains_secrets,
        "secret_severity": t.secret_severity,
        "secret_findings": list(t.secret_findings),
        "is_model_weight": t.is_model_weight,
        "model_name": t.model_name,
        "model_format": t.model_format,
        "prunable": t.prunable,
        "sub_target_of": t.sub_target_of,
        "ghost_type": t.ghost_type,
        "channel_name": t.channel_name,
        "inactive_days": t.inactive_days,
        "association_tier": t.association_tier,
        "association_method": t.association_method,
        "associated_app": t.associated_app,
        "associated_bundle_id": t.associated_bundle_id,
    }


def _recompute_report_totals(report: ToolScanReport) -> None:
    report.total_size_bytes = sum(t.size_bytes for t in report.targets)
    report.safe_size_bytes = sum(t.size_bytes for t in report.targets if t.is_safe)
    report.model_weight_size_bytes = sum(t.size_bytes for t in report.targets if t.is_model_weight)


def _is_slim_target(t: TargetMatch) -> bool:
    if t.category in ("credentials", "configs") or t.contains_secrets:
        return False
    lower_path = t.resolved_path.lower()
    if any(lower_path.endswith(ext) for ext in (".sqlite", ".sqlite3", ".db", ".plist")):
        return False
    return bool(
        t.prunable
        or t.is_model_weight
        or t.category in ("caches", "ai_models")
        or "files" in lower_path
        or "knowledgebase" in lower_path
        or "indexeddb" in lower_path
        or "toolchain" in lower_path
    )


def _run_reports_for_mode(
    scanner: RuleScanner,
    tools: Optional[List[str]],
    mode: str,
) -> List[ToolScanReport]:
    tools_filter = [t for t in tools if t] if tools else None
    if mode == "ghosts" and not tools_filter:
        ghost_rules = [r for r in scanner.load_rules() if "ghost_rules" in r]
        reports = [scanner.scan_tool(r) for r in ghost_rules]
        reports.append(RootOrphanScanner().scan())
    elif mode == "channels" and not tools_filter:
        all_rules = scanner.load_rules()
        reports = [ChannelRedundancyScanner(rules=all_rules, use_builtin_defaults=True).scan()]
    elif mode == "associations" and not tools_filter:
        all_rules = scanner.load_rules()
        reports = [AssociationEngine(rules=all_rules).scan()]
    else:
        reports = scanner.scan_all(filter_ids=tools_filter)

    if mode == "models":
        for r in reports:
            r.targets = [t for t in r.targets if t.is_model_weight or t.category == "ai_models"]
            _recompute_report_totals(r)
    elif mode == "slim":
        for r in reports:
            r.targets = [t for t in r.targets if _is_slim_target(t)]
            _recompute_report_totals(r)
    elif mode == "ghosts":
        for r in reports:
            r.targets = [
                t for t in r.targets
                if t.ghost_type is not None or t.category in ("ghost", "skeleton", "locks", "temp_images")
            ]
            _recompute_report_totals(r)
    elif mode == "channels":
        for r in reports:
            r.targets = [t for t in r.targets if t.channel_name is not None]
            _recompute_report_totals(r)
    elif mode == "associations":
        for r in reports:
            r.targets = [t for t in r.targets if t.association_tier is not None]
            _recompute_report_totals(r)
    elif mode == "secrets":
        for r in reports:
            r.targets = [t for t in r.targets if t.contains_secrets]
            _recompute_report_totals(r)

    return reports


class SeaOtterMCPService:
    """封装 Sea-Otter 核心 MCP 工具逻辑，支持依赖注入以便测试。"""

    def __init__(
        self,
        scanner_factory: Optional[Callable[[], RuleScanner]] = None,
        cleaner_factory: Optional[Callable[[], SafeCleaner]] = None,
        quarantine_factory: Optional[Callable[[], QuarantineManager]] = None,
    ):
        self.scanner_factory = scanner_factory or RuleScanner
        self.cleaner_factory = cleaner_factory or (lambda: SafeCleaner(use_trash=True, use_quarantine=True))
        self.quarantine_factory = quarantine_factory or QuarantineManager

    @staticmethod
    def get_tool_definitions() -> List[Dict[str, Any]]:
        return [
            {
                "name": "sea_otter_scan",
                "description": (
                    "Inspect macOS/Linux AI coding tools, Agent CLIs, on-device LLM weights, "
                    "decoupled orphan directories, stale preview channels, and plaintext secret leaks. "
                    "Read-only operation returning disk usage breakdown and L1-L4 risk classification."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "tools": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional list of tool IDs to scan (e.g. ['cursor', 'cherry-studio']). Omit to scan all.",
                        },
                        "mode": {
                            "type": "string",
                            "enum": list(VALID_SCAN_MODES),
                            "default": "all",
                            "description": (
                                "Scan mode: 'all' (full), 'models' (on-device LLM weights), 'slim' (prunable attachments/vectors/caches), "
                                "'ghosts' (L1 root bugs/skeletons/locks), 'channels' (stale Canary/Dev/Beta), "
                                "'associations' (3-tier orphan reverse mapping), or 'secrets' (plaintext token/key privacy audit)."
                            ),
                        },
                        "include_clean": {
                            "type": "boolean",
                            "default": False,
                            "description": "Include tools that have zero residuals on disk.",
                        },
                    },
                    "additionalProperties": False,
                },
            },
            {
                "name": "sea_otter_clean",
                "description": (
                    "Safely archive/slim redundant AI tool caches, models, attachments, or orphan directories into "
                    "~/.Trash/AppSupport_Cleanup_<timestamp>/ with manifest.json for lossless rollback. "
                    "ALWAYS defaults to dry_run=true; actual cleanup requires BOTH dry_run=false and confirm=true "
                    "after presenting disk savings and any secret warnings to the user."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "tools": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional list of tool IDs to target.",
                        },
                        "mode": {
                            "type": "string",
                            "enum": list(VALID_CLEAN_MODES),
                            "default": "default",
                            "description": "Cleanup mode: 'default', 'models', 'slim', 'ghosts', 'channels', or 'associations'.",
                        },
                        "category": {
                            "type": "string",
                            "description": "Optional comma-separated target categories (e.g. 'caches,data_and_history').",
                        },
                        "dry_run": {
                            "type": "boolean",
                            "default": True,
                            "description": "Read-only preview mode (default true). Set to false only after user confirmation.",
                        },
                        "confirm": {
                            "type": "boolean",
                            "default": False,
                            "description": "Explicit user confirmation flag required when dry_run=false.",
                        },
                        "include_l3": {
                            "type": "boolean",
                            "default": False,
                            "description": "Allow cleaning L3 in-use bloatware/caches (auto-enabled for models/slim/channels).",
                        },
                        "include_secrets": {
                            "type": "boolean",
                            "default": False,
                            "description": "Allow archiving targets flagged with plaintext credentials/keys (always blocked unless true).",
                        },
                    },
                    "additionalProperties": False,
                },
            },
            {
                "name": "sea_otter_rollback",
                "description": (
                    "List atomic quarantine cleanup sessions or losslessly restore archived files/directories "
                    "from ~/.Trash/AppSupport_Cleanup_<timestamp>/ back to their original paths."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": ["list", "restore"],
                            "default": "list",
                            "description": "'list' returns available quarantine sessions; 'restore' recovers a session.",
                        },
                        "session_id": {
                            "type": "string",
                            "description": "Quarantine session ID (e.g. 'cleanup_20261128_120000'). Omit or 'latest' for the newest session.",
                        },
                        "dry_run": {
                            "type": "boolean",
                            "default": True,
                            "description": "Preview restoration paths without modifying the filesystem (default true for restore).",
                        },
                        "overwrite": {
                            "type": "boolean",
                            "default": False,
                            "description": "Overwrite if a new file/directory now exists at the original path.",
                        },
                    },
                    "additionalProperties": False,
                },
            },
        ]

    def handle_scan(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        tools = arguments.get("tools")
        mode = str(arguments.get("mode") or "all")
        include_clean = bool(arguments.get("include_clean", False))

        if mode not in VALID_SCAN_MODES:
            raise ValueError(f"Unsupported scan mode: {mode}. Expected one of {VALID_SCAN_MODES}")

        scanner = self.scanner_factory()
        reports = _run_reports_for_mode(scanner, tools=tools, mode=mode)
        visible = [r for r in reports if r.has_residuals or include_clean]

        total_bytes = sum(r.total_size_bytes for r in reports)
        safe_bytes = sum(r.safe_size_bytes for r in reports)
        model_bytes = sum(r.model_weight_size_bytes for r in reports)
        l1_bytes = sum(sum(t.size_bytes for t in r.l1_targets) for r in reports)
        l2_bytes = sum(sum(t.size_bytes for t in r.l2_targets) for r in reports)
        l3_bytes = sum(sum(t.size_bytes for t in r.l3_targets) for r in reports)
        l4_count = sum(len(r.l4_targets) for r in reports)
        secret_count = sum(r.secret_count for r in reports)

        return {
            "mode": mode,
            "summary": {
                "scanned_tools_count": len(reports),
                "visible_tools_count": len(visible),
                "total_size_bytes": total_bytes,
                "total_size_human": format_size(total_bytes),
                "safe_reclaimable_bytes": safe_bytes,
                "safe_reclaimable_human": format_size(safe_bytes),
                "model_weight_bytes": model_bytes,
                "model_weight_human": format_size(model_bytes),
                "secret_targets_count": secret_count,
                "risk_breakdown": {
                    "L1_SAFE_bytes": l1_bytes,
                    "L1_SAFE_human": format_size(l1_bytes),
                    "L2_ORPHAN_bytes": l2_bytes,
                    "L2_ORPHAN_human": format_size(l2_bytes),
                    "L3_IN_USE_bytes": l3_bytes,
                    "L3_IN_USE_human": format_size(l3_bytes),
                    "L4_DANGER_protected_count": l4_count,
                },
            },
            "tools": [
                {
                    "id": r.tool_id,
                    "name": r.name,
                    "category": r.category,
                    "vendor": r.vendor,
                    "status": r.status,
                    "total_size_bytes": r.total_size_bytes,
                    "total_size_human": format_size(r.total_size_bytes),
                    "safe_size_bytes": r.safe_size_bytes,
                    "model_weight_size_bytes": r.model_weight_size_bytes,
                    "secret_count": r.secret_count,
                    "running_processes": r.running_processes,
                    "targets": [_serialize_target(t) for t in r.targets],
                }
                for r in visible
            ],
        }

    def handle_clean(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        tools = arguments.get("tools")
        mode = str(arguments.get("mode") or "default")
        category = arguments.get("category")
        dry_run = bool(arguments.get("dry_run", True))
        confirm = bool(arguments.get("confirm", False))
        include_l3 = bool(arguments.get("include_l3", False))
        include_secrets = bool(arguments.get("include_secrets", False))

        if mode not in VALID_CLEAN_MODES:
            raise ValueError(f"Unsupported clean mode: {mode}. Expected one of {VALID_CLEAN_MODES}")

        if mode in ("models", "slim", "channels"):
            include_l3 = True

        categories_filter = None
        if category:
            categories_filter = [c.strip() for c in str(category).split(",") if c.strip()]

        scanner = self.scanner_factory()
        scan_mode = "all" if mode == "default" else mode
        reports = _run_reports_for_mode(scanner, tools=tools, mode=scan_mode)

        candidates: List[TargetMatch] = []
        skipped_unsafe = 0
        skipped_l3_count = 0
        skipped_l3_bytes = 0
        skipped_secrets_count = 0

        for r in reports:
            for t in r.targets:
                if not t.tool_id:
                    t.tool_id = r.tool_id
                if not t.tool_name:
                    t.tool_name = r.name

                if categories_filter and t.category not in categories_filter:
                    continue
                if mode == "slim" and not _is_slim_target(t):
                    continue
                if t.risk_level == RiskLevel.L4_DANGER.value or not t.is_safe:
                    skipped_unsafe += 1
                    continue
                if t.risk_level == RiskLevel.L3_IN_USE.value and not include_l3:
                    skipped_l3_count += 1
                    skipped_l3_bytes += t.size_bytes
                    continue
                if t.contains_secrets and not include_secrets:
                    skipped_secrets_count += 1
                    continue

                candidates.append(t)

        candidate_bytes = sum(t.size_bytes for t in candidates)
        secret_candidates = [t for t in candidates if t.contains_secrets]
        secret_warnings = [
            {
                "path": t.resolved_path,
                "severity": t.secret_severity,
                "findings": list(t.secret_findings),
                "advice": "清理前请确认已备份重要凭据；若为废弃软件残留，建议隔离后同步吊销旧 Token/Key。",
            }
            for t in secret_candidates
        ]

        # 交互确认保护：必须同时显式传 dry_run=false 与 confirm=true 才执行真实归档移动
        effective_dry_run = dry_run or (not confirm)
        needs_confirmation = (not dry_run) and (not confirm) and len(candidates) > 0

        if effective_dry_run:
            return {
                "mode": mode,
                "is_dry_run": True,
                "needs_confirmation": needs_confirmation,
                "message": (
                    "已生成预览清单，需要用户明确确认后传 dry_run=false 且 confirm=true 方可执行隔离清理。"
                    if needs_confirmation or candidates
                    else "未发现符合条件的可清理目标。"
                ),
                "estimated_reclaim_bytes": candidate_bytes,
                "estimated_reclaim_human": format_size(candidate_bytes),
                "candidate_count": len(candidates),
                "candidates": [_serialize_target(t) for t in candidates],
                "skipped_summary": {
                    "blocked_l4_unsafe_count": skipped_unsafe,
                    "skipped_l3_count": skipped_l3_count,
                    "skipped_l3_human": format_size(skipped_l3_bytes),
                    "skipped_secrets_count": skipped_secrets_count,
                },
                "secret_warnings": secret_warnings,
            }

        cleaner = self.cleaner_factory()
        results = cleaner.clean_targets(candidates, dry_run=False, force_secret=include_secrets)
        freed_bytes = sum(res.size_freed for res in results)
        success_count = sum(1 for res in results if res.success)

        return {
            "mode": mode,
            "is_dry_run": False,
            "needs_confirmation": False,
            "success_count": success_count,
            "total_count": len(candidates),
            "freed_bytes": freed_bytes,
            "freed_human": format_size(freed_bytes),
            "session_id": cleaner.last_session_id,
            "quarantine_dir": cleaner.last_quarantine_dir,
            "manifest_path": cleaner.last_manifest_path,
            "rollback_hint": (
                f"如需无损恢复，请调用 sea_otter_rollback (action='restore', session_id='{cleaner.last_session_id}', dry_run=false)"
                if cleaner.last_session_id else None
            ),
            "secret_warnings": secret_warnings,
            "results": [
                {
                    "path": res.target.resolved_path,
                    "success": res.success,
                    "size_freed": res.size_freed,
                    "method_used": res.method_used,
                    "message": res.message,
                    "quarantine_path": res.quarantine_path,
                }
                for res in results
            ],
        }

    def handle_rollback(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        action = str(arguments.get("action") or "list")
        session_id = arguments.get("session_id")
        dry_run = bool(arguments.get("dry_run", True))
        overwrite = bool(arguments.get("overwrite", False))

        qm = self.quarantine_factory()
        if action == "list":
            sessions = qm.list_sessions()
            return {
                "action": "list",
                "quarantine_base_dir": qm.base_dir,
                "session_count": len(sessions),
                "sessions": sessions,
            }

        if action != "restore":
            raise ValueError(f"Unsupported rollback action: {action}. Expected 'list' or 'restore'.")

        session = qm.find_session(session_id)
        if session is None:
            return {
                "action": "restore",
                "success": False,
                "error": f"未找到匹配的隔离会话: {session_id or 'latest'}",
                "quarantine_base_dir": qm.base_dir,
            }

        report = qm.rollback_session(
            session_id=session.get("session_id"),
            dry_run=dry_run,
            overwrite=overwrite,
        )
        return {
            "action": "restore",
            "success": report.failed_count == 0,
            "session_id": report.session_id,
            "quarantine_dir": report.quarantine_dir,
            "manifest_path": report.manifest_path,
            "is_dry_run": report.is_dry_run,
            "restored_count": report.restored_count,
            "restored_bytes": report.restored_bytes,
            "restored_human": format_size(report.restored_bytes),
            "failed_count": report.failed_count,
            "results": [
                {
                    "name": r.name,
                    "original_path": r.original_path,
                    "quarantine_path": r.quarantine_path,
                    "size_bytes": r.size_bytes,
                    "success": r.success,
                    "skipped": r.skipped,
                    "message": r.message,
                }
                for r in report.results
            ],
        }

    def dispatch_tool(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        args = arguments if isinstance(arguments, dict) else {}
        # 严禁工具执行过程中向 stdout 打印文本污染 JSON-RPC 流
        with contextlib.redirect_stdout(sys.stderr):
            if name == "sea_otter_scan":
                return self.handle_scan(args)
            if name == "sea_otter_clean":
                return self.handle_clean(args)
            if name == "sea_otter_rollback":
                return self.handle_rollback(args)
        raise KeyError(f"Unknown tool: {name}")


class MCPStdioServer:
    """标准 Model Context Protocol (JSON-RPC 2.0 over stdio) 消息循环"""

    def __init__(self, service: Optional[SeaOtterMCPService] = None):
        self.service = service or SeaOtterMCPService()
        self.initialized = False

    @staticmethod
    def _error_response(req_id: Any, code: int, message: str, data: Any = None) -> Dict[str, Any]:
        err: Dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            err["data"] = data
        return {"jsonrpc": "2.0", "id": req_id, "error": err}

    @staticmethod
    def _ok_response(req_id: Any, result: Dict[str, Any]) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    def handle_message(self, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
            return self._error_response(msg.get("id") if isinstance(msg, dict) else None, -32600, "Invalid Request")

        method = msg.get("method")
        has_id = "id" in msg
        req_id = msg.get("id")
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}

        # 通知类消息 (无 id) 不返回响应
        if not has_id:
            if method == "notifications/initialized":
                self.initialized = True
            return None

        if not isinstance(method, str) or not method:
            return self._error_response(req_id, -32600, "Invalid Request: missing method")

        if method == "initialize":
            client_version = params.get("protocolVersion")
            negotiated = (
                client_version
                if client_version in SUPPORTED_PROTOCOL_VERSIONS
                else DEFAULT_PROTOCOL_VERSION
            )
            return self._ok_response(req_id, {
                "protocolVersion": negotiated,
                "capabilities": {
                    "tools": {"listChanged": False},
                },
                "serverInfo": {
                    "name": SERVER_NAME,
                    "version": SERVER_VERSION,
                },
                "instructions": (
                    "Use sea_otter_scan to inspect AI tool disk usage and risks first. "
                    "Use sea_otter_clean with dry_run=true to preview cleanup candidates and secret warnings, "
                    "then set dry_run=false and confirm=true only after user confirmation. "
                    "Use sea_otter_rollback to list or restore archived items."
                ),
            })

        if method == "ping":
            return self._ok_response(req_id, {})

        if method == "tools/list":
            return self._ok_response(req_id, {
                "tools": self.service.get_tool_definitions(),
            })

        if method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments")
            if not isinstance(tool_name, str) or not tool_name:
                return self._error_response(req_id, -32602, "Invalid params: missing tool name")
            if tool_args is not None and not isinstance(tool_args, dict):
                return self._error_response(req_id, -32602, "Invalid params: arguments must be an object")

            try:
                payload = self.service.dispatch_tool(tool_name, tool_args or {})
                return self._ok_response(req_id, {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(payload, indent=2, ensure_ascii=False),
                        }
                    ],
                    "isError": False,
                })
            except KeyError as e:
                return self._error_response(req_id, -32602, str(e))
            except ValueError as e:
                return self._ok_response(req_id, {
                    "content": [{"type": "text", "text": json.dumps({"error": str(e)}, ensure_ascii=False)}],
                    "isError": True,
                })
            except Exception as e:
                return self._ok_response(req_id, {
                    "content": [{"type": "text", "text": json.dumps({"error": f"Tool execution failed: {e}"}, ensure_ascii=False)}],
                    "isError": True,
                })

        return self._error_response(req_id, -32601, f"Method not found: {method}")

    @staticmethod
    def _read_next_message(stdin: TextIO) -> Tuple[Optional[str], bool]:
        """
        支持换行分隔 JSON-RPC (标准 MCP stdio) 与 Content-Length 帧头两种输入格式。
        返回 (raw_json_str, is_eof)
        """
        while True:
            line = stdin.readline()
            if line == "":
                return None, True
            stripped = line.strip()
            if not stripped:
                continue

            if stripped.lower().startswith("content-length:"):
                try:
                    content_length = int(stripped.split(":", 1)[1].strip())
                except ValueError:
                    continue
                while True:
                    hdr = stdin.readline()
                    if hdr == "" or hdr.strip() == "":
                        break
                body = stdin.read(content_length)
                return body, False

            return stripped, False

    def serve(self, stdin: Optional[TextIO] = None, stdout: Optional[TextIO] = None) -> None:
        in_stream = stdin or sys.stdin
        out_stream = stdout or sys.stdout

        while True:
            raw_msg, is_eof = self._read_next_message(in_stream)
            if is_eof:
                break
            if not raw_msg:
                continue

            try:
                parsed = json.loads(raw_msg)
            except json.JSONDecodeError as e:
                err = self._error_response(None, -32700, f"Parse error: {e}")
                out_stream.write(json.dumps(err, ensure_ascii=False) + "\n")
                out_stream.flush()
                continue

            resp = self.handle_message(parsed)
            if resp is not None:
                out_stream.write(json.dumps(resp, ensure_ascii=False) + "\n")
                out_stream.flush()


def main() -> None:
    """CLI entrypoint for `sea-otter-mcp`."""
    MCPStdioServer().serve()


if __name__ == "__main__":
    main()
