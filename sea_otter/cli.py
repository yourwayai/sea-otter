"""
命令行接口核心驱动 (CLI Dispatcher)
包含 scan, clean, rules 命令的具体实现。
"""

import sys
import json
import argparse
from typing import List, Optional

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
from sea_otter.validator import validate_rule_schema_v12
from sea_otter.ui import (
    c, Color, format_size, print_banner, get_status_badge, get_risk_badge,
    get_model_badge, get_prunable_badge, get_ghost_badge, get_channel_badge,
    get_association_badge, CATEGORY_NAMES
)

def cmd_scan(args, scanner: RuleScanner):
    """执行扫描体检命令"""
    if not args.json:
        print_banner()

    tools_filter = args.tools if args.tools else None
    only_models = getattr(args, "models", False)
    only_slim = getattr(args, "slim", False)
    only_ghosts = getattr(args, "ghosts", False)
    only_channels = getattr(args, "channels", False)
    only_associations = getattr(args, "associations", False)

    if only_ghosts and not tools_filter:
        ghost_rules = [r for r in scanner.load_rules() if "ghost_rules" in r]
        reports = [scanner.scan_tool(r) for r in ghost_rules]
        reports.append(RootOrphanScanner().scan())
    elif only_channels and not tools_filter:
        all_rules = scanner.load_rules()
        reports = [ChannelRedundancyScanner(rules=all_rules, use_builtin_defaults=True).scan()]
    elif only_associations and not tools_filter:
        all_rules = scanner.load_rules()
        reports = [AssociationEngine(rules=all_rules).scan()]
    else:
        reports = scanner.scan_all(filter_ids=tools_filter)
    if only_models:
        for r in reports:
            r.targets = [t for t in r.targets if t.is_model_weight or t.category == "ai_models"]
            r.total_size_bytes = sum(t.size_bytes for t in r.targets)
            r.safe_size_bytes = sum(t.size_bytes for t in r.targets if t.is_safe)
            r.model_weight_size_bytes = sum(t.size_bytes for t in r.targets if t.is_model_weight)
    elif only_slim:
        for r in reports:
            r.targets = [
                t for t in r.targets
                if (t.prunable or t.is_model_weight or t.category in ["caches", "ai_models"]
                    or "files" in t.resolved_path.lower() or "knowledgebase" in t.resolved_path.lower()
                    or "indexeddb" in t.resolved_path.lower())
                and t.category not in ["credentials", "configs"] and not t.contains_secrets
                and not any(t.resolved_path.lower().endswith(ext) for ext in [".sqlite", ".sqlite3", ".db", ".plist"])
            ]
            r.total_size_bytes = sum(t.size_bytes for t in r.targets)
            r.safe_size_bytes = sum(t.size_bytes for t in r.targets if t.is_safe)
            r.model_weight_size_bytes = sum(t.size_bytes for t in r.targets if t.is_model_weight)
    elif only_ghosts:
        for r in reports:
            r.targets = [
                t for t in r.targets
                if t.ghost_type is not None or t.category in ["ghost", "skeleton", "locks", "temp_images"]
            ]
            r.total_size_bytes = sum(t.size_bytes for t in r.targets)
            r.safe_size_bytes = sum(t.size_bytes for t in r.targets if t.is_safe)
            r.model_weight_size_bytes = 0
    elif only_channels:
        for r in reports:
            r.targets = [t for t in r.targets if t.channel_name is not None]
            r.total_size_bytes = sum(t.size_bytes for t in r.targets)
            r.safe_size_bytes = sum(t.size_bytes for t in r.targets if t.is_safe)
            r.model_weight_size_bytes = 0
    elif only_associations:
        for r in reports:
            r.targets = [t for t in r.targets if t.association_tier is not None]
            r.total_size_bytes = sum(t.size_bytes for t in r.targets)
            r.safe_size_bytes = sum(t.size_bytes for t in r.targets if t.is_safe)
            r.model_weight_size_bytes = 0

    if args.json:
        # JSON 格式输出，方便集成外部工具 (如 Raycast 插件)
        out_data = []
        for r in reports:
            out_data.append({
                "id": r.tool_id,
                "name": r.name,
                "category": r.category,
                "vendor": r.vendor,
                "homepage": r.homepage,
                "status": r.status,
                "total_size_bytes": r.total_size_bytes,
                "safe_size_bytes": r.safe_size_bytes,
                "model_weight_size_bytes": r.model_weight_size_bytes,
                "secret_count": r.secret_count,
                "running_processes": r.running_processes,
                "active_locks": r.active_locks,
                "targets": [
                    {
                        "category": t.category,
                        "path": t.resolved_path,
                        "description": t.description,
                        "size_bytes": t.size_bytes,
                        "contains_secrets": t.contains_secrets,
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
                        "risk_level": t.risk_level,
                        "default_selected": t.default_selected,
                        "is_safe": t.is_safe,
                        "safety_reason": t.safety_reason
                    }
                    for t in r.targets
                ]
            })
        print(json.dumps(out_data, indent=2, ensure_ascii=False))
        return

    # 人类可读格式渲染
    total_tools = len(reports)
    running_count = sum(1 for r in reports if r.status == "running")
    installed_count = sum(1 for r in reports if r.status == "installed")
    orphaned_count = sum(1 for r in reports if r.status == "orphaned")
    clean_count = sum(1 for r in reports if r.status == "clean")
    total_bytes = sum(r.total_size_bytes for r in reports)
    total_secrets = sum(r.secret_count for r in reports)
    total_model_bytes = sum(r.model_weight_size_bytes for r in reports)

    # 四级安全防护矩阵统计
    total_l1_bytes = sum(sum(t.size_bytes for t in r.l1_targets) for r in reports)
    total_l2_bytes = sum(sum(t.size_bytes for t in r.l2_targets) for r in reports)
    total_l3_bytes = sum(sum(t.size_bytes for t in r.l3_targets) for r in reports)
    total_l4_count = sum(len(r.l4_targets) for r in reports)

    visible_reports = [r for r in reports if r.has_residuals or args.show_all]

    if not visible_reports:
        print(c("✨ 太棒了！未发现任何已安装的 AI 工具或残留文件，环境非常整洁。", Color.GREEN))
        return

    if only_models:
        print(c("🧠 正在扫描系统中的本地端侧 AI 大模型与权重占用...", Color.BOLD, Color.BRIGHT_CYAN))
    elif only_ghosts:
        print(c("👻 正在扫描存储根目录散落文件、幽灵目录与骨架空目录...", Color.BOLD, Color.BRIGHT_GREEN))
    elif only_channels:
        print(c("🏝️ 正在执行浏览器与 IDE 多通道发布孤岛交叉检测 (Channel Cross-Check)...", Color.BOLD, Color.BRIGHT_YELLOW))
    elif only_associations:
        print(c("🔗 正在执行应用名与路径脱节的三级反向映射孤儿扫描 (Association Engine)...", Color.BOLD, Color.BRIGHT_CYAN))
    else:
        print(c("🔍 正在扫描系统中的 AI 开发者工具与 Agent 残留...", Color.BOLD))
    print()

    for r in visible_reports:
        status_badge = get_status_badge(r.status)
        size_str = format_size(r.total_size_bytes)
        
        # 头部标题
        print(f"📦 {c(r.name, Color.BOLD, Color.BRIGHT_WHITE)} {c(f'({r.tool_id})', Color.DIM)} -> {status_badge}")
        if r.running_processes:
            p_desc = ", ".join(r.running_processes[:2])
            print(f"   {c('活跃进程:', Color.DIM)} {c(p_desc, Color.BRIGHT_BLUE)} {c('(🛡️ 安全防线已锁定保护，避免误伤)', Color.YELLOW)}")
        elif r.detection_matches:
            det_info = ", ".join(r.detection_matches)
            print(f"   {c('检测凭证:', Color.DIM)} {c(det_info, Color.CYAN)}")
        
        if r.targets:
            print(f"   {c('发现占用:', Color.DIM)} {c(size_str, Color.BOLD, Color.BRIGHT_YELLOW)} (共 {len(r.targets)} 处目标)")
            for t in r.targets:
                cat_desc = CATEGORY_NAMES.get(t.category, t.category)
                risk_badge = get_risk_badge(t.risk_level)
                secret_badge = c(" 🔑[敏感凭证]", Color.BOLD, Color.RED) if t.contains_secrets else ""
                model_badge = get_model_badge(t.is_model_weight, t.size_bytes, t.model_name)
                prune_badge = get_prunable_badge(t.prunable, t.resolved_path, t.description)
                ghost_badge = get_ghost_badge(t.ghost_type, t.category)
                channel_badge = get_channel_badge(t.channel_name, t.inactive_days)
                assoc_badge = get_association_badge(t.association_tier, t.associated_app, t.inactive_days)
                safety_badge = "" if t.is_safe else c(f" ⚠️[{t.safety_reason}]", Color.BOLD, Color.BRIGHT_RED)
                
                print(f"     • [{c(cat_desc, Color.MAGENTA)}] {risk_badge} {t.resolved_path} {c(f'({format_size(t.size_bytes)})', Color.DIM)}{secret_badge}{model_badge}{prune_badge}{ghost_badge}{channel_badge}{assoc_badge}{safety_badge}")
                if t.description:
                    desc_text = t.description
                    if t.model_name and t.model_name not in desc_text:
                        desc_text = f"[{t.model_name}] {desc_text}"
                    print(f"       {c('↳ ' + desc_text, Color.DIM)}")
        else:
            print(f"   {c('状态:', Color.DIM)} {c('无任何残留占用', Color.DIM)}")
        print()

    # 底部统计卡片
    status_summary_parts = []
    if running_count > 0:
        status_summary_parts.append(c(f"{running_count} 运行保护", Color.BRIGHT_BLUE))
    status_summary_parts.append(c(f"{installed_count} 已安装", Color.GREEN))
    status_summary_parts.append(c(f"{orphaned_count} 孤儿残留", Color.YELLOW))
    status_summary_parts.append(c(f"{clean_count} 整洁无残留", Color.DIM))

    print(c("═" * 68, Color.DIM))
    print(c("📊 扫描体检汇总报告", Color.BOLD, Color.BRIGHT_CYAN))
    print(f" • 覆盖规则: {c(str(total_tools), Color.BOLD)} 个工具")
    print(f" • 软件状态: {' | '.join(status_summary_parts)}")
    print(f" • 发现占用: {c(format_size(total_bytes), Color.BOLD, Color.BRIGHT_YELLOW)}")
    if total_model_bytes > 0:
        print(f" • 本地模型: {c(format_size(total_model_bytes), Color.BOLD, Color.BRIGHT_CYAN)} (包含 LLM / 向量嵌入模型)")
    if total_secrets > 0:
        print(f" • 敏感凭证: {c(str(total_secrets) + ' 处包含私钥/OAuth Token', Color.BOLD, Color.RED)}")
    print(c(" • 安全矩阵分级汇总:", Color.DIM))
    print(f"   ├─ {c('🟢 L1 极低风险', Color.BOLD, Color.BRIGHT_GREEN)}: {format_size(total_l1_bytes)} (空锁/Bug/散落，默认勾选归档)")
    print(f"   ├─ {c('🟡 L2 明确已卸载', Color.BOLD, Color.YELLOW)}: {format_size(total_l2_bytes)} (孤儿残留，默认勾选隔离)")
    if total_l3_bytes > 0:
        print(f"   ├─ {c('🟠 L3 在用减负', Color.BOLD, Color.BRIGHT_YELLOW)}: {format_size(total_l3_bytes)} (在用软件/模型，默认不勾选需确认)")
    if total_l4_count > 0:
        print(f"   └─ {c('🔴 L4 绝对红线', Color.BOLD, Color.BRIGHT_RED)}: {total_l4_count} 处受保护目标 (系统红线/活跃进程，硬编码阻断)")
    else:
        print(f"   └─ {c('🔴 L4 绝对红线', Color.BOLD, Color.BRIGHT_RED)}: 0 处违规 (系统关键数据安全)")
    print(c("═" * 68, Color.DIM))
    print(f"{c('💡 提示:', Color.DIM)} 执行 {c('sea-otter clean --dry-run', Color.CYAN)} 可预览清理计划；默认所有被清理文件将移入系统废纸篓，安全可恢复。")

def cmd_clean(args, scanner: RuleScanner):
    """执行清理操作"""
    print_banner()

    tools_filter = args.tools if args.tools else None
    only_models = getattr(args, "models", False)
    slim_mode = getattr(args, "slim", False)
    only_ghosts = getattr(args, "ghosts", False)
    only_channels = getattr(args, "channels", False)
    only_associations = getattr(args, "associations", False)

    if only_ghosts and not tools_filter:
        ghost_rules = [r for r in scanner.load_rules() if "ghost_rules" in r]
        reports = [scanner.scan_tool(r) for r in ghost_rules]
        reports.append(RootOrphanScanner().scan())
    elif only_channels and not tools_filter:
        all_rules = scanner.load_rules()
        reports = [ChannelRedundancyScanner(rules=all_rules, use_builtin_defaults=True).scan()]
    elif only_associations and not tools_filter:
        all_rules = scanner.load_rules()
        reports = [AssociationEngine(rules=all_rules).scan()]
    else:
        reports = scanner.scan_all(filter_ids=tools_filter)

    categories_filter = None
    if args.category:
        categories_filter = [c.strip() for c in args.category.split(",") if c.strip()]

    include_l3 = getattr(args, "include_l3", False)
    if only_models or slim_mode or only_channels:
        include_l3 = True

    if slim_mode:
        print(c("✂️ [安全减负模式 (Slimming Mode)]：保留主配置与核心对话，专注释放会话大附件、过期向量嵌入库与各类缓存", Color.BOLD, Color.BRIGHT_MAGENTA))
        print(c("🛡️ [安全保护屏障] 核心会话数据库 (cherrystudio.sqlite)、助手 Prompt 模板与 API 密钥已受到绝对保护。", Color.DIM))
        print()
    elif only_ghosts:
        print(c("👻 [根目录散落与幽灵清理模式]：专注清理 L1 极低风险的幽灵目录、散落引导图、过期死锁与骨架空目录", Color.BOLD, Color.BRIGHT_GREEN))
        print()
    elif only_channels:
        print(c("🏝️ [多通道发布孤岛清理模式]：主通道活跃使用中，一键清理超过 90 天未启动的停用测试通道 (Canary/Dev/Beta)", Color.BOLD, Color.BRIGHT_YELLOW))
        print()
    elif only_associations:
        print(c("🔗 [三级反向映射孤儿清理模式]：专项清理通过 Plist / 特征字典 / 启发式推导确认的已卸载应用残留", Color.BOLD, Color.BRIGHT_CYAN))
        print()

    # 筛选待清理目标
    candidates: List[TargetMatch] = []
    skipped_secrets_count = 0
    skipped_unsafe_count = 0
    skipped_l3_count = 0
    skipped_l3_bytes = 0

    for r in reports:
        for t in r.targets:
            if not t.tool_id:
                t.tool_id = r.tool_id
            if not t.tool_name:
                t.tool_name = r.name
            if categories_filter and t.category not in categories_filter:
                continue

            # 专项模型过滤
            if only_models and not t.is_model_weight and t.category != "ai_models":
                continue

            # 专项幽灵/根目录散落过滤
            if only_ghosts and t.ghost_type is None and t.category not in ["ghost", "skeleton", "locks", "temp_images"]:
                continue

            # 专项多通道测试孤岛过滤
            if only_channels and t.channel_name is None:
                continue

            # 专项三级反向映射孤儿过滤
            if only_associations and t.association_tier is None:
                continue

            # 专项安全减负模式过滤
            if slim_mode:
                # 排除敏感凭据与配置文件
                if t.category in ["credentials", "configs"] or t.contains_secrets:
                    continue
                # 排除核心数据库文件
                if any(t.resolved_path.lower().endswith(ext) for ext in [".sqlite", ".sqlite3", ".db", ".plist"]):
                    continue
                # 判定是否属于减负项 (纯缓存、本地模型/向量库、标记为 prunable 或会话附件/工具链)
                is_slim = (
                    t.prunable
                    or t.is_model_weight
                    or t.category in ["caches", "ai_models"]
                    or "files" in t.resolved_path.lower()
                    or "knowledgebase" in t.resolved_path.lower()
                    or "indexeddb" in t.resolved_path.lower()
                    or "toolchain" in t.resolved_path.lower()
                )
                if not is_slim:
                    continue

            # 1. 绝对系统红线或被安全防线拦截的目标，绝对阻断 (L4: Protected System)
            if t.risk_level == RiskLevel.L4_DANGER.value or not t.is_safe:
                skipped_unsafe_count += 1
                continue

            # 2. L3 (在用软件减负) 默认不勾选，需用户显式指定 --include-l3 (或使用 --models / --slim 专项参数)
            if t.risk_level == RiskLevel.L3_IN_USE.value and not include_l3:
                skipped_l3_count += 1
                skipped_l3_bytes += t.size_bytes
                continue

            # 3. 敏感凭据过滤
            if t.contains_secrets and not args.include_secrets:
                skipped_secrets_count += 1
                continue

            candidates.append(t)

    if not candidates:
        print(c("✨ 没有可清理的目标项！", Color.GREEN))
        if skipped_l3_count > 0:
            print(f"ℹ️ 检测到 {c(str(skipped_l3_count), Color.BOLD)} 处 L3 在用软件减负目标 (共 {c(format_size(skipped_l3_bytes), Color.YELLOW)})，默认已受保护未勾选。")
            print(f"   如需深度清理正在使用的软件模型权重或缓存，请带上 {c('--include-l3', Color.CYAN)}、{c('--models', Color.CYAN)} 或 {c('--slim', Color.CYAN)} 参数。")
        if skipped_secrets_count > 0:
            print(f"ℹ️ 检测到 {skipped_secrets_count} 处敏感凭证，默认已被跳过（如需清理请带上 {c('--include-secrets', Color.YELLOW)}）。")
        if args.dry_run:
            print(c("🛡️ [Dry-run 只读模式] 模拟运行，未对文件系统做任何改动。", Color.BOLD, Color.CYAN))
        return

    candidate_size = sum(t.size_bytes for t in candidates)

    print(c("🎯 待清理目标清单 (已通过四级安全防护矩阵仲裁):", Color.BOLD, Color.BRIGHT_WHITE))
    for t in candidates:
        secret_mark = c(" 🔑[敏感凭证]", Color.RED) if t.contains_secrets else ""
        risk_mark = get_risk_badge(t.risk_level)
        model_mark = f" {get_model_badge(t.is_model_weight, t.size_bytes, t.model_name)}" if (t.is_model_weight or t.category == "ai_models") else ""
        prune_mark = f" {get_prunable_badge(t.prunable, t.resolved_path, t.description)}" if (t.prunable and not t.is_model_weight) else ""
        ghost_mark = f" {get_ghost_badge(t.ghost_type, t.category)}" if (t.ghost_type or t.category in ["ghost", "skeleton", "locks", "temp_images"]) else ""
        channel_mark = f" {get_channel_badge(t.channel_name, t.inactive_days)}" if t.channel_name else ""
        assoc_mark = f" {get_association_badge(t.association_tier, t.associated_app, t.inactive_days)}" if t.association_tier else ""
        print(f"  [{c(CATEGORY_NAMES.get(t.category, t.category), Color.MAGENTA)}] {risk_mark}{model_mark}{prune_mark}{ghost_mark}{channel_mark}{assoc_mark} {t.resolved_path} {c(f'({format_size(t.size_bytes)})', Color.DIM)}{secret_mark}")
        if t.model_name:
            print(f"    {c(f'🧠 模型/向量库: {t.model_name} (可独立修剪/不破坏宿主主配置)', Color.CYAN)}")
        print(f"    {c(t.description, Color.DIM)}")

    print()
    print(f"预计释放空间: {c(format_size(candidate_size), Color.BOLD, Color.BRIGHT_GREEN)} (共 {len(candidates)} 项)")
    if slim_mode:
        print(c("🛡️ [减负模式生效] 核心会话数据库、助手预设及敏感凭据已全部安全保留。", Color.CYAN))
    elif skipped_l3_count > 0:
        print(c(f"ℹ️ 另有 {skipped_l3_count} 处 L3 在用减负项 ({format_size(skipped_l3_bytes)}) 默认未勾选保护 (加 --include-l3 或 --slim 可纳入)", Color.DIM))


    if args.dry_run:
        print()
        print(c("🛡️ [Dry-run 只读模式] 模拟运行，未对文件系统做任何改动。", Color.BOLD, Color.CYAN))
        return

    # 交互确认
    if not args.yes:
        print()
        confirm = input(f"确认将上述 {len(candidates)} 项移入系统废纸篓吗？[y/N]: ").strip().lower()
        if confirm not in ["y", "yes"]:
            print(c("🚫 已取消清理操作。", Color.YELLOW))
            return

    cleaner = SafeCleaner(use_trash=True)
    print()
    print(c("🚀 开始安全清理 (移入系统废纸篓)...", Color.BOLD))
    
    results = cleaner.clean_targets(
        candidates,
        dry_run=False,
        force_secret=args.include_secrets
    )

    success_count = sum(1 for res in results if res.success)
    freed_size = sum(res.size_freed for res in results)

    for res in results:
        t = res.target
        if res.success:
            print(f"  {c('✔', Color.GREEN)} {t.resolved_path} -> {c(res.message, Color.DIM)}")
        else:
            print(f"  {c('✖', Color.RED)} {t.resolved_path} -> {c(res.message, Color.RED)}")

    print()
    print(c("═" * 68, Color.DIM))
    print(f"✨ {c('清理完成!', Color.BOLD, Color.GREEN)} 成功处理 {c(str(success_count), Color.BOLD)}/{len(candidates)} 项，已释放空间: {c(format_size(freed_size), Color.BOLD, Color.BRIGHT_GREEN)}")
    if cleaner.last_session_id and cleaner.last_quarantine_dir:
        print(f"📦 {c('原子隔离会话:', Color.DIM)} {c(cleaner.last_session_id, Color.CYAN)} -> {c(cleaner.last_quarantine_dir, Color.DIM)}")
        if cleaner.last_manifest_path:
            print(f"📄 {c('回滚元数据清单:', Color.DIM)} {cleaner.last_manifest_path}")
        print(f"{c('💡 提示:', Color.DIM)} 如需一键无损恢复，请执行 {c(f'sea-otter rollback {cleaner.last_session_id}', Color.CYAN)}。")
    else:
        print(f"{c('💡 提示:', Color.DIM)} 所有文件已移入系统废纸篓，可在废纸篓中随时“放回原处”。")


def cmd_rollback(args):
    """原子隔离区查看与一键无损回滚命令"""
    use_json = getattr(args, "json", False)
    if not use_json:
        print_banner()

    qm = QuarantineManager()
    if getattr(args, "list_sessions", False):
        sessions = qm.list_sessions()
        if use_json:
            print(json.dumps(sessions, indent=2, ensure_ascii=False))
            return

        if not sessions:
            print(c("✨ 隔离区为空，暂无可回滚的历史清理会话。", Color.GREEN))
            return

        print(c(f"📦 隔离区共记录 {len(sessions)} 次历史清理会话 ({qm.base_dir}):\n", Color.BOLD))
        for s in sessions:
            sid = s.get("session_id", "unknown")
            created_at = s.get("created_at", "")
            status = s.get("status", "active")
            items = s.get("items", [])
            total_bytes = int(s.get("total_reclaimed_bytes", 0))
            if status == "rolled_back":
                status_str = c("[已全部回滚]", Color.DIM)
            elif status == "partial":
                status_str = c("[部分已回滚]", Color.YELLOW)
            else:
                status_str = c("[可无损恢复]", Color.BRIGHT_GREEN)
            print(f"  • {c(sid, Color.BOLD, Color.CYAN)} {status_str} · {created_at} · {len(items)} 项 ({format_size(total_bytes)})")
            apps = sorted({it.get("app_name", "Unknown") for it in items})
            print(f"    {c('涉及工具:', Color.DIM)} {', '.join(apps[:5])}{' ...' if len(apps) > 5 else ''}")
            print(f"    {c('隔离路径:', Color.DIM)} {s.get('quarantine_dir', '')}")
        print(f"\n{c('💡 提示:', Color.DIM)} 执行 {c('sea-otter rollback <session_id>', Color.CYAN)}（或省略 ID 回滚最近一次）即可无损恢复。")
        return

    session_id = getattr(args, "session_id", None)
    dry_run = getattr(args, "dry_run", False)
    force = getattr(args, "force", False)
    yes = getattr(args, "yes", False)

    session = qm.find_session(session_id)
    if session is None:
        msg = f"未找到匹配的隔离会话: {session_id or 'latest'} (目录: {qm.base_dir})"
        if use_json:
            print(json.dumps({"success": False, "error": msg}, ensure_ascii=False))
        else:
            print(c(f"⚠️ {msg}", Color.YELLOW))
            print(f"{c('💡 提示:', Color.DIM)} 执行 {c('sea-otter rollback --list', Color.CYAN)} 查看所有可用的历史隔离会话。")
        return

    items = session.get("items", [])
    pending_items = [it for it in items if not it.get("rolled_back")]

    if not use_json:
        print(c(f"⏪ 准备无损回滚隔离会话: {session.get('session_id')}", Color.BOLD, Color.BRIGHT_CYAN))
        print(f"   {c('创建时间:', Color.DIM)} {session.get('created_at', '')}")
        print(f"   {c('隔离目录:', Color.DIM)} {session.get('quarantine_dir', '')}")
        print(f"   {c('待恢复项:', Color.DIM)} {len(pending_items)}/{len(items)} 项")
        for it in pending_items:
            sz_str = format_size(int(it.get("size_bytes", 0)))
            print(f"     • [{it.get('risk_level', 'L2_ORPHAN')}] {it.get('original_path')} {c(f'({sz_str})', Color.DIM)}")
        print()

    if not pending_items:
        if use_json:
            print(json.dumps({"success": True, "session_id": session.get("session_id"), "restored_count": 0, "message": "该会话中所有条目均已回滚"}, ensure_ascii=False))
        else:
            print(c("✨ 该会话中的所有条目均已恢复完毕，无需重复回滚。", Color.GREEN))
        return

    if not dry_run and not yes and not use_json:
        confirm = input(f"确认将上述 {len(pending_items)} 项恢复至原路径吗？[y/N]: ").strip().lower()
        if confirm not in ["y", "yes"]:
            print(c("🚫 已取消回滚操作。", Color.YELLOW))
            return

    report = qm.rollback_session(session_id=session.get("session_id"), dry_run=dry_run, overwrite=force)

    if use_json:
        out = {
            "success": report.failed_count == 0,
            "session_id": report.session_id,
            "quarantine_dir": report.quarantine_dir,
            "manifest_path": report.manifest_path,
            "is_dry_run": report.is_dry_run,
            "restored_count": report.restored_count,
            "restored_bytes": report.restored_bytes,
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
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return

    for res in report.results:
        if res.skipped:
            print(f"  {c('-', Color.DIM)} {res.original_path} -> {c(res.message, Color.DIM)}")
        elif res.success:
            print(f"  {c('✔', Color.GREEN)} {res.original_path} -> {c(res.message, Color.DIM)}")
        else:
            print(f"  {c('✖', Color.RED)} {res.original_path} -> {c(res.message, Color.RED)}")

    print()
    if dry_run:
        print(c("🛡️ [Dry-run 只读模式] 模拟回滚预览，未对文件系统做任何改动。", Color.BOLD, Color.CYAN))
    else:
        print(c("═" * 68, Color.DIM))
        print(f"✨ {c('回滚完成!', Color.BOLD, Color.GREEN)} 成功恢复 {c(str(report.restored_count), Color.BOLD)} 项 ({format_size(report.restored_bytes)})。")

def cmd_rules(args, scanner: RuleScanner):
    """规则管理命令"""
    print_banner()
    rules = scanner.load_rules()

    if args.rule_action == "list":
        print(c(f"📋 当前规则库共收录 {len(rules)} 款 AI 编程与开发者工具规则:\n", Color.BOLD))
        print(f"  {'ID':<20} {'工具名称':<28} {'分类':<15} {'厂商'}")
        print("  " + "─" * 70)
        for r in rules:
            print(f"  {c(r.get('id', ''), Color.CYAN):<20} {r.get('name', ''):<28} {r.get('category', ''):<15} {c(r.get('vendor', ''), Color.DIM)}")
        print()
    elif args.rule_action == "validate":
        print(c("🔍 正在校验所有规则文件的格式与字段完整度 (Rule Schema v1.2)...", Color.BOLD))
        valid_count = 0
        for r in rules:
            rid = r.get("id", "unknown")
            is_valid, errors = validate_rule_schema_v12(r)
            if not is_valid:
                print(f"  {c('✖', Color.RED)} 规则 [{c(rid, Color.CYAN)}] 校验失败:")
                for err in errors:
                    print(f"      {c('↳ ' + err, Color.RED)}")
            else:
                valid_count += 1
                targets = r.get("targets", {})
                target_count = sum(len(v) for v in targets.values() if isinstance(v, list))
                extras = []
                if "channels" in r:
                    cur = r["channels"].get("current_channel", "unknown")
                    rel_count = len(r["channels"].get("related_channels", []))
                    extras.append(f"通道: {cur} ({rel_count} 关联通道)")
                if "ghost_rules" in r:
                    g_count = len(r["ghost_rules"].get("root_patterns", []))
                    extras.append(f"幽灵规则: {g_count} 项")
                extra_str = f" [{', '.join(extras)}]" if extras else ""
                print(f"  {c('✔', Color.GREEN)} 规则 [{c(rid, Color.CYAN)}] 校验通过 (包含 {target_count} 处目标定义){c(extra_str, Color.DIM)}")
        print(f"\n✨ 校验完毕: {valid_count}/{len(rules)} 条规则完全合规 (Rule Schema v1.2)。")

def cmd_about():
    """打印详细的项目关于信息 (About Sea-Otter)"""
    print_banner(full=True)
    
    BOLD = Color.BOLD
    W = Color.BRIGHT_WHITE
    C = Color.BRIGHT_CYAN
    Y = Color.YELLOW
    G = Color.GREEN
    DIM = Color.DIM

    about_text = f"""
{c("🦦 关于 Sea-Otter (DevSweep Engine)", BOLD, W)}
{c("─" * 60, DIM)}
{c("像海獭（Sea Otter）浮在水面梳理皮毛一样，时刻保持开发环境的清爽与安全。", Y)}

{c("🌟 诞生背景：", BOLD, C)}
在 AI 编程工具与 Agent CLI 爆发的时代，我们频繁尝鲜各类智能体工具（如 Claude Code,
Codex, Cursor, Windsurf, Trae, Ollama 等）。但传统清理软件（如 CleanMyMac、AppCleaner）
往往只能匹配应用安装包，面临严重的【三大痛点】：
  1. {c("Dotfiles 盲区", BOLD)}：海量配置、会话数据库深藏于 ~/.claude, ~/.gemini, ~/.codex 等隐藏目录；
  2. {c("孤儿残留堆积", BOLD)}：App 已拖入废纸篓，但后台守护进程、数 GB 的本地模型和 SQLite 数据库依然滞留；
  3. {c("敏感凭证泄露", BOLD)}：大量明文的 OAuth Token、API Key 混杂在旧缓存中，形成长期的安全隐患。

{c("🛡️ 核心安全防线：", BOLD, G)}
  • {c("进程存活交叉验证", BOLD)}：严格核对系统活跃进程与单例锁，正在运行的工具强制锁定保护，绝不误杀。
  • {c("代码工作区强制免疫", BOLD)}：探测到 .git, .svn, .obsidian 目录时，一律视为工程资产，绝对阻断删除。
  • {c("默认系统废纸篓安全删除", BOLD)}：绝不执行暴力 rm -rf，优先移入系统废纸篓，随时可“放回原处”。
  • {c("敏感凭据高危警示", BOLD)}：自动标记包含 API Key / 访问令牌的敏感文件，默认清理时自动跳过。

{c("📌 项目元信息：", BOLD, W)}
  • 版本号:   {c("v1.0.0 (Rule Schema v1.1)", BOLD)}
  • 开发者:   {c("YourWay AI & Sea-Otter Contributors", C)}
  • 开源协议: {c("MIT License", G)}
  • 官方仓库: {c("https://github.com/yourwayai/sea-otter", C)}
{c("─" * 60, DIM)}
"""
    print(about_text)

def cmd_interactive_dashboard(scanner: RuleScanner):
    """交互式控制台菜单 (当用户仅输入 `sea-otter` 时启动)"""
    print_banner(full=True)

    print(c("📋 欢迎进入 Sea-Otter 交互式控制台！请选择操作模式：", Color.BOLD))
    print()
    print(f"  {c('1', Color.BOLD, Color.BRIGHT_CYAN)}  🔍 全盘扫描体检 (输出 AI 工具安装状态与孤儿残留占用)")
    print(f"  {c('2', Color.BOLD, Color.BRIGHT_GREEN)}  🛡️ 安全清理预览 (Dry-run 模拟预览哪些文件会被移入废纸篓)")
    print(f"  {c('3', Color.BOLD, Color.BRIGHT_YELLOW)}  🧹 一键清理缓存 (安全清理所有纯缓存，移入废纸篓)")
    print(f"  {c('4', Color.BOLD, Color.BRIGHT_MAGENTA)}  ✂️ 智能安全减负 (Slim Mode - 释放会话大附件与向量库，保留对话与配置)")
    print(f"  {c('5', Color.BOLD, Color.MAGENTA)}  📋 查看收录规则 (浏览当前收录的 {len(scanner.rules_dirs)} 个规则源中的规则)")
    print(f"  {c('6', Color.BOLD, Color.BRIGHT_BLUE)}  ℹ️ 关于项目理念 (了解 Sea-Otter 诞生背景与安全设计)")
    print(f"  {c('7', Color.BOLD, Color.WHITE)}  🌐 访问官方仓库 (打开 GitHub 仓库主页)")
    print(f"  {c('q', Color.DIM)}  🚪 退出程序")
    print()

    try:
        choice = input(c("👉 请输入序号 [1-7 或 q]: ", Color.BOLD, Color.YELLOW)).strip().lower()
    except (KeyboardInterrupt, EOFError):
        print("\n👋 已退出。")
        return

    print()
    if choice == "1":
        class DummyArgs:
            tools = []
            show_all = False
            models = False
            slim = False
            json = False
        cmd_scan(DummyArgs(), scanner)
    elif choice == "2":
        class DummyCleanArgs:
            tools = []
            category = None
            dry_run = True
            include_secrets = False
            include_l3 = False
            models = False
            slim = False
            yes = False
        cmd_clean(DummyCleanArgs(), scanner)
    elif choice == "3":
        class DummyCleanCacheArgs:
            tools = []
            category = "caches"
            dry_run = False
            include_secrets = False
            include_l3 = False
            models = False
            slim = False
            yes = False
        cmd_clean(DummyCleanCacheArgs(), scanner)
    elif choice == "4":
        class DummySlimArgs:
            tools = []
            category = None
            dry_run = False
            include_secrets = False
            include_l3 = True
            models = False
            slim = True
            yes = False
        cmd_clean(DummySlimArgs(), scanner)
    elif choice == "5":
        class DummyRulesArgs:
            rule_action = "list"
        cmd_rules(DummyRulesArgs(), scanner)
    elif choice == "6":
        cmd_about()
    elif choice == "7":
        import webbrowser
        print(c("🚀 正在为您打开官方仓库: https://github.com/yourwayai/sea-otter", Color.CYAN))
        webbrowser.open("https://github.com/yourwayai/sea-otter")
    elif choice in ["q", "quit", "exit"]:
        print(c("🦦 保持好心情，下次再见！", Color.GREEN))
    else:
        print(c("⚠️ 无效的选项，默认执行全盘扫描体检：", Color.YELLOW))
        class DummyArgs:
            tools = []
            show_all = False
            models = False
            slim = False
            json = False
        cmd_scan(DummyArgs(), scanner)

def main():
    parser = argparse.ArgumentParser(
        prog="sea-otter",
        description="🦦 Sea-Otter: 面向新一代 AI 编程工具与 Agent CLI 的精细化清理与体检工具"
    )
    parser.add_argument("--version", action="version", version="Sea-Otter v1.0.0")

    subparsers = parser.add_subparsers(dest="command", help="可用子命令 (留空进入交互式主菜单)")

    # scan
    p_scan = subparsers.add_parser("scan", help="扫描系统中的 AI 开发者工具状态与残留占用")
    p_scan.add_argument("tools", nargs="*", help="指定要扫描的工具 ID (如 cursor, codex)，默认扫描全部")
    p_scan.add_argument("-a", "--all", dest="show_all", action="store_true", help="显示所有工具（包含未安装且无残留项）")
    p_scan.add_argument("-m", "--models", action="store_true", help="仅显示本地 AI 端侧模型与权重占用")
    p_scan.add_argument("-s", "--slim", action="store_true", help="仅查看支持安全减负的目标项 (会话大附件、向量嵌入库、缓存)")
    p_scan.add_argument("-g", "--ghosts", action="store_true", help="仅扫描根目录散落文件、幽灵目录与骨架空目录 (L1 极低风险)")
    p_scan.add_argument("-C", "--channels", action="store_true", help="仅检测多通道发布孤岛 (如超过 90 天未用的 Canary/Dev/Beta 测试通道)")
    p_scan.add_argument("-A", "--associations", action="store_true", help="仅检测应用名与路径脱节的三级反向映射孤儿目录")
    p_scan.add_argument("--json", action="store_true", help="以 JSON 格式输出扫描结果")

    # clean
    p_clean = subparsers.add_parser("clean", help="安全清理指定的工具残留或缓存 (移入废纸篓)")
    p_clean.add_argument("tools", nargs="*", help="指定要清理的工具 ID (可选)")
    p_clean.add_argument("-c", "--category", help="按分类过滤 (如 caches,data_and_history)")
    p_clean.add_argument("-m", "--models", action="store_true", help="专项清理本地 AI 端侧大模型与权重文件 (保留应用主配置与在用数据)")
    p_clean.add_argument("-s", "--slim", action="store_true", help="安全减负模式：保留主配置与核心对话，仅清理会话大附件、过期向量嵌入库与各类缓存")
    p_clean.add_argument("-g", "--ghosts", action="store_true", help="专项清理根目录散落文件、幽灵目录与骨架空目录 (L1 极低风险)")
    p_clean.add_argument("-C", "--channels", action="store_true", help="专项清理停用超过 90 天的测试通道孤岛 (Canary/Dev/Beta)")
    p_clean.add_argument("-A", "--associations", action="store_true", help="专项清理三级反向映射引擎推导的已卸载应用孤儿目录")
    p_clean.add_argument("-n", "--dry-run", action="store_true", help="只读模式，仅预览待清理目标与空间，不进行实际移动")
    p_clean.add_argument("--include-l3", action="store_true", help="允许清理 L3 在用软件减负项 (如正在使用的端侧大模型、本地缓存)，默认安全跳过保护")
    p_clean.add_argument("--include-secrets", action="store_true", help="允许清理敏感凭证 (如 Token/API 密钥)，默认安全跳过")
    p_clean.add_argument("-y", "--yes", action="store_true", help="无需交互确认，直接移入废纸篓")


    # rollback
    p_rollback = subparsers.add_parser("rollback", help="从 ~/.Trash 原子隔离区无损恢复已清理的文件/目录")
    p_rollback.add_argument("session_id", nargs="?", help="指定隔离会话 ID（如 cleanup_20261125_114500），省略则默认最新会话")
    p_rollback.add_argument("-l", "--list", dest="list_sessions", action="store_true", help="列出所有历史隔离会话")
    p_rollback.add_argument("-n", "--dry-run", action="store_true", help="只读模式，仅预览恢复路径，不执行实际移动")
    p_rollback.add_argument("-f", "--force", action="store_true", help="若原路径已有同名文件或目录，强制覆盖恢复")
    p_rollback.add_argument("-y", "--yes", action="store_true", help="无需交互确认，直接恢复")
    p_rollback.add_argument("--json", action="store_true", help="以 JSON 格式输出结果")

    # rules
    p_rules = subparsers.add_parser("rules", help="查看或校验内置规则库")
    p_rules.add_argument("rule_action", choices=["list", "validate"], default="list", nargs="?", help="list (查看列表) 或 validate (校验规则规范)")

    # about
    subparsers.add_parser("about", help="显示 Sea-Otter 项目背景、设计哲学与安全防线说明")

    args = parser.parse_args()

    scanner = RuleScanner()

    if args.command == "scan":
        cmd_scan(args, scanner)
    elif args.command == "clean":
        cmd_clean(args, scanner)
    elif args.command == "rollback":
        cmd_rollback(args)
    elif args.command == "rules":
        cmd_rules(args, scanner)
    elif args.command == "about":
        cmd_about()
    else:
        # 当直接输入 `sea-otter` 时，进入带吉祥物形象和功能目录的交互界面
        cmd_interactive_dashboard(scanner)

if __name__ == "__main__":
    main()

