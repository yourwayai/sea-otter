"""
命令行接口核心驱动 (CLI Dispatcher)
包含 scan, clean, rules 命令的具体实现。
"""

import sys
import json
import argparse
from typing import List, Optional

from sea_otter.scanner import RuleScanner, ToolScanReport, TargetMatch
from sea_otter.cleaner import SafeCleaner
from sea_otter.ui import (
    c, Color, format_size, print_banner, get_status_badge, CATEGORY_NAMES
)

def cmd_scan(args, scanner: RuleScanner):
    """执行扫描体检命令"""
    if not args.json:
        print_banner()

    tools_filter = args.tools if args.tools else None
    reports = scanner.scan_all(filter_ids=tools_filter)

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

    visible_reports = [r for r in reports if r.has_residuals or args.show_all]

    if not visible_reports:
        print(c("✨ 太棒了！未发现任何已安装的 AI 工具或残留文件，环境非常整洁。", Color.GREEN))
        return

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
                secret_badge = c(" 🔑[敏感凭证]", Color.BOLD, Color.RED) if t.contains_secrets else ""
                model_badge = c(" 🧠[本地模型权重]", Color.BOLD, Color.BRIGHT_CYAN) if t.is_model_weight else ""
                safety_badge = "" if t.is_safe else c(f" ⚠️[{t.safety_reason}]", Color.BOLD, Color.BRIGHT_RED)
                
                print(f"     • [{c(cat_desc, Color.MAGENTA)}] {t.resolved_path} {c(f'({format_size(t.size_bytes)})', Color.DIM)}{secret_badge}{model_badge}{safety_badge}")
                if t.description:
                    print(f"       {c('↳ ' + t.description, Color.DIM)}")
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
    print(c("═" * 68, Color.DIM))
    print(f"{c('💡 提示:', Color.DIM)} 执行 {c('sea-otter clean --dry-run', Color.CYAN)} 可预览清理计划；默认所有被清理文件将移入系统废纸篓，安全可恢复。")

def cmd_clean(args, scanner: RuleScanner):
    """执行清理操作"""
    print_banner()

    tools_filter = args.tools if args.tools else None
    reports = scanner.scan_all(filter_ids=tools_filter)

    categories_filter = None
    if args.category:
        categories_filter = [c.strip() for c in args.category.split(",") if c.strip()]

    # 筛选待清理目标
    candidates: List[TargetMatch] = []
    skipped_secrets_count = 0
    skipped_unsafe_count = 0

    for r in reports:
        for t in r.targets:
            if categories_filter and t.category not in categories_filter:
                continue
            if not t.is_safe:
                skipped_unsafe_count += 1
                continue
            if t.contains_secrets and not args.include_secrets:
                skipped_secrets_count += 1
                continue
            candidates.append(t)

    if not candidates:
        print(c("✨ 没有可清理的目标项！", Color.GREEN))
        if skipped_secrets_count > 0:
            print(f"ℹ️ 检测到 {skipped_secrets_count} 处敏感凭证，默认已被跳过（如需清理请带上 {c('--include-secrets', Color.YELLOW)}）。")
        return

    candidate_size = sum(t.size_bytes for t in candidates)

    print(c("🎯 待清理目标清单:", Color.BOLD, Color.BRIGHT_WHITE))
    for t in candidates:
        secret_mark = c(" 🔑[敏感凭证]", Color.RED) if t.contains_secrets else ""
        print(f"  [{c(CATEGORY_NAMES.get(t.category, t.category), Color.MAGENTA)}] {t.resolved_path} {c(f'({format_size(t.size_bytes)})', Color.DIM)}{secret_mark}")
        print(f"    {c(t.description, Color.DIM)}")

    print()
    print(f"预计释放空间: {c(format_size(candidate_size), Color.BOLD, Color.BRIGHT_GREEN)} (共 {len(candidates)} 项)")

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
    print(f"{c('💡 提示:', Color.DIM)} 所有文件已移入系统废纸篓，可在废纸篓中随时“放回原处”。")

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
        print(c("🔍 正在校验所有规则文件的格式与字段完整度...", Color.BOLD))
        valid_count = 0
        for r in rules:
            rid = r.get("id")
            name = r.get("name")
            category = r.get("category")
            targets = r.get("targets", {})
            if not rid or not name or not category or not targets:
                print(f"  {c('✖', Color.RED)} 规则 {rid or '未知'} 缺少核心必填字段！")
            else:
                valid_count += 1
                print(f"  {c('✔', Color.GREEN)} 规则 [{c(rid, Color.CYAN)}] 校验通过 (包含 {sum(len(v) for v in targets.values())} 处目标定义)")
        print(f"\n✨ 校验完毕: {valid_count}/{len(rules)} 条规则完全合规。")

def main():
    parser = argparse.ArgumentParser(
        prog="sea-otter",
        description="🦦 Sea-Otter: 面向新一代 AI 编程工具与 Agent CLI 的精细化清理与体检工具"
    )
    parser.add_argument("--version", action="version", version="Sea-Otter v1.0.0")

    subparsers = parser.add_subparsers(dest="command", help="可用子命令")

    # scan
    p_scan = subparsers.add_parser("scan", help="扫描系统中的 AI 开发者工具状态与残留占用")
    p_scan.add_argument("tools", nargs="*", help="指定要扫描的工具 ID (如 cursor, codex)，默认扫描全部")
    p_scan.add_argument("-a", "--all", dest="show_all", action="store_true", help="显示所有工具（包含未安装且无残留项）")
    p_scan.add_argument("--json", action="store_true", help="以 JSON 格式输出扫描结果")

    # clean
    p_clean = subparsers.add_parser("clean", help="安全清理指定的工具残留或缓存 (移入废纸篓)")
    p_clean.add_argument("tools", nargs="*", help="指定要清理的工具 ID (可选)")
    p_clean.add_argument("-c", "--category", help="按分类过滤 (如 caches,data_and_history)")
    p_clean.add_argument("-n", "--dry-run", action="store_true", help="只读模式，仅预览待清理目标与空间，不进行实际移动")
    p_clean.add_argument("--include-secrets", action="store_true", help="允许清理敏感凭证 (如 Token/API 密钥)，默认安全跳过")
    p_clean.add_argument("-y", "--yes", action="store_true", help="无需交互确认，直接移入废纸篓")

    # rules
    p_rules = subparsers.add_parser("rules", help="查看或校验内置规则库")
    p_rules.add_argument("rule_action", choices=["list", "validate"], default="list", nargs="?", help="list (查看列表) 或 validate (校验规则规范)")

    args = parser.parse_args()

def cmd_interactive_dashboard(scanner: RuleScanner):
    """交互式控制台菜单 (当用户仅输入 `sea-otter` 时启动)"""
    print_banner(full=True)

    print(c("📋 欢迎进入 Sea-Otter 交互式控制台！请选择操作模式：", Color.BOLD))
    print()
    print(f"  {c('1', Color.BOLD, Color.BRIGHT_CYAN)}  🔍 全盘扫描体检 (输出 AI 工具安装状态与孤儿残留占用)")
    print(f"  {c('2', Color.BOLD, Color.BRIGHT_GREEN)}  🛡️ 安全清理预览 (Dry-run 模拟预览哪些文件会被移入废纸篓)")
    print(f"  {c('3', Color.BOLD, Color.BRIGHT_YELLOW)}  🧹 一键清理缓存 (安全清理所有纯缓存，移入废纸篓)")
    print(f"  {c('4', Color.BOLD, Color.MAGENTA)}  📋 查看收录规则 (浏览当前收录的 14 款 AI 工具规则清单)")
    print(f"  {c('5', Color.BOLD, Color.WHITE)}  🌐 访问官方仓库 (打开 GitHub 仓库主页)")
    print(f"  {c('q', Color.DIM)}  🚪 退出程序")
    print()

    try:
        choice = input(c("👉 请输入序号 [1-5 或 q]: ", Color.BOLD, Color.YELLOW)).strip().lower()
    except (KeyboardInterrupt, EOFError):
        print("\n👋 已退出。")
        return

    print()
    if choice == "1":
        class DummyArgs:
            tools = []
            show_all = False
            json = False
        cmd_scan(DummyArgs(), scanner)
    elif choice == "2":
        class DummyCleanArgs:
            tools = []
            category = None
            dry_run = True
            include_secrets = False
            yes = False
        cmd_clean(DummyCleanArgs(), scanner)
    elif choice == "3":
        class DummyCleanCacheArgs:
            tools = []
            category = "caches"
            dry_run = False
            include_secrets = False
            yes = False
        cmd_clean(DummyCleanCacheArgs(), scanner)
    elif choice == "4":
        class DummyRulesArgs:
            rule_action = "list"
        cmd_rules(DummyRulesArgs(), scanner)
    elif choice == "5":
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
    p_scan.add_argument("--json", action="store_true", help="以 JSON 格式输出扫描结果")

    # clean
    p_clean = subparsers.add_parser("clean", help="安全清理指定的工具残留或缓存 (移入废纸篓)")
    p_clean.add_argument("tools", nargs="*", help="指定要清理的工具 ID (可选)")
    p_clean.add_argument("-c", "--category", help="按分类过滤 (如 caches,data_and_history)")
    p_clean.add_argument("-n", "--dry-run", action="store_true", help="只读模式，仅预览待清理目标与空间，不进行实际移动")
    p_clean.add_argument("--include-secrets", action="store_true", help="允许清理敏感凭证 (如 Token/API 密钥)，默认安全跳过")
    p_clean.add_argument("-y", "--yes", action="store_true", help="无需交互确认，直接移入废纸篓")

    # rules
    p_rules = subparsers.add_parser("rules", help="查看或校验内置规则库")
    p_rules.add_argument("rule_action", choices=["list", "validate"], default="list", nargs="?", help="list (查看列表) 或 validate (校验规则规范)")

    args = parser.parse_args()

    scanner = RuleScanner()

    if args.command == "scan":
        cmd_scan(args, scanner)
    elif args.command == "clean":
        cmd_clean(args, scanner)
    elif args.command == "rules":
        cmd_rules(args, scanner)
    else:
        # 当直接输入 `sea-otter` 时，进入带吉祥物形象和功能目录的交互界面
        cmd_interactive_dashboard(scanner)

if __name__ == "__main__":
    main()

