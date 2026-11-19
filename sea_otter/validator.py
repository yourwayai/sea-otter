"""
规则库规范校验模块 (Rule Schema v1.2 Validator)
负责对收录的 YAML 规则进行 Schema v1.2 规范校验（支持通道分支、端侧模型与幽灵目录规则）。
"""

import re
from typing import Dict, Any, List, Tuple

SCHEMA_VERSION = "v1.2"

# 合法的工具一级分类
VALID_CATEGORIES = {
    "ide",
    "cli-agent",
    "desktop-agent",
    "runtime",
    "extension",
    "browser",
}

# 合法的 targets 子分类
VALID_TARGET_CATEGORIES = {
    "caches",
    "preferences",
    "credentials",
    "ai_models",
    "data_and_history",
    "configs",
    "binaries_and_scripts",
}

# 合法的四级安全风险等级
VALID_RISK_LEVELS = {
    "L1_SAFE",
    "L2_ORPHAN",
    "L3_IN_USE",
    "L4_DANGER",
}

ID_REGEX = re.compile(r"^[a-z0-9-]+$")


def validate_target_item(item: Any, path_context: str = "target") -> List[str]:
    """校验单项目标 (targetItem) 规范"""
    errors = []
    if not isinstance(item, dict):
        return [f"{path_context}: 目标必须是字典对象，收到 {type(item).__name__}"]

    # 1. 必填字段
    if "path" not in item or not isinstance(item["path"], str) or not item["path"].strip():
        errors.append(f"{path_context}: 缺少非空字符串 path 字段")
    if "description" not in item or not isinstance(item["description"], str) or not item["description"].strip():
        errors.append(f"{path_context}: 缺少非空字符串 description 字段")

    # 2. 可选类型约束
    if "risk_level" in item:
        if item["risk_level"] not in VALID_RISK_LEVELS:
            errors.append(
                f"{path_context}: risk_level '{item['risk_level']}' 非法，必须为 {sorted(VALID_RISK_LEVELS)} 之一"
            )

    for bool_field in ["default_selected", "contains_secrets", "is_model_weight", "regenerable", "prunable"]:
        if bool_field in item and not isinstance(item[bool_field], bool):
            errors.append(f"{path_context}: {bool_field} 必须是布尔值 (boolean)")

    for str_field in ["model_name", "model_format"]:
        if str_field in item and not isinstance(item[str_field], str):
            errors.append(f"{path_context}: {str_field} 必须是字符串")

    # 3. 递归校验子目标 (sub_targets)
    if "sub_targets" in item:
        sub_list = item["sub_targets"]
        if not isinstance(sub_list, list):
            errors.append(f"{path_context}: sub_targets 必须是列表")
        else:
            for idx, sub in enumerate(sub_list):
                sub_errors = validate_target_item(sub, f"{path_context}.sub_targets[{idx}]")
                errors.extend(sub_errors)

    return errors


def validate_channels(channels: Any) -> List[str]:
    """校验 Schema v1.2 多通道分支 (channels) 规范"""
    errors = []
    if not isinstance(channels, dict):
        return [f"channels 必须是字典对象，收到 {type(channels).__name__}"]

    if "current_channel" in channels and not isinstance(channels["current_channel"], str):
        errors.append("channels.current_channel 必须是字符串")

    if "related_channels" in channels:
        rel_list = channels["related_channels"]
        if not isinstance(rel_list, list):
            errors.append("channels.related_channels 必须是列表")
        else:
            for idx, ch in enumerate(rel_list):
                ctx = f"channels.related_channels[{idx}]"
                if not isinstance(ch, dict):
                    errors.append(f"{ctx} 必须是字典对象")
                    continue
                if "id" not in ch or not isinstance(ch["id"], str) or not ch["id"].strip():
                    errors.append(f"{ctx} 缺失必要非空字符串 id 字段")
                if "name" not in ch or not isinstance(ch["name"], str) or not ch["name"].strip():
                    errors.append(f"{ctx} 缺失必要非空字符串 name 字段")
                for opt_str in ["channel", "data_path", "app_bundle_id", "app_path"]:
                    if opt_str in ch and not isinstance(ch[opt_str], str):
                        errors.append(f"{ctx}.{opt_str} 必须是字符串")
    return errors


def validate_ghost_rules(ghost_rules: Any) -> List[str]:
    """校验 Schema v1.2 根目录与幽灵项匹配规则 (ghost_rules) 规范"""
    errors = []
    if not isinstance(ghost_rules, dict):
        return [f"ghost_rules 必须是字典对象，收到 {type(ghost_rules).__name__}"]

    if "root_patterns" in ghost_rules:
        patterns = ghost_rules["root_patterns"]
        if not isinstance(patterns, list):
            errors.append("ghost_rules.root_patterns 必须是列表")
        else:
            for idx, pat in enumerate(patterns):
                ctx = f"ghost_rules.root_patterns[{idx}]"
                if not isinstance(pat, dict):
                    errors.append(f"{ctx} 必须是字典对象")
                    continue
                if "regex" not in pat or not isinstance(pat["regex"], str) or not pat["regex"].strip():
                    errors.append(f"{ctx} 缺失必要非空字符串 regex 字段")
                else:
                    try:
                        re.compile(pat["regex"])
                    except re.error as e:
                        errors.append(f"{ctx} 正则表达式语法非法: {pat['regex']} ({e})")

                if "description" not in pat or not isinstance(pat["description"], str) or not pat["description"].strip():
                    errors.append(f"{ctx} 缺失必要非空字符串 description 字段")

                if "risk_level" in pat and pat["risk_level"] not in VALID_RISK_LEVELS:
                    errors.append(f"{ctx} risk_level '{pat['risk_level']}' 非法，必须为 {sorted(VALID_RISK_LEVELS)} 之一")

                if "target_roots" in pat:
                    if not isinstance(pat["target_roots"], list) or not all(isinstance(r, str) for r in pat["target_roots"]):
                        errors.append(f"{ctx}.target_roots 必须是字符串列表")

    return errors


def validate_rule_schema_v12(rule: Any) -> Tuple[bool, List[str]]:
    """
    全量校验单条规则是否完全符合 Rule Schema v1.2 规范
    返回: (is_valid: bool, error_messages: List[str])
    """
    errors: List[str] = []
    if not isinstance(rule, dict):
        return False, [f"规则根对象必须是字典，收到 {type(rule).__name__}"]

    # 1. 必填核心元数据
    rid = rule.get("id")
    if not rid or not isinstance(rid, str):
        errors.append("规则缺失必要 id 字段 (字符串)")
    elif not ID_REGEX.match(rid):
        errors.append(f"规则 id '{rid}' 格式不合法，必须由小写字母、数字和连字符组成 (^[a-z0-9-]+$)")

    name = rule.get("name")
    if not name or not isinstance(name, str) or not name.strip():
        errors.append("规则缺失必要 name 字段 (非空字符串)")

    category = rule.get("category")
    if not category or not isinstance(category, str):
        errors.append("规则缺失必要 category 字段")
    elif category not in VALID_CATEGORIES:
        errors.append(f"category '{category}' 非法，必须为 {sorted(VALID_CATEGORIES)} 之一")

    # 2. 目标分类字典 (targets)
    targets = rule.get("targets")
    if targets is None or not isinstance(targets, dict) or len(targets) == 0:
        errors.append("规则缺失 targets 定义或 targets 为空字典")
    else:
        for cat_name, items in targets.items():
            if cat_name not in VALID_TARGET_CATEGORIES:
                errors.append(f"targets 包含未知分类 '{cat_name}'，合法分类为 {sorted(VALID_TARGET_CATEGORIES)}")
            if not isinstance(items, list):
                errors.append(f"targets.{cat_name} 必须是目标项列表")
            else:
                for idx, it in enumerate(items):
                    item_errs = validate_target_item(it, f"targets.{cat_name}[{idx}]")
                    errors.extend(item_errs)

    # 3. 多通道分支矩阵 (channels, Schema v1.2 新增)
    if "channels" in rule:
        ch_errs = validate_channels(rule["channels"])
        errors.extend(ch_errs)

    # 4. 根目录与幽灵异常规则 (ghost_rules, Schema v1.2 新增)
    if "ghost_rules" in rule:
        gh_errs = validate_ghost_rules(rule["ghost_rules"])
        errors.extend(gh_errs)

    # 5. 存活保护 (protection)
    if "protection" in rule:
        prot = rule["protection"]
        if not isinstance(prot, dict):
            errors.append("protection 必须是字典对象")
        else:
            for p_list in ["process_names", "lock_files"]:
                if p_list in prot and not isinstance(prot[p_list], list):
                    errors.append(f"protection.{p_list} 必须是字符串列表")

    # 6. 安装检测 (detection)
    if "detection" in rule:
        det = rule["detection"]
        if not isinstance(det, dict):
            errors.append("detection 必须是字典对象")
        else:
            for d_list in ["app_bundle_id", "app_paths", "cli_binaries"]:
                if d_list in det and not isinstance(det[d_list], list):
                    errors.append(f"detection.{d_list} 必须是字符串列表")

    # 7. 安全防线配置 (safety)
    if "safety" in rule:
        safe = rule["safety"]
        if not isinstance(safe, dict):
            errors.append("safety 必须是字典对象")
        else:
            for s_bool in ["protect_git_repos", "protect_workspaces"]:
                if s_bool in safe and not isinstance(safe[s_bool], bool):
                    errors.append(f"safety.{s_bool} 必须是布尔值")
            if "exclude_paths" in safe and not isinstance(safe["exclude_paths"], list):
                errors.append("safety.exclude_paths 必须是字符串列表")

    return (len(errors) == 0, errors)
