"""
Sea-Otter Automated Test Suite
验证规则合法性、安全防线拦截机制、扫描引擎判定及系统废纸篓清理。
"""

import os
import shutil
import tempfile
import unittest
import subprocess
import json
import yaml

from sea_otter.scanner import RuleScanner, TargetMatch
from sea_otter.safety import validate_target_safety, contains_workspace_or_repo, normalize_path
from sea_otter.cleaner import SafeCleaner


class TestRules(unittest.TestCase):
    def setUp(self):
        self.scanner = RuleScanner()
        self.rules = self.scanner.load_rules()

    def test_rules_loaded(self):
        self.assertGreaterEqual(len(self.rules), 12, "规则库收录数量应不少于 12 款主流工具")

    def test_rule_schema_fields(self):
        required_keys = {"id", "name", "category", "vendor", "targets"}
        for r in self.rules:
            rule_id = r.get("id")
            for k in required_keys:
                self.assertIn(k, r, f"规则 [{rule_id}] 缺失必要字段: {k}")
            self.assertIsInstance(r["targets"], dict, f"规则 [{rule_id}] targets 必须是字典")


class TestSafetyGuard(unittest.TestCase):
    def test_system_root_protection(self):
        for sys_path in ["/", "/System", "/Library", "/usr", "/usr/bin", "/var", "/etc"]:
            is_safe, reason = validate_target_safety(sys_path)
            self.assertFalse(is_safe, f"系统目录 {sys_path} 应被严格拦截")
            self.assertIn("系统核心根路径", reason)

    def test_user_root_protection(self):
        home = os.path.expanduser("~")
        for user_path in [home, os.path.join(home, "Desktop"), os.path.join(home, "Documents")]:
            is_safe, reason = validate_target_safety(user_path)
            self.assertFalse(is_safe, f"用户主目录 {user_path} 应被严格拦截")

    def test_git_workspace_protection(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            # 创建模拟 git 项目 (使用嵌套目录避免直接命中 Linux 下 /tmp/xxx 的层级过浅保护)
            repo_dir = os.path.join(tmp_dir, "test_repo")
            git_dir = os.path.join(repo_dir, ".git")
            os.makedirs(git_dir)
            is_repo, ind = contains_workspace_or_repo(repo_dir)
            self.assertTrue(is_repo)
            self.assertEqual(ind, ".git")

            is_safe, reason = validate_target_safety(repo_dir)
            self.assertFalse(is_safe, "包含 .git 的目录应被安全防线拦截")
            self.assertIn(".git", reason)

    def test_rule_exclude_paths(self):
        rule_safety = {
            "protect_git_repos": True,
            "exclude_paths": ["~/Projects", "~/Documents"]
        }
        test_path = os.path.expanduser("~/Projects/my-app")
        is_safe, reason = validate_target_safety(test_path, rule_safety=rule_safety)
        self.assertFalse(is_safe)
        self.assertIn("严格排除路径", reason)


class TestSafeCleaner(unittest.TestCase):
    def setUp(self):
        self.cleaner = SafeCleaner(use_trash=True)
        self.test_dir = tempfile.mkdtemp(prefix="sea_otter_test_")

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_dry_run_does_not_delete(self):
        dummy_file = os.path.join(self.test_dir, "cache.tmp")
        with open(dummy_file, "w") as f:
            f.write("test cache data")

        target = TargetMatch(
            category="caches",
            raw_path=dummy_file,
            resolved_path=dummy_file,
            description="测试缓存",
            size_bytes=len("test cache data"),
            file_count=1,
            contains_secrets=False,
            is_model_weight=False,
            default_selected=True,
            is_safe=True,
            safety_reason="安全"
        )

        res = self.cleaner.clean_target(target, dry_run=True)
        self.assertTrue(res.success)
        self.assertTrue(res.is_dry_run)
        self.assertTrue(os.path.exists(dummy_file), "Dry-run 模式下文件不应被删除")

    def test_secret_protection_by_default(self):
        dummy_secret = os.path.join(self.test_dir, "token.json")
        with open(dummy_secret, "w") as f:
            f.write('{"token": "secret123"}')

        target = TargetMatch(
            category="credentials",
            raw_path=dummy_secret,
            resolved_path=dummy_secret,
            description="测试凭据",
            size_bytes=20,
            file_count=1,
            contains_secrets=True,
            is_model_weight=False,
            default_selected=True,
            is_safe=True,
            safety_reason="安全"
        )

        # 未传 force_secret 时应被跳过
        res = self.cleaner.clean_target(target, dry_run=False, force_secret=False)
        self.assertFalse(res.success)
        self.assertEqual(res.method_used, "skipped_secret")
        self.assertTrue(os.path.exists(dummy_secret), "敏感文件未明确授权不应被清理")

    def test_safe_trash_in_home(self):
        # 在家目录下建立测试文件测试 trash
        home_test_file = os.path.expanduser("~/.sea_otter_test_trash.tmp")
        try:
            with open(home_test_file, "w") as f:
                f.write("trash me safely")

            target = TargetMatch(
                category="caches",
                raw_path=home_test_file,
                resolved_path=home_test_file,
                description="废纸篓测试",
                size_bytes=15,
                file_count=1,
                contains_secrets=False,
                is_model_weight=False,
                default_selected=True,
                is_safe=True,
                safety_reason="安全"
            )

            res = self.cleaner.clean_target(target, dry_run=False)
            self.assertTrue(res.success)
            self.assertFalse(os.path.exists(home_test_file), "移入废纸篓后原路径文件应已不存在")
        finally:
            if os.path.exists(home_test_file):
                os.remove(home_test_file)


class TestCLIExecution(unittest.TestCase):
    def test_cli_rules_list(self):
        proc = subprocess.run(["sea-otter", "rules", "list"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("当前规则库共收录", proc.stdout)

    def test_cli_rules_validate(self):
        proc = subprocess.run(["sea-otter", "rules", "validate"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("条规则完全合规", proc.stdout)

    def test_cli_scan_json(self):
        proc = subprocess.run(["sea-otter", "scan", "--json"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertIsInstance(data, list)
        self.assertGreaterEqual(len(data), 12)

    def test_cli_clean_dry_run(self):
        proc = subprocess.run(["sea-otter", "clean", "--dry-run"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("Dry-run 只读模式", proc.stdout)


if __name__ == "__main__":
    unittest.main()
