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
import sqlite3
import plistlib
import yaml

from sea_otter.scanner import (
    RuleScanner,
    TargetMatch,
    AIModelScanner,
    RootOrphanScanner,
    ChannelRedundancyScanner,
    AssociationEngine,
    SecretLeakAuditor,
)
from sea_otter.safety import validate_target_safety, contains_workspace_or_repo, normalize_path, RiskLevel
from sea_otter.cleaner import SafeCleaner, QuarantineManager, QUARANTINE_DIR_PREFIX
from sea_otter.validator import validate_rule_schema_v12


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

    def test_system_redline_vault_protection(self):
        """测试系统红线库 (System Redline Vault) 硬阻断"""
        home = os.path.expanduser("~")
        redline_cases = [
            os.path.join(home, "Library/Application Support/com.apple.TCC"),
            os.path.join(home, "Library/Application Support/com.apple.TCC/TCC.db"),
            os.path.join(home, "Library/Application Support/AddressBook"),
            os.path.join(home, "Library/Application Support/CallHistoryDB"),
            os.path.join(home, "Library/Application Support/CloudDocs"),
            os.path.join(home, "Library/Application Support/com.apple.sharedfilelist"),
        ]
        for rp in redline_cases:
            is_safe, reason = validate_target_safety(rp)
            self.assertFalse(is_safe, f"系统红线路径 {rp} 应被硬编码阻断")
            self.assertIn("系统红线", reason)

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


class TestRiskMatrix(unittest.TestCase):
    """测试四级安全防护矩阵 (L1 ~ L4) 判定逻辑"""

    def test_l1_zero_impact_junk(self):
        from sea_otter.safety import assess_risk_level, RiskLevel
        home = os.path.expanduser("~")
        # Bug 幽灵目录、散落锁文件等
        null_dir = os.path.join(home, "Library/Application Support/(null)")
        lvl, is_safe, reason = assess_risk_level(null_dir, software_status="orphaned")
        self.assertEqual(lvl, RiskLevel.L1_SAFE)
        self.assertTrue(is_safe)
        self.assertIn("极低风险", reason)

        lock_file = os.path.join(home, "Library/Application Support/.ACCC_Lock")
        lvl2, is_safe2, _ = assess_risk_level(lock_file, software_status="orphaned")
        self.assertEqual(lvl2, RiskLevel.L1_SAFE)
        self.assertTrue(is_safe2)

    def test_l2_orphaned_apps(self):
        from sea_otter.safety import assess_risk_level, RiskLevel
        home = os.path.expanduser("~")
        orphan_dir = os.path.join(home, "Library/Application Support/UninstalledApp")
        lvl, is_safe, reason = assess_risk_level(orphan_dir, software_status="orphaned")
        self.assertEqual(lvl, RiskLevel.L2_ORPHAN)
        self.assertTrue(is_safe)
        self.assertIn("明确已卸载", reason)

    def test_l3_in_use_bloatware(self):
        from sea_otter.safety import assess_risk_level, RiskLevel
        home = os.path.expanduser("~")
        active_cache = os.path.join(home, "Library/Caches/com.google.Chrome")
        lvl, is_safe, reason = assess_risk_level(active_cache, software_status="installed")
        self.assertEqual(lvl, RiskLevel.L3_IN_USE)
        self.assertTrue(is_safe)
        self.assertIn("在用软件减负", reason)

        # 本地模型权重
        model_dir = os.path.join(home, ".ollama/models")
        lvl2, is_safe2, _ = assess_risk_level(model_dir, software_status="installed", is_model_weight=True)
        self.assertEqual(lvl2, RiskLevel.L3_IN_USE)

    def test_l4_protected_system_and_running(self):
        from sea_otter.safety import assess_risk_level, RiskLevel
        home = os.path.expanduser("~")
        
        # 1. 系统红线服务 -> L4
        tcc_path = os.path.join(home, "Library/Application Support/com.apple.TCC")
        lvl, is_safe, _ = assess_risk_level(tcc_path, software_status="orphaned")
        self.assertEqual(lvl, RiskLevel.L4_DANGER)
        self.assertFalse(is_safe)

        # 2. 软件运行中 -> L4
        running_path = os.path.join(home, "Library/Application Support/RunningApp")
        lvl2, is_safe2, _ = assess_risk_level(running_path, software_status="running")
        self.assertEqual(lvl2, RiskLevel.L4_DANGER)
        self.assertFalse(is_safe2)



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
            self.assertFalse(os.path.exists(home_test_file), "移入废纸篓/隔离区后原路径文件应已不存在")
        finally:
            if os.path.exists(home_test_file):
                os.remove(home_test_file)
            if self.cleaner.last_quarantine_dir and os.path.exists(self.cleaner.last_quarantine_dir):
                shutil.rmtree(self.cleaner.last_quarantine_dir, ignore_errors=True)

    def test_l4_target_strictly_blocked(self):
        """测试 L4 绝对系统红线被 cleaner 强制拦截"""
        home = os.path.expanduser("~")
        tcc_path = os.path.join(home, "Library/Application Support/com.apple.TCC")
        target = TargetMatch(
            category="preferences",
            raw_path=tcc_path,
            resolved_path=tcc_path,
            description="TCC 权限库",
            size_bytes=1024,
            file_count=1,
            contains_secrets=False,
            is_model_weight=False,
            default_selected=False,
            is_safe=False,
            safety_reason="触发系统红线硬白名单保护",
            risk_level="L4_DANGER"
        )
        res = self.cleaner.clean_target(target, dry_run=False)
        self.assertFalse(res.success)
        self.assertEqual(res.method_used, "blocked")
        self.assertIn("L4 绝对系统红线", res.message)


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
        # 校验返回数据中的 targets 包含 risk_level 字段且符合 L1~L4 规范
        for tool in data:
            for t in tool.get("targets", []):
                self.assertIn("risk_level", t)
                self.assertIn(t["risk_level"], ["L1_SAFE", "L2_ORPHAN", "L3_IN_USE", "L4_DANGER"])

    def test_cli_clean_dry_run(self):
        proc = subprocess.run(["sea-otter", "clean", "--dry-run"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("Dry-run 只读模式", proc.stdout)

    def test_cli_scan_models_flag(self):
        proc = subprocess.run(["sea-otter", "scan", "-m", "--json"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertIsInstance(data, list)
        for tool in data:
            for t in tool.get("targets", []):
                self.assertTrue(t.get("is_model_weight") or t.get("category") == "ai_models")

    def test_cli_clean_models_dry_run(self):
        proc = subprocess.run(["sea-otter", "clean", "google-chrome", "--models", "--dry-run"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("Dry-run 只读模式", proc.stdout)

    def test_cli_scan_slim_flag(self):
        proc = subprocess.run(["sea-otter", "scan", "cherry-studio", "--slim", "--json"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertIsInstance(data, list)
        for tool in data:
            for t in tool.get("targets", []):
                self.assertNotIn(t.get("category"), ["credentials", "configs"])
                self.assertFalse(any(t["path"].endswith(ext) for ext in [".sqlite", ".db", ".plist"]))

    def test_cli_clean_slim_dry_run(self):
        proc = subprocess.run(["sea-otter", "clean", "cherry-studio", "--slim", "--dry-run"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("安全减负模式", proc.stdout)
        self.assertIn("Dry-run 只读模式", proc.stdout)

    def test_cli_scan_ghosts_flag(self):
        proc = subprocess.run(["sea-otter", "scan", "--ghosts", "--json"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertIsInstance(data, list)
        for tool in data:
            for t in tool.get("targets", []):
                self.assertTrue(
                    t.get("ghost_type") is not None
                    or t.get("category") in ["ghost", "skeleton", "locks", "temp_images"]
                )
                self.assertEqual(t.get("risk_level"), "L1_SAFE")

    def test_cli_clean_ghosts_dry_run(self):
        proc = subprocess.run(["sea-otter", "clean", "--ghosts", "--dry-run"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("根目录散落与幽灵清理模式", proc.stdout)
        self.assertIn("Dry-run 只读模式", proc.stdout)

    def test_cli_scan_channels_flag(self):
        proc = subprocess.run(["sea-otter", "scan", "--channels", "--json"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertIsInstance(data, list)
        for tool in data:
            for t in tool.get("targets", []):
                self.assertIsNotNone(t.get("channel_name"))
                self.assertGreaterEqual(t.get("inactive_days", 0), 90)

    def test_cli_clean_channels_dry_run(self):
        proc = subprocess.run(["sea-otter", "clean", "--channels", "--dry-run"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("多通道发布孤岛清理模式", proc.stdout)
        self.assertIn("Dry-run 只读模式", proc.stdout)

    def test_cli_rollback_list(self):
        proc = subprocess.run(["sea-otter", "rollback", "--list", "--json"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertIsInstance(data, list)

    def test_cli_scan_associations_flag(self):
        proc = subprocess.run(["sea-otter", "scan", "-A", "--json"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertIsInstance(data, list)
        for tool in data:
            for t in tool.get("targets", []):
                self.assertIn(t.get("association_tier"), [1, 2, 3])
                self.assertEqual(t.get("risk_level"), "L2_ORPHAN")

    def test_cli_clean_associations_dry_run(self):
        proc = subprocess.run(["sea-otter", "clean", "-A", "--dry-run"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("三级反向映射孤儿清理模式", proc.stdout)
        self.assertIn("Dry-run 只读模式", proc.stdout)

    def test_cli_scan_secrets_flag(self):
        proc = subprocess.run(["sea-otter", "scan", "-S", "--json"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertIsInstance(data, list)
        for tool in data:
            for t in tool.get("targets", []):
                self.assertTrue(t.get("contains_secrets"))
                self.assertIn("secret_findings", t)


class TestFineGrainedSlimming(unittest.TestCase):
    """测试细粒度子项目分解与安全减负裁剪机制"""

    def setUp(self):
        self.scanner = RuleScanner()

    def test_cherry_studio_rule_structure(self):
        rules = self.scanner.load_rules(filter_ids=["cherry-studio"])
        self.assertEqual(len(rules), 1)
        r = rules[0]
        targets = r.get("targets", {})
        
        # 验证包含本地向量库与附件细分项
        self.assertIn("ai_models", targets)
        self.assertIn("data_and_history", targets)
        self.assertIn("caches", targets)

        paths = [item["path"] for cat in targets.values() for item in cat]
        self.assertTrue(any("IndexedDB" in p for p in paths), "必须收录 IndexedDB 向量嵌入库")
        self.assertTrue(any("Data/Files" in p for p in paths), "必须收录 Data/Files 会话大附件")
        self.assertTrue(any("Data/KnowledgeBase" in p for p in paths), "必须收录 KnowledgeBase 知识库向量索引")

        # 验证核心数据库在排除名单中
        exclude_paths = r.get("safety", {}).get("exclude_paths", [])
        self.assertTrue(any("cherrystudio.sqlite" in ep for ep in exclude_paths), "核心会话 SQLite 必须在排除免疫名单中")
        self.assertTrue(any("agents.db" in ep for ep in exclude_paths), "助手数据库必须在排除免疫名单中")

    def test_sub_targets_expansion_in_scan(self):
        dummy_rule = {
            "id": "test-slim-tool",
            "name": "Test Slim Tool",
            "category": "desktop-agent",
            "targets": {
                "data_and_history": [
                    {
                        "path": "/dummy/parent",
                        "description": "父目录",
                        "sub_targets": [
                            {
                                "path": "/dummy/parent/attachments",
                                "description": "会话大附件",
                                "prunable": True
                            }
                        ]
                    }
                ]
            }
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            parent_dir = os.path.join(tmp_dir, "parent")
            attach_dir = os.path.join(parent_dir, "attachments")
            os.makedirs(attach_dir)
            with open(os.path.join(attach_dir, "file.bin"), "wb") as f:
                f.write(b"x" * 1024)

            dummy_rule["targets"]["data_and_history"][0]["path"] = parent_dir
            dummy_rule["targets"]["data_and_history"][0]["sub_targets"][0]["path"] = attach_dir

            report = self.scanner.scan_tool(dummy_rule)
            target_paths = [t.resolved_path for t in report.targets]
            self.assertIn(attach_dir, target_paths, "子项目应被 scan_tool 递归解析")
            attach_target = next(t for t in report.targets if t.resolved_path == attach_dir)
            self.assertTrue(attach_target.prunable)
            self.assertEqual(attach_target.sub_target_of, parent_dir)


class TestAIModelScanner(unittest.TestCase):
    def test_model_file_extensions(self):
        cases = [
            ("model.gguf", "GGUF"),
            ("weights.safetensors", "SafeTensors"),
            ("encoder.onnx", "ONNX"),
            ("checkpoint.pt", "PyTorch Checkpoint"),
            ("model.tflite", "TensorFlow Lite"),
            ("classifier.mlmodel", "CoreML"),
            ("weights.bin", "Binary Weights"),
        ]
        for fname, expected_fmt in cases:
            is_model, fmt = AIModelScanner.is_model_file(f"/dummy/path/{fname}")
            self.assertTrue(is_model, f"文件 {fname} 应被识别为模型")
            self.assertEqual(fmt, expected_fmt)

    def test_gguf_magic_header(self):
        with tempfile.NamedTemporaryFile(suffix=".tmp") as tmp:
            tmp.write(b"GGUF\x00\x00\x00\x03some_tensor_bytes")
            tmp.flush()
            is_model, fmt = AIModelScanner.is_model_file(tmp.name)
            self.assertTrue(is_model)
            self.assertEqual(fmt, "GGUF")

    def test_pth_python_vs_pytorch(self):
        # 1. 文本 .pth (Python path file)
        with tempfile.NamedTemporaryFile(suffix=".pth", mode="w") as tmp_txt:
            tmp_txt.write("import sys; sys.path.insert(0, '/some/dir')\n")
            tmp_txt.flush()
            is_model, _ = AIModelScanner.is_model_file(tmp_txt.name)
            self.assertFalse(is_model, "Python site-packages 路径配置 .pth 不应被误判为模型权重")

        # 2. 二进制 .pth (PyTorch zip or pickle)
        with tempfile.NamedTemporaryFile(suffix=".pth", mode="wb") as tmp_bin:
            tmp_bin.write(b"PK\x03\x04pytorch_archive_bytes")
            tmp_bin.flush()
            is_model, fmt = AIModelScanner.is_model_file(tmp_bin.name)
            self.assertTrue(is_model, "包含 PK 头的 PyTorch .pth 应被识别为模型权重")
            self.assertEqual(fmt, "PyTorch Checkpoint")

    def test_chrome_optguide_detection(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chrome_opt_dir = os.path.join(tmp_dir, "OptGuideOnDeviceModel", "version_123")
            os.makedirs(chrome_opt_dir)
            manifest_file = os.path.join(chrome_opt_dir, "manifest.json")
            with open(manifest_file, "w") as f:
                json.dump({"BaseModelSpec": {"name": "v3Nano"}}, f)
            weights_file = os.path.join(chrome_opt_dir, "weights.bin")
            with open(weights_file, "wb") as f:
                f.write(b"dummy_weights" * 100)

            res = AIModelScanner.inspect_path(chrome_opt_dir)
            self.assertTrue(res.is_model_weight)
            self.assertIn("Gemini Nano", res.model_name)
            self.assertIn("v3Nano", res.model_name)
            self.assertEqual(res.model_files_count, 1)

    def test_ignore_virtualenv_in_inspect(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            venv_dir = os.path.join(tmp_dir, "my_project", ".venv", "site-packages")
            os.makedirs(venv_dir)
            dummy_onnx = os.path.join(venv_dir, "library_model.onnx")
            with open(dummy_onnx, "wb") as f:
                f.write(b"onnx_content")

            project_dir = os.path.join(tmp_dir, "my_project")
            res = AIModelScanner.inspect_path(project_dir)
            self.assertFalse(res.is_model_weight, "虚拟环境内部库的模型不应导致整个项目目录被误判为端侧模型权重资产")


class TestRuleSchemaV12(unittest.TestCase):
    """测试 Rule Schema v1.2 规范与字段完整性校验器"""

    def setUp(self):
        self.scanner = RuleScanner()
        self.rules = self.scanner.load_rules()

    def test_all_rules_pass_v12_validator(self):
        self.assertGreaterEqual(len(self.rules), 19, "收录规则数量应不少于 19 款")
        loaded_ids = {r.get("id") for r in self.rules}
        for expected_id in ["google-chrome", "microsoft-edge", "wechat-devtools", "lark-and-steam", "vscode"]:
            self.assertIn(expected_id, loaded_ids, f"应收录高频规则 {expected_id}")
        for r in self.rules:
            is_valid, errors = validate_rule_schema_v12(r)
            self.assertTrue(is_valid, f"规则 [{r.get('id')}] 未通过 Schema v1.2 校验: {errors}")

    def test_invalid_rule_id(self):
        invalid_rule = {
            "id": "Invalid_ID_Uppercase",
            "name": "Invalid Tool",
            "category": "ide",
            "targets": {"caches": [{"path": "/a", "description": "desc"}]}
        }
        is_valid, errors = validate_rule_schema_v12(invalid_rule)
        self.assertFalse(is_valid)
        self.assertTrue(any("id" in err for err in errors))

    def test_invalid_category(self):
        invalid_rule = {
            "id": "valid-id",
            "name": "Tool",
            "category": "invalid-category-xyz",
            "targets": {"caches": [{"path": "/a", "description": "desc"}]}
        }
        is_valid, errors = validate_rule_schema_v12(invalid_rule)
        self.assertFalse(is_valid)
        self.assertTrue(any("category" in err for err in errors))

    def test_channels_validation(self):
        valid_rule = {
            "id": "browser-tool",
            "name": "Browser Tool",
            "category": "browser",
            "channels": {
                "current_channel": "stable",
                "related_channels": [
                    {"id": "browser-beta", "name": "Browser Beta", "channel": "beta"}
                ]
            },
            "targets": {"caches": [{"path": "/a", "description": "desc"}]}
        }
        is_valid, errors = validate_rule_schema_v12(valid_rule)
        self.assertTrue(is_valid, errors)

        invalid_rule = {
            "id": "browser-tool",
            "name": "Browser Tool",
            "category": "browser",
            "channels": {
                "related_channels": [
                    {"id": "missing-name"} # 缺少 name
                ]
            },
            "targets": {"caches": [{"path": "/a", "description": "desc"}]}
        }
        is_valid, errors = validate_rule_schema_v12(invalid_rule)
        self.assertFalse(is_valid)
        self.assertTrue(any("name" in err for err in errors))

    def test_ghost_rules_validation(self):
        valid_rule = {
            "id": "ghost-tool",
            "name": "Ghost Tool",
            "category": "runtime",
            "ghost_rules": {
                "root_patterns": [
                    {
                        "regex": r"^\(null\)$",
                        "description": "空指针幽灵目录",
                        "risk_level": "L1_SAFE"
                    }
                ]
            },
            "targets": {"caches": [{"path": "/a", "description": "desc"}]}
        }
        is_valid, errors = validate_rule_schema_v12(valid_rule)
        self.assertTrue(is_valid, errors)

        invalid_regex_rule = {
            "id": "ghost-tool",
            "name": "Ghost Tool",
            "category": "runtime",
            "ghost_rules": {
                "root_patterns": [
                    {
                        "regex": r"^([a-z$",  # 非法未闭合正则
                        "description": "非法正则"
                    }
                ]
            },
            "targets": {"caches": [{"path": "/a", "description": "desc"}]}
        }
        is_valid, errors = validate_rule_schema_v12(invalid_regex_rule)
        self.assertFalse(is_valid)
        self.assertTrue(any("正则" in err for err in errors))


class TestRootOrphanScanner(unittest.TestCase):
    """测试 Task 04: 跨平台代码 Bug 与根目录散落探测引擎 (RootOrphanScanner)"""

    def _make_root(self, tmp_dir: str) -> str:
        # 使用深层路径避免触发根路径层级过浅保护 (<= 2 层)
        root = os.path.join(tmp_dir, "Users", "tester", "Library", "Application Support")
        os.makedirs(root, exist_ok=True)
        return root

    def test_abnormal_bug_names_detection(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = self._make_root(tmp_dir)
            bug_names = ["(null)", "undefined", "null", "none", "   "]
            for name in bug_names:
                p = os.path.join(root, name)
                os.makedirs(p)
                with open(os.path.join(p, "orphan.dat"), "wb") as f:
                    f.write(b"x" * 16)

            report = RootOrphanScanner(roots=[root]).scan()
            self.assertEqual(report.tool_id, "root-orphans")
            self.assertEqual(report.status, "orphaned")
            found_names = {os.path.basename(t.resolved_path) for t in report.targets}
            self.assertEqual(found_names, set(bug_names))
            for t in report.targets:
                self.assertEqual(t.risk_level, RiskLevel.L1_SAFE.value)
                self.assertTrue(t.is_safe)
                self.assertTrue(t.default_selected)
                self.assertEqual(t.ghost_type, "bug_name")
                self.assertEqual(t.category, "ghost")

    def test_scattered_files_and_dead_locks_detection(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = self._make_root(tmp_dir)
            files = {
                "2052-TM10002069.png": "scattered_file",
                "default.store": "scattered_file",
                ".ACCC_Lock": "dead_lock",
                ".ADCS_Lock": "dead_lock",
                "legacy.lock": "dead_lock",
            }
            for fname in files:
                with open(os.path.join(root, fname), "wb") as f:
                    f.write(b"dummy")

            report = RootOrphanScanner(roots=[root]).scan()
            by_name = {os.path.basename(t.resolved_path): t for t in report.targets}
            self.assertEqual(set(by_name.keys()), set(files.keys()))
            for fname, expected_type in files.items():
                t = by_name[fname]
                self.assertEqual(t.ghost_type, expected_type)
                self.assertEqual(t.risk_level, RiskLevel.L1_SAFE.value)
                self.assertTrue(t.is_safe)
                self.assertTrue(t.default_selected)

    def test_skeleton_empty_dirs_detection_and_boundaries(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = self._make_root(tmp_dir)

            # 1. 纯空嵌套骨架目录 (< 64KB 且子孙全空) -> 应捕获
            pro_apps = os.path.join(root, "ProApps", "Custom LUTs", "Presets")
            os.makedirs(pro_apps)

            # 2. 仅包含小体积 .DS_Store 的空骨架目录 -> 应捕获
            finder_empty = os.path.join(root, "OldEmptyPlugin")
            os.makedirs(os.path.join(finder_empty, "Sub"))
            with open(os.path.join(finder_empty, ".DS_Store"), "wb") as f:
                f.write(b"\x00" * 4096)

            # 3. 含真实业务文件的正常目录 (即使体积很小) -> 不应被误判
            real_app = os.path.join(root, "RealApp")
            os.makedirs(real_app)
            with open(os.path.join(real_app, "settings.json"), "w") as f:
                f.write("{}")

            # 4. 体积 >= 64KB 的目录 (即使仅有 .DS_Store) -> 不应被误判为骨架空目录
            oversized_ds = os.path.join(root, "LargeMetadataDir")
            os.makedirs(oversized_ds)
            with open(os.path.join(oversized_ds, ".DS_Store"), "wb") as f:
                f.write(b"\x00" * (65 * 1024))

            # 5. 含有 .git 的空工作区目录 -> 强制免疫不捕获
            git_ws = os.path.join(root, "UserRepo")
            os.makedirs(os.path.join(git_ws, ".git"))

            report = RootOrphanScanner(roots=[root]).scan()
            found_names = {os.path.basename(t.resolved_path) for t in report.targets}
            self.assertEqual(found_names, {"ProApps", "OldEmptyPlugin"})
            for t in report.targets:
                self.assertEqual(t.ghost_type, "skeleton_dir")
                self.assertEqual(t.category, "skeleton")
                self.assertEqual(t.risk_level, RiskLevel.L1_SAFE.value)
                self.assertLess(t.size_bytes, RootOrphanScanner.SKELETON_MAX_BYTES)

    def test_system_redline_and_native_dirs_never_flagged(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = self._make_root(tmp_dir)
            for protected_name in [
                "com.apple.TCC",
                "com.apple.spotlight",
                "AskPermission",
                "CoreParsec",
                "AddressBook",
                "Preview",
                "System Preferences",
                "TrustedPeersHelper",
                "accountsd",
                ".DS_Store",
                ".localized",
            ]:
                p = os.path.join(root, protected_name)
                if protected_name in [".DS_Store", ".localized"]:
                    with open(p, "wb") as f:
                        f.write(b"")
                else:
                    os.makedirs(p)

            report = RootOrphanScanner(roots=[root]).scan()
            self.assertEqual(len(report.targets), 0, "系统红线与 macOS 原生空目录绝不应被判定为幽灵残留")
            self.assertEqual(report.status, "clean")

    def test_rule_ghost_patterns_evaluation(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chrome_dir = os.path.join(tmp_dir, "Users", "tester", "Library", "Application Support", "Google", "Chrome")
            os.makedirs(chrome_dir)
            sock = os.path.join(chrome_dir, ".org.chromium.Chromium.XYZ123")
            with open(sock, "wb") as f:
                f.write(b"")

            rule = {
                "id": "mock-chrome",
                "name": "Mock Chrome",
                "category": "browser",
                "targets": {"caches": [{"path": os.path.join(chrome_dir, "NonExistentCache"), "description": "cache"}]},
                "ghost_rules": {
                    "root_patterns": [
                        {
                            "regex": r"^\.org\.chromium\.Chromium\..*$",
                            "description": "Chromium 临时残留套接字",
                            "risk_level": "L1_SAFE",
                            "target_roots": [chrome_dir],
                        }
                    ]
                },
            }
            report = RuleScanner().scan_tool(rule)
            self.assertEqual(len(report.targets), 1)
            t = report.targets[0]
            self.assertEqual(t.resolved_path, sock)
            self.assertEqual(t.ghost_type, "rule_ghost")
            self.assertEqual(t.risk_level, RiskLevel.L1_SAFE.value)
            self.assertTrue(t.default_selected)

    def test_l1_root_orphan_dry_run_and_clean(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = self._make_root(tmp_dir)
            null_dir = os.path.join(root, "(null)")
            os.makedirs(null_dir)
            report = RootOrphanScanner(roots=[root]).scan()
            self.assertEqual(len(report.targets), 1)

            cleaner = SafeCleaner(use_trash=True)
            dry_results = cleaner.clean_targets(report.targets, dry_run=True)
            self.assertEqual(len(dry_results), 1)
            self.assertTrue(dry_results[0].success)
            self.assertTrue(os.path.exists(null_dir))


class TestChannelRedundancyScanner(unittest.TestCase):
    """测试 Task 05: 浏览器与 IDE 多通道发布孤岛检测引擎 (ChannelRedundancyScanner)"""

    def _set_mtime(self, path: str, ts: float):
        os.utime(path, (ts, ts))

    def test_edge_and_chrome_rules_have_valid_channels(self):
        scanner = RuleScanner()
        rules = scanner.load_rules(filter_ids=["microsoft-edge", "google-chrome"])
        self.assertEqual(len(rules), 2)
        for r in rules:
            is_valid, errors = validate_rule_schema_v12(r)
            self.assertTrue(is_valid, f"{r['id']} 校验失败: {errors}")
            self.assertIn("channels", r)
            self.assertGreaterEqual(len(r["channels"]["related_channels"]), 2)

    def test_channel_cross_check_detects_stale_orphan_and_installed(self):
        now = 1_800_000_000.0
        recent_ts = now - 2 * 86400        # 2 天前活跃
        stale_120d_ts = now - 120 * 86400  # 120 天未启动 (> 90 天)
        active_15d_ts = now - 15 * 86400   # 15 天前启动 (< 90 天，不应误报)

        with tempfile.TemporaryDirectory() as tmp_dir:
            base = os.path.join(tmp_dir, "Users", "tester", "Library", "Application Support")
            cache_base = os.path.join(tmp_dir, "Users", "tester", "Library", "Caches")
            stable_data = os.path.join(base, "Microsoft Edge")
            canary_data = os.path.join(base, "Microsoft Edge Canary")
            canary_cache = os.path.join(cache_base, "Microsoft Edge Canary")
            dev_data = os.path.join(base, "Microsoft Edge Dev")
            dev_app = os.path.join(tmp_dir, "Applications", "Microsoft Edge Dev.app")
            beta_data = os.path.join(base, "Microsoft Edge Beta")

            for d in [stable_data, canary_data, canary_cache, dev_data, dev_app, beta_data]:
                os.makedirs(d, exist_ok=True)

            # 写入占位文件并精确设定时间戳
            stable_state = os.path.join(stable_data, "Local State")
            with open(stable_state, "w") as f:
                f.write("{}")
            self._set_mtime(stable_state, recent_ts)
            self._set_mtime(stable_data, recent_ts)

            canary_file = os.path.join(canary_data, "History")
            with open(canary_file, "wb") as f:
                f.write(b"x" * 2048)
            self._set_mtime(canary_file, stale_120d_ts)
            self._set_mtime(canary_data, stale_120d_ts)

            canary_cache_file = os.path.join(canary_cache, "cache.bin")
            with open(canary_cache_file, "wb") as f:
                f.write(b"c" * 4096)
            self._set_mtime(canary_cache_file, stale_120d_ts)
            self._set_mtime(canary_cache, stale_120d_ts)

            dev_file = os.path.join(dev_data, "Preferences")
            with open(dev_file, "w") as f:
                f.write("{}")
            self._set_mtime(dev_file, stale_120d_ts)
            self._set_mtime(dev_data, stale_120d_ts)

            beta_file = os.path.join(beta_data, "Preferences")
            with open(beta_file, "w") as f:
                f.write("{}")
            self._set_mtime(beta_file, active_15d_ts)
            self._set_mtime(beta_data, active_15d_ts)

            mock_rule = {
                "id": "microsoft-edge",
                "name": "Microsoft Edge",
                "category": "browser",
                "protection": {"lock_files": [os.path.join(stable_data, "SingletonLock")]},
                "channels": {
                    "current_channel": "stable",
                    "related_channels": [
                        {
                            "id": "edge-canary",
                            "name": "Microsoft Edge Canary",
                            "channel": "canary",
                            "data_path": canary_data,
                            "app_path": os.path.join(tmp_dir, "Applications", "NonExistent Canary.app"),
                        },
                        {
                            "id": "edge-dev",
                            "name": "Microsoft Edge Dev",
                            "channel": "dev",
                            "data_path": dev_data,
                            "app_path": dev_app,
                        },
                        {
                            "id": "edge-beta",
                            "name": "Microsoft Edge Beta",
                            "channel": "beta",
                            "data_path": beta_data,
                            "app_path": os.path.join(tmp_dir, "Applications", "NonExistent Beta.app"),
                        },
                    ],
                },
                "targets": {"caches": [{"path": canary_cache, "description": "cache"}]},
            }

            report = ChannelRedundancyScanner(rules=[mock_rule], now=now).scan()
            self.assertEqual(report.tool_id, "channel-redundancy")
            self.assertEqual(report.status, "orphaned")
            by_path = {t.resolved_path: t for t in report.targets}

            # Canary (.app 已卸载 + 120天未用) -> L2_ORPHAN + 伴随缓存
            self.assertIn(canary_data, by_path)
            self.assertIn(canary_cache, by_path)
            self.assertEqual(by_path[canary_data].risk_level, RiskLevel.L2_ORPHAN.value)
            self.assertTrue(by_path[canary_data].default_selected)
            self.assertEqual(by_path[canary_data].channel_name, "canary")
            self.assertEqual(by_path[canary_data].inactive_days, 120)

            # Dev (.app 仍在 + 120天未用) -> L3_IN_USE (需确认或 --channels)
            self.assertIn(dev_data, by_path)
            self.assertEqual(by_path[dev_data].risk_level, RiskLevel.L3_IN_USE.value)
            self.assertFalse(by_path[dev_data].default_selected)

            # Beta (15天前用过) -> 不应被判定为孤岛
            self.assertNotIn(beta_data, by_path)

    def test_channel_cross_check_skips_when_stable_inactive_or_test_running(self):
        now = 1_800_000_000.0
        stale_ts = now - 120 * 86400

        with tempfile.TemporaryDirectory() as tmp_dir:
            base = os.path.join(tmp_dir, "Users", "tester", "Library", "Application Support")
            stable_data = os.path.join(base, "Google", "Chrome")
            canary_data = os.path.join(base, "Google", "Chrome Canary")
            os.makedirs(stable_data)
            os.makedirs(canary_data)
            self._set_mtime(stable_data, stale_ts)
            self._set_mtime(canary_data, stale_ts)

            mock_rule = {
                "id": "google-chrome",
                "name": "Google Chrome",
                "category": "browser",
                "protection": {"lock_files": [os.path.join(stable_data, "SingletonLock")]},
                "channels": {
                    "current_channel": "stable",
                    "related_channels": [
                        {"id": "chrome-canary", "name": "Chrome Canary", "channel": "canary", "data_path": canary_data}
                    ],
                },
                "targets": {"caches": [{"path": canary_data, "description": "c"}]},
            }

            # 1. Stable 也超过 30 天未活跃 -> Cross-Check 不触发
            report1 = ChannelRedundancyScanner(rules=[mock_rule], now=now).scan()
            self.assertEqual(len(report1.targets), 0)

            # 2. Stable 恢复活跃，但 Canary 持有 SingletonLock (正在运行) -> 保护跳过
            self._set_mtime(stable_data, now - 86400)
            with open(os.path.join(canary_data, "SingletonLock"), "w") as f:
                f.write("lock")
            self._set_mtime(canary_data, stale_ts)
            report2 = ChannelRedundancyScanner(rules=[mock_rule], now=now).scan()
            self.assertEqual(len(report2.targets), 0)


class TestQuarantineRollback(unittest.TestCase):
    """测试 Task 06: 原子隔离区与一键无损回滚系统 (Quarantine & Rollback)"""

    def _make_workspace(self, tmp_dir: str):
        app_support = os.path.join(tmp_dir, "Users", "tester", "Library", "Application Support")
        trash_dir = os.path.join(tmp_dir, "Users", "tester", ".Trash")
        os.makedirs(app_support, exist_ok=True)
        os.makedirs(trash_dir, exist_ok=True)
        return app_support, trash_dir

    def test_quarantine_manifest_and_full_rollback(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            app_support, trash_dir = self._make_workspace(tmp_dir)

            # 创建测试残留：Skype 目录、散落 png 文件、以及两个同名的 Cache 目录
            skype_dir = os.path.join(app_support, "Skype")
            os.makedirs(os.path.join(skype_dir, "Profile"))
            with open(os.path.join(skype_dir, "Profile", "db.dat"), "wb") as f:
                f.write(b"skype_data_123")

            png_file = os.path.join(app_support, "2052-TM10002069.png")
            with open(png_file, "wb") as f:
                f.write(b"png_bytes")

            cache_a = os.path.join(app_support, "AppA", "Cache")
            cache_b = os.path.join(app_support, "AppB", "Cache")
            os.makedirs(cache_a)
            os.makedirs(cache_b)
            with open(os.path.join(cache_a, "a.bin"), "wb") as f:
                f.write(b"aaa")
            with open(os.path.join(cache_b, "b.bin"), "wb") as f:
                f.write(b"bbb")

            targets = [
                TargetMatch(
                    category="data_and_history",
                    raw_path=skype_dir,
                    resolved_path=skype_dir,
                    description="Skype 已卸载孤儿目录",
                    size_bytes=14,
                    file_count=1,
                    contains_secrets=False,
                    is_model_weight=False,
                    default_selected=True,
                    is_safe=True,
                    safety_reason="孤儿残留",
                    risk_level=RiskLevel.L2_ORPHAN.value,
                    tool_id="skype",
                    tool_name="Skype",
                ),
                TargetMatch(
                    category="temp_images",
                    raw_path=png_file,
                    resolved_path=png_file,
                    description="历史引导图",
                    size_bytes=9,
                    file_count=1,
                    contains_secrets=False,
                    is_model_weight=False,
                    default_selected=True,
                    is_safe=True,
                    safety_reason="L1",
                    risk_level=RiskLevel.L1_SAFE.value,
                    tool_id="root-orphans",
                    tool_name="Root Orphans",
                ),
                TargetMatch(
                    category="caches",
                    raw_path=cache_a,
                    resolved_path=cache_a,
                    description="AppA Cache",
                    size_bytes=3,
                    file_count=1,
                    contains_secrets=False,
                    is_model_weight=False,
                    default_selected=True,
                    is_safe=True,
                    safety_reason="L2",
                    risk_level=RiskLevel.L2_ORPHAN.value,
                    tool_id="app-a",
                    tool_name="AppA",
                ),
                TargetMatch(
                    category="caches",
                    raw_path=cache_b,
                    resolved_path=cache_b,
                    description="AppB Cache",
                    size_bytes=3,
                    file_count=1,
                    contains_secrets=False,
                    is_model_weight=False,
                    default_selected=True,
                    is_safe=True,
                    safety_reason="L2",
                    risk_level=RiskLevel.L2_ORPHAN.value,
                    tool_id="app-b",
                    tool_name="AppB",
                ),
            ]

            cleaner = SafeCleaner(use_trash=True, use_quarantine=True, quarantine_base_dir=trash_dir)
            results = cleaner.clean_targets(targets, dry_run=False)
            self.assertTrue(all(r.success for r in results))
            self.assertTrue(all(r.method_used == "quarantine" for r in results))
            self.assertIsNotNone(cleaner.last_session_id)
            self.assertIsNotNone(cleaner.last_quarantine_dir)
            self.assertTrue(os.path.basename(cleaner.last_quarantine_dir).startswith(QUARANTINE_DIR_PREFIX))

            # 原路径均已被移走
            for p in [skype_dir, png_file, cache_a, cache_b]:
                self.assertFalse(os.path.exists(p))

            # 验证 manifest.json 结构与关键元数据
            self.assertTrue(os.path.isfile(cleaner.last_manifest_path))
            with open(cleaner.last_manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)

            self.assertEqual(manifest["version"], "1.2.0")
            self.assertEqual(manifest["session_id"], cleaner.last_session_id)
            self.assertEqual(manifest["total_reclaimed_bytes"], 29)
            self.assertEqual(manifest["status"], "active")
            self.assertEqual(len(manifest["items"]), 4)
            self.assertEqual(manifest["items"][0]["app_id"], "skype")
            self.assertEqual(manifest["items"][0]["original_path"], skype_dir)
            self.assertEqual(manifest["items"][0]["risk_level"], "L2_ORPHAN")
            # 同名 Cache 目录应自动去重命名，互不覆盖
            self.assertNotEqual(
                manifest["items"][2]["target_relative_path"],
                manifest["items"][3]["target_relative_path"],
            )

            qm = QuarantineManager(quarantine_base_dir=trash_dir)
            sessions = qm.list_sessions()
            self.assertEqual(len(sessions), 1)

            # 1. Dry-run 回滚不改变文件状态
            dry_rb = qm.rollback_session(cleaner.last_session_id, dry_run=True)
            self.assertEqual(dry_rb.restored_count, 4)
            self.assertFalse(os.path.exists(skype_dir))

            # 2. 正式一键无损回滚 (省略 session_id 默认回滚最新会话)
            rb = qm.rollback_session(dry_run=False)
            self.assertEqual(rb.restored_count, 4)
            self.assertEqual(rb.failed_count, 0)
            self.assertTrue(os.path.isfile(os.path.join(skype_dir, "Profile", "db.dat")))
            self.assertTrue(os.path.isfile(png_file))
            with open(os.path.join(cache_a, "a.bin"), "rb") as f:
                self.assertEqual(f.read(), b"aaa")
            with open(os.path.join(cache_b, "b.bin"), "rb") as f:
                self.assertEqual(f.read(), b"bbb")

            # 3. 验证 manifest 已标记为 rolled_back，重复回滚会安全跳过
            with open(cleaner.last_manifest_path, "r", encoding="utf-8") as f:
                manifest_after = json.load(f)
            self.assertEqual(manifest_after["status"], "rolled_back")
            rb_again = qm.rollback_session(cleaner.last_session_id, dry_run=False)
            self.assertEqual(rb_again.restored_count, 0)
            self.assertTrue(all(r.skipped for r in rb_again.results))

    def test_rollback_conflict_and_path_traversal_guard(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            app_support, trash_dir = self._make_workspace(tmp_dir)
            target_file = os.path.join(app_support, "conflict.log")
            with open(target_file, "w") as f:
                f.write("original_content")

            target = TargetMatch(
                category="caches",
                raw_path=target_file,
                resolved_path=target_file,
                description="日志",
                size_bytes=16,
                file_count=1,
                contains_secrets=False,
                is_model_weight=False,
                default_selected=True,
                is_safe=True,
                safety_reason="L1",
                risk_level=RiskLevel.L1_SAFE.value,
                tool_id="test",
                tool_name="Test",
            )
            cleaner = SafeCleaner(use_trash=True, use_quarantine=True, quarantine_base_dir=trash_dir)
            cleaner.clean_targets([target], dry_run=False)

            # 原路径出现新建同名文件 -> 默认不覆盖
            with open(target_file, "w") as f:
                f.write("new_file")

            qm = QuarantineManager(quarantine_base_dir=trash_dir)
            rb_conflict = qm.rollback_session(cleaner.last_session_id, overwrite=False)
            self.assertEqual(rb_conflict.failed_count, 1)
            self.assertIn("已存在同名", rb_conflict.results[0].message)
            with open(target_file, "r") as f:
                self.assertEqual(f.read(), "new_file")

            # 使用 overwrite=True 强制恢复
            rb_force = qm.rollback_session(cleaner.last_session_id, overwrite=True)
            self.assertEqual(rb_force.restored_count, 1)
            with open(target_file, "r") as f:
                self.assertEqual(f.read(), "original_content")

            # 路径穿越防护校验
            with open(cleaner.last_manifest_path, "r", encoding="utf-8") as f:
                m = json.load(f)
            m["items"][0]["rolled_back"] = False
            m["items"][0]["target_relative_path"] = "../../etc/passwd"
            qm.write_manifest(cleaner.last_quarantine_dir, m)
            rb_traversal = qm.rollback_session(cleaner.last_session_id)
            self.assertEqual(rb_traversal.failed_count, 1)
            self.assertIn("越界", rb_traversal.results[0].message)


class TestAssociationEngine(unittest.TestCase):
    """测试 Task 08: 应用名与路径脱节的三级反向映射引擎 (Association Engine)"""

    @staticmethod
    def _create_mock_app(app_dir: str, app_filename: str, bundle_id: str, display_name: str, executable: str = ""):
        contents = os.path.join(app_dir, app_filename, "Contents")
        os.makedirs(contents, exist_ok=True)
        plist_data = {
            "CFBundleIdentifier": bundle_id,
            "CFBundleDisplayName": display_name,
            "CFBundleName": display_name,
            "CFBundleExecutable": executable or display_name,
        }
        with open(os.path.join(contents, "Info.plist"), "wb") as f:
            plistlib.dump(plist_data, f)

    @staticmethod
    def _set_tree_time(path: str, ts: float):
        if os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                for fn in files:
                    os.utime(os.path.join(root, fn), (ts, ts))
                for dn in dirs:
                    os.utime(os.path.join(root, dn), (ts, ts))
        os.utime(path, (ts, ts))

    def test_tier1_plist_and_bundle_id_reverse_lookup(self):
        now = 1_800_000_000.0
        with tempfile.TemporaryDirectory() as tmp_dir:
            apps_dir = os.path.join(tmp_dir, "Applications")
            support_dir = os.path.join(tmp_dir, "Users", "tester", "Library", "Application Support")
            os.makedirs(apps_dir)
            os.makedirs(support_dir)

            # 安装两个应用：DemoApp 与 ChatGPT (bundle_id 与数据目录 com.openai.chat 不同)
            self._create_mock_app(apps_dir, "DemoApp.app", "com.example.demoapp", "DemoApp")
            self._create_mock_app(apps_dir, "ChatGPT.app", "com.openai.codex", "ChatGPT")

            # 1. 已卸载应用的 Info.plist 目录 -> Tier 1 判定为孤儿
            orphan_plist_dir = os.path.join(support_dir, "LegacyHelperData")
            os.makedirs(orphan_plist_dir)
            with open(os.path.join(orphan_plist_dir, "Info.plist"), "wb") as f:
                plistlib.dump({
                    "CFBundleIdentifier": "com.vendor.ghostapp",
                    "CFBundleDisplayName": "Ghost App",
                }, f)
            with open(os.path.join(orphan_plist_dir, "cache.bin"), "wb") as f:
                f.write(b"123456")

            # 2. 已安装应用的辅助启动器 Bundle ID 目录 -> 前缀回溯判定为 installed
            helper_dir = os.path.join(support_dir, "com.example.demoapp.launcher")
            os.makedirs(helper_dir)

            # 3. 脱节的反向域名目录 com.openai.chat -> 通过 signatures/name_idx 关联到 ChatGPT.app (installed)
            openai_dir = os.path.join(support_dir, "com.openai.chat")
            os.makedirs(openai_dir)

            engine = AssociationEngine(
                roots=[support_dir],
                app_dirs=[apps_dir],
                rules=[],
                now=now,
                use_spotlight=False,
                running_processes=[],
            )
            report = engine.scan()
            resolved_paths = {t.resolved_path for t in report.targets}

            self.assertIn(orphan_plist_dir, resolved_paths)
            self.assertNotIn(helper_dir, resolved_paths)
            self.assertNotIn(openai_dir, resolved_paths)

            match = next(t for t in report.targets if t.resolved_path == orphan_plist_dir)
            self.assertEqual(match.association_tier, 1)
            self.assertEqual(match.association_method, "plist_bundle_id")
            self.assertEqual(match.associated_app, "Ghost App")
            self.assertEqual(match.associated_bundle_id, "com.vendor.ghostapp")
            self.assertEqual(match.risk_level, RiskLevel.L2_ORPHAN.value)

    def test_tier2_signature_db_and_running_protection(self):
        now = 1_800_000_000.0
        with tempfile.TemporaryDirectory() as tmp_dir:
            apps_dir = os.path.join(tmp_dir, "Applications")
            support_dir = os.path.join(tmp_dir, "Users", "tester", "Library", "Application Support")
            os.makedirs(apps_dir)
            os.makedirs(support_dir)

            # Mock 安装了 Visual Studio Code.app，其数据目录叫 Code
            self._create_mock_app(apps_dir, "Visual Studio Code.app", "com.microsoft.VSCode", "Visual Studio Code")

            code_dir = os.path.join(support_dir, "Code")
            os.makedirs(code_dir)
            with open(os.path.join(code_dir, "state.vscdb"), "wb") as f:
                f.write(b"vscode")

            # 未安装的 Skype 孤儿目录 (使用自定义 signatures 避免依赖宿主机 /Applications)
            uninstalled_dir = os.path.join(support_dir, "CustomDecoupledDir")
            os.makedirs(uninstalled_dir)
            with open(os.path.join(uninstalled_dir, "history.db"), "wb") as f:
                f.write(b"history_bytes")

            # 另一个在进程中运行的应用目录
            running_dir = os.path.join(support_dir, "RunningToolDir")
            os.makedirs(running_dir)
            with open(os.path.join(running_dir, "data.bin"), "wb") as f:
                f.write(b"running")

            extra_sigs = {
                "customdecoupleddir": {
                    "app_name": "Custom Decoupled App",
                    "bundle_ids": ["com.test.customdecoupled"],
                    "app_paths": [os.path.join(apps_dir, "Custom Decoupled App.app")],
                    "process_names": ["CustomDecoupled"],
                },
                "runningtooldir": {
                    "app_name": "Running Tool",
                    "bundle_ids": ["com.test.runningtool"],
                    "app_paths": [os.path.join(apps_dir, "Running Tool.app")],
                    "process_names": ["RunningToolProc"],
                },
            }

            engine = AssociationEngine(
                roots=[support_dir],
                app_dirs=[apps_dir],
                rules=[],
                now=now,
                use_spotlight=False,
                running_processes=["/Applications/RunningToolProc"],
                extra_signatures=extra_sigs,
            )
            report = engine.scan()
            resolved_paths = {t.resolved_path for t in report.targets}

            self.assertNotIn(code_dir, resolved_paths, "已安装 VS Code 的 Code 目录不应误判为孤儿")
            self.assertNotIn(running_dir, resolved_paths, "正在运行的进程对应目录必须保护跳过")
            self.assertIn(uninstalled_dir, resolved_paths)

            match = next(t for t in report.targets if t.resolved_path == uninstalled_dir)
            self.assertEqual(match.association_tier, 2)
            self.assertEqual(match.association_method, "signature_db")
            self.assertEqual(match.associated_app, "Custom Decoupled App")
            self.assertEqual(match.associated_bundle_id, "com.test.customdecoupled")
            self.assertEqual(match.risk_level, RiskLevel.L2_ORPHAN.value)

    def test_tier3_heuristic_idle_and_safety_filters(self):
        now = 1_800_000_000.0
        old_ts = now - 200 * 86400
        recent_ts = now - 30 * 86400

        with tempfile.TemporaryDirectory() as tmp_dir:
            apps_dir = os.path.join(tmp_dir, "Applications")
            support_dir = os.path.join(tmp_dir, "Users", "tester", "Library", "Application Support")
            os.makedirs(apps_dir)
            os.makedirs(support_dir)

            # 已安装 Cool Editor.app，其数据目录名称去空格后为 CoolEditor (超过200天未改但应用在用)
            self._create_mock_app(apps_dir, "Cool Editor.app", "com.cool.editor", "Cool Editor")
            installed_norm_dir = os.path.join(support_dir, "CoolEditor")
            os.makedirs(installed_norm_dir)
            with open(os.path.join(installed_norm_dir, "prefs.json"), "w") as f:
                f.write("{}")
            self._set_tree_time(installed_norm_dir, old_ts)

            # 1. 超过 180 天未访问且无对应应用的未知目录 -> Tier 3 孤儿
            stale_unknown = os.path.join(support_dir, "OldAbandonedClient")
            os.makedirs(stale_unknown)
            with open(os.path.join(stale_unknown, "session.dat"), "wb") as f:
                f.write(b"old_session_payload")
            self._set_tree_time(stale_unknown, old_ts)

            # 2. 仅 30 天未访问的未知目录 -> 不应标记
            recent_unknown = os.path.join(support_dir, "RecentCliTool")
            os.makedirs(recent_unknown)
            with open(os.path.join(recent_unknown, "db.dat"), "wb") as f:
                f.write(b"recent")
            self._set_tree_time(recent_unknown, recent_ts)

            # 3. 含 .git 工程目录的旧目录 -> 免疫保护
            git_dir = os.path.join(support_dir, "AbandonedGitRepo")
            os.makedirs(os.path.join(git_dir, ".git"))
            with open(os.path.join(git_dir, "README.md"), "w") as f:
                f.write("repo")
            self._set_tree_time(git_dir, old_ts)

            # 4. 系统红线/原生目录 & 已被 YAML 规则覆盖的目录 -> 保护跳过
            sys_dir = os.path.join(support_dir, "Quick Look")
            os.makedirs(sys_dir)
            with open(os.path.join(sys_dir, "index.db"), "wb") as f:
                f.write(b"sys")
            self._set_tree_time(sys_dir, old_ts)

            rule_covered = os.path.join(support_dir, "CoveredTool")
            os.makedirs(rule_covered)
            with open(os.path.join(rule_covered, "cache.bin"), "wb") as f:
                f.write(b"covered")
            self._set_tree_time(rule_covered, old_ts)

            mock_rules = [
                {
                    "id": "covered-tool",
                    "name": "Covered Tool",
                    "targets": {"caches": [{"path": rule_covered}]},
                }
            ]

            engine = AssociationEngine(
                roots=[support_dir],
                app_dirs=[apps_dir],
                rules=mock_rules,
                stale_days=180,
                now=now,
                use_spotlight=False,
                running_processes=[],
            )
            report = engine.scan()
            resolved_paths = {t.resolved_path for t in report.targets}

            self.assertIn(stale_unknown, resolved_paths)
            self.assertNotIn(installed_norm_dir, resolved_paths)
            self.assertNotIn(recent_unknown, resolved_paths)
            self.assertNotIn(git_dir, resolved_paths)
            self.assertNotIn(sys_dir, resolved_paths)
            self.assertNotIn(rule_covered, resolved_paths)

            match = next(t for t in report.targets if t.resolved_path == stale_unknown)
            self.assertEqual(match.association_tier, 3)
            self.assertEqual(match.association_method, "heuristic")
            self.assertGreaterEqual(match.inactive_days, 200)
            self.assertEqual(match.risk_level, RiskLevel.L2_ORPHAN.value)


class TestSecretLeakAuditor(unittest.TestCase):
    """测试 Task 09: 敏感凭据与 API Key 深度隐私审计 (Secret Leak Warning)"""

    def test_credential_filenames_and_false_positive_guards(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            # 1. 典型敏感凭据文件名
            for fname in ["oauth_creds.json", "auth.json", "bootstrap_token.enc", "id_ed25519", ".env"]:
                fp = os.path.join(tmp_dir, fname)
                with open(fp, "w", encoding="utf-8") as f:
                    f.write("placeholder")
                res = SecretLeakAuditor.inspect_path(fp)
                self.assertTrue(res.contains_secrets, f"凭据文件 {fname} 应触发敏感审计")
                self.assertEqual(res.severity, "high")

            # 2. 易误报的非凭据文件：microcredentials.json、tokenizer.json、公用 CA cacert.pem、.env.example
            for safe_name, content in [
                ("verified_nace_microcredentials.json", '{"courses": []}'),
                ("tokenizer.json", '{"vocab_size": 32000}'),
                ("cacert.pem", "-----BEGIN CERTIFICATE-----\nMII...\n-----END CERTIFICATE-----\n"),
                (".env.example", "OPENAI_API_KEY="),
            ]:
                fp = os.path.join(tmp_dir, safe_name)
                with open(fp, "w", encoding="utf-8") as f:
                    f.write(content)
                res = SecretLeakAuditor.inspect_path(fp)
                self.assertFalse(res.contains_secrets, f"普通文件 {safe_name} 不应误报为敏感凭据")

    def test_sensitive_keys_detection_and_secret_redaction(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            raw_secret = "sk-live-secret-token-value-987654321"
            cfg_path = os.path.join(tmp_dir, "settings.json")
            with open(cfg_path, "w", encoding="utf-8") as f:
                json.dump({
                    "access_token": "oauth_tok_abc12345",
                    "api_key": raw_secret,
                    "client_secret": "sec_xyz_999",
                    "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0\n-----END PRIVATE KEY-----",
                }, f)

            # 空值/占位符文件不应误报
            empty_cfg = os.path.join(tmp_dir, "template.json")
            with open(empty_cfg, "w", encoding="utf-8") as f:
                json.dump({"api_key": None, "access_token": "", "secret": "<placeholder>"}, f)

            res = SecretLeakAuditor.inspect_path(cfg_path)
            self.assertTrue(res.contains_secrets)
            self.assertEqual(res.severity, "high")
            for expected_key in ["access_token", "api_key", "secret", "private_key"]:
                self.assertIn(expected_key, res.matched_keys)
            # 绝不泄露明文凭据值
            joined = " ".join(res.findings)
            self.assertNotIn(raw_secret, joined)
            self.assertNotIn("oauth_tok_abc12345", joined)

            res_empty = SecretLeakAuditor.inspect_path(empty_cfg)
            self.assertFalse(res_empty.contains_secrets)

    def test_sqlite_readonly_secret_audit(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = os.path.join(tmp_dir, "workbuddy_state.sqlite")
            conn = sqlite3.connect(db_path)
            conn.execute("CREATE TABLE ItemTable (key TEXT, value TEXT)")
            conn.execute("INSERT INTO ItemTable VALUES ('oauth.access_token', 'tok_secret_value_12345')")
            conn.execute("INSERT INTO ItemTable VALUES ('openai.api_key', 'sk-sqlite-secret-1234567890abcdef')")
            conn.commit()
            conn.close()

            res = SecretLeakAuditor.inspect_path(db_path)
            self.assertTrue(res.contains_secrets)
            self.assertEqual(res.severity, "high")
            self.assertIn("access_token", res.matched_keys)
            self.assertIn("api_key", res.matched_keys)
            self.assertFalse(os.path.exists(db_path + "-wal"))

    def test_scanner_and_preclean_secret_warning_output(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            rules_dir = os.path.join(tmp_dir, "rules")
            data_dir = os.path.join(tmp_dir, "Users", "tester", "Library", "Application Support", "LegacyAI")
            os.makedirs(rules_dir)
            os.makedirs(data_dir)

            with open(os.path.join(data_dir, "oauth_creds.json"), "w", encoding="utf-8") as f:
                json.dump({"access_token": "tok_legacy_12345", "api_key": "sk-legacy-1234567890abcdef"}, f)

            rule_yaml = {
                "id": "legacy-ai",
                "name": "Legacy AI",
                "category": "desktop-agent",
                "vendor": "Legacy",
                "targets": {
                    "data_and_history": [
                        {"path": data_dir, "description": "残留工作区目录"}
                    ]
                },
            }
            with open(os.path.join(rules_dir, "legacy-ai.yaml"), "w", encoding="utf-8") as f:
                yaml.safe_dump(rule_yaml, f, allow_unicode=True)

            # 1. RuleScanner 扫描应自动升级包含明文凭据的目录
            scanner = RuleScanner(rules_dir=rules_dir)
            report = scanner.scan_tool(rule_yaml)
            self.assertEqual(len(report.targets), 1)
            t = report.targets[0]
            self.assertTrue(t.contains_secrets)
            self.assertEqual(t.secret_severity, "high")
            self.assertFalse(t.default_selected)
            self.assertEqual(t.risk_level, RiskLevel.L2_ORPHAN.value)
            self.assertTrue(any("oauth_creds.json" in fn for fn in t.secret_findings))

            # 2. CLI clean --dry-run（未加 --include-secrets）应安全跳过并提示备份/授权
            env = dict(os.environ)
            env["SEA_OTTER_RULES_DIR"] = rules_dir
            proc_skip = subprocess.run(
                ["sea-otter", "clean", "legacy-ai", "--dry-run"],
                capture_output=True, text=True, env=env,
            )
            self.assertEqual(proc_skip.returncode, 0)
            self.assertIn("隐私安全提示", proc_skip.stdout)
            self.assertIn("--include-secrets", proc_skip.stdout)

            # 3. CLI clean --include-secrets --dry-run 应在清理前展示高危隐私告警与备份/抹除提示
            proc_warn = subprocess.run(
                ["sea-otter", "clean", "legacy-ai", "--include-secrets", "--dry-run"],
                capture_output=True, text=True, env=env,
            )
            self.assertEqual(proc_warn.returncode, 0)
            self.assertIn("高危隐私告警", proc_warn.stdout)
            self.assertIn("备份", proc_warn.stdout)
            self.assertIn("oauth_creds.json", proc_warn.stdout)


if __name__ == "__main__":
    unittest.main()

