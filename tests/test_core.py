"""Unit tests for pc-work-mcp distribution core modules."""

from __future__ import annotations

import base64
import json
import logging
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from output_guard import OutputGuard  # noqa: E402
from security import normalize_path_str  # noqa: E402
from server import (  # noqa: E402
    BOUNDARY_EFFECTIVE_DATE,
    DEFAULT_CONFIG,
    Handler,
    JsonRpcError,
    McpCore,
    McpServer,
    WorkspaceSelectionCancelled,
    deep_merge,
    ensure_first_run_workspace,
    is_local_token_configured,
    issue_local_token,
    load_config,
    main as server_main,
    verify_public_tcp_reachability,
)
from snapshot import SnapshotManager  # noqa: E402


class TestMcpCore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.ws = self.root / "workspace"
        self.outside = self.root / "outside"
        self.blocked = self.root / "blocked_sys"
        self.ws.mkdir()
        self.outside.mkdir()
        self.blocked.mkdir()

        self.cfg = deep_merge(DEFAULT_CONFIG, {
            "workspace": {
                "initialized": True,
                "default_dir": str(self.ws),
                "blocked_read_prefixes": [str(self.blocked)],
                "popup_approval": {"enabled": True, "timeout_sec": 5, "allow_session_trust": True},
                "snapshot": {"enabled": True, "max_versions_per_file": 3},
            },
            "exec": {
                "sync_timeout_sec": 10,
                "max_sync_timeout_sec": 20,
                "max_inline_chars": 1200,
                "workdir": str(self.ws),
            },
            "push": {"outbox_dir": str(self.root / "outbox")},
            "log": {"file": str(self.root / "logs" / "test.log")},
        })
        self.popup_calls = []
        self.next_decision = (False, False)

        def fake_popup(tool, target, summary, timeout, allow_trust, parent):
            self.popup_calls.append((tool, target, summary, parent))
            return self.next_decision

        self.core = McpCore(self.cfg, approval_cb=fake_popup)

    def tearDown(self):
        root_log = logging.getLogger()
        for h in list(root_log.handlers):
            if isinstance(h, logging.FileHandler):
                root_log.removeHandler(h)
                h.close()
        self.tmp.cleanup()

    def test_msys_path_normalization(self):
        self.assertEqual(normalize_path_str("/g/workspace/demo/a.py"), r"G:\workspace\demo\a.py")
        self.assertEqual(normalize_path_str("/c/"), "C:\\")

    def test_three_zone_read_and_write(self):
        # Green zone write: no popup
        res = self.core.handle("tools/call", {
            "name": "write_file",
            "arguments": {"path": str(self.ws / "hello.txt"), "content": "hi"},
        })
        self.assertFalse(res["isError"])
        self.assertEqual(len(self.popup_calls), 0)

        # Yellow zone read: allowed without popup
        ext_file = self.outside / "info.txt"
        ext_file.write_text("yellow", encoding="utf-8")
        res = self.core.handle("tools/call", {
            "name": "read_file",
            "arguments": {"path": str(ext_file)},
        })
        self.assertFalse(res["isError"])
        self.assertIn("yellow", res["content"][0]["text"])
        self.assertEqual(len(self.popup_calls), 0)

        # Blocked prefix read: denied
        sec_file = self.blocked / "secret.txt"
        sec_file.write_text("nope", encoding="utf-8")
        res = self.core.handle("tools/call", {
            "name": "read_file",
            "arguments": {"path": str(sec_file)},
        })
        self.assertTrue(res["isError"])
        self.assertIn("PermissionDenied", res["content"][0]["text"])

        # Traversal into outside via .. : triggers red zone popup and denies when False
        self.next_decision = (False, False)
        res = self.core.handle("tools/call", {
            "name": "write_file",
            "arguments": {"path": str(self.ws / ".." / "outside" / "evil.txt"), "content": "x"},
        })
        self.assertTrue(res["isError"])
        self.assertEqual(len(self.popup_calls), 1)
        self.assertFalse((self.outside / "evil.txt").exists())

        # Session trust allows subsequent writes in same parent dir without second popup
        self.next_decision = (True, True)
        res = self.core.handle("tools/call", {
            "name": "write_file",
            "arguments": {"path": str(self.outside / "ok1.txt"), "content": "1"},
        })
        self.assertFalse(res["isError"])
        self.assertEqual(len(self.popup_calls), 2)

        res = self.core.handle("tools/call", {
            "name": "write_file",
            "arguments": {"path": str(self.outside / "ok2.txt"), "content": "2"},
        })
        self.assertFalse(res["isError"])
        self.assertEqual(len(self.popup_calls), 2)

    def test_snapshot_retention_and_crlf_edit(self):
        target = self.ws / "crlf.txt"
        target.write_bytes(b"line1\r\nline2\r\nline3\r\n")

        res = self.core.handle("tools/call", {
            "name": "edit_file",
            "arguments": {"path": str(target), "old_text": "line1\nline2", "new_text": "L1\nL2"},
        })
        self.assertFalse(res["isError"])
        self.assertIn("EOL-normalized", res["content"][0]["text"])
        self.assertEqual(target.read_bytes(), b"L1\r\nL2\r\nline3\r\n")

        for i in range(4):
            self.core.handle("tools/call", {
                "name": "write_file",
                "arguments": {"path": str(target), "content": f"v{i}"},
            })
            time.sleep(0.02)
        snaps = list((self.ws / ".mcp_snapshots").glob("crlf.txt.*.bak"))
        self.assertEqual(len(snaps), 3)

        # Atomic batch edits: mismatched 2nd hunk aborts with closest line hints & leaves file/snapshots untouched
        multi = self.ws / "multi.py"
        multi.write_text("import os\n\ndef compute_alpha(x):\n    return x + 1\n\ndef compute_beta(y):\n    return y * 2\n", encoding="utf-8")
        snap_before = len(list((self.ws / ".mcp_snapshots").glob("multi.py.*.bak")))
        with self.assertRaises(JsonRpcError) as ctx:
            self.core.handle("tools/call", {
                "name": "edit_file",
                "arguments": {
                    "path": str(multi),
                    "edits": [
                        {"old_text": "import os", "new_text": "import sys"},
                        {"old_text": "def compute_beta(z):\n    return z * 9", "new_text": "pass"},
                    ],
                },
            })
        err_msg = str(ctx.exception)
        self.assertIn("edit #2/2", err_msg)
        self.assertIn("L6:", err_msg)
        self.assertIn("import os", multi.read_text(encoding="utf-8"))
        self.assertEqual(len(list((self.ws / ".mcp_snapshots").glob("multi.py.*.bak"))), snap_before)

        # Valid batch edits apply atomically with single snapshot and single post-edit check
        r_batch = self.core.handle("tools/call", {
            "name": "edit_file",
            "arguments": {
                "path": str(multi),
                "edits": [
                    {"old_text": "import os", "new_text": "import sys"},
                    {"old_text": "def compute_alpha(x):\n    return x + 1", "new_text": "def compute_alpha(x):\n    return x + 10"},
                    {"old_text": "def compute_beta(y):\n    return y * 2", "new_text": "def compute_beta(y):\n    return y * 20"},
                ],
            },
        })
        self.assertFalse(r_batch["isError"])
        batch_txt = r_batch["content"][0]["text"]
        self.assertIn("applied 3 edit(s)", batch_txt)
        self.assertIn("python_syntax: ok", batch_txt)
        new_src = multi.read_text(encoding="utf-8")
        self.assertIn("import sys", new_src)
        self.assertIn("return x + 10", new_src)
        self.assertIn("return y * 20", new_src)

    def test_output_guard_bypass(self):
        og = OutputGuard(self.ws / ".tmp_outputs", max_inline_chars=1200, head_chars=300, tail_chars=300)
        big = "\n".join(f"row-{i:04d}" for i in range(500))
        out, log_path = og.format_or_bypass(big, prefix="unit")
        self.assertIsNotNone(log_path)
        self.assertTrue(log_path.is_file())
        self.assertIn(".tmp_outputs", out)
        self.assertLess(len(out), len(big))

        # read_file truncates directly in memory with original-path line hints (no duplicate .tmp_outputs/read_*.log)
        big_src = self.ws / "big_source.txt"
        big_src.write_text("\n".join(f"src-line-{i:04d}-payload" for i in range(1, 200)), encoding="utf-8")
        small_core = McpCore(deep_merge(self.cfg, {"exec": {"max_inline_chars": 1000}}), approval_cb=lambda *a: (False, False))
        r_rf = small_core.handle("tools/call", {"name": "read_file", "arguments": {"path": str(big_src)}})
        rf_txt = r_rf["content"][0]["text"]
        self.assertIn("无需额外落盘", rf_txt)
        self.assertIn("start_line=", rf_txt)
        self.assertFalse(list((self.ws / ".tmp_outputs").glob("read_*.log")))

    def test_list_dir_ignores_noise(self):
        (self.ws / "keep.py").write_text("print(1)", encoding="utf-8")
        (self.ws / "node_modules" / "pkg").mkdir(parents=True)
        (self.ws / "node_modules" / "pkg" / "index.js").write_text("", encoding="utf-8")
        res = self.core.handle("tools/call", {
            "name": "list_dir",
            "arguments": {"path": str(self.ws), "recursive": True},
        })
        txt = res["content"][0]["text"]
        self.assertIn("keep.py", txt)
        self.assertNotIn("node_modules", txt)

        # Oversized list_dir output must route through OutputGuard to avoid context blow-up
        many_dir = self.ws / "many_files"
        many_dir.mkdir()
        for i in range(60):
            (many_dir / f"long_entry_filename_{i:03d}_payload_item.txt").write_text("x", encoding="utf-8")
        small_guard_core = McpCore(deep_merge(self.cfg, {"exec": {"max_inline_chars": 1000}}), approval_cb=lambda *a: (False, False))
        r_big = small_guard_core.handle("tools/call", {
            "name": "list_dir",
            "arguments": {"path": str(many_dir), "max_entries": 200},
        })
        big_txt = r_big["content"][0]["text"]
        self.assertIn(".tmp_outputs", big_txt)
        self.assertTrue(any((self.ws / ".tmp_outputs").glob("list_*.log")))

    def test_async_job_and_workspace_status(self):
        res = self.core.handle("tools/call", {
            "name": "start_job",
            "arguments": {"engine": "python", "code": "import time; print('started', flush=True); time.sleep(0.3); print('done')"},
        })
        self.assertFalse(res["isError"])
        job_info = json.loads(res["content"][0]["text"])
        job_id = job_info["job_id"]

        for _ in range(30):
            st_res = self.core.handle("tools/call", {
                "name": "get_job_status",
                "arguments": {"job_id": job_id, "tail_lines": 20},
            })
            st = json.loads(st_res["content"][0]["text"])
            if st["status"] != "running":
                break
            time.sleep(0.1)
        self.assertEqual(st["status"], "completed")
        self.assertIn("done", st["tail_output"])

        ws_res = self.core.handle("tools/call", {"name": "workspace_status", "arguments": {}})
        self.assertFalse(ws_res["isError"])
        ws_data = json.loads(ws_res["content"][0]["text"])
        self.assertEqual(ws_data["version"], "1.0.0-dist")
        self.assertEqual(ws_data["default_workspace"], str(self.ws.resolve()))
        self.assertEqual(ws_data["boundary_notice"]["effective_as_of"], BOUNDARY_EFFECTIVE_DATE)
        self.assertIn("新建独立版本文件夹", ws_data["self_modification_rule"])
        self.assertEqual(len(ws_res["content"]), 2)
        self.assertEqual(ws_res["content"][1]["type"], "image")
        self.assertEqual(ws_res["content"][1]["mimeType"], "image/png")
        png_bytes = base64.b64decode(ws_res["content"][1]["data"])
        self.assertTrue(png_bytes.startswith(b"\x89PNG\r\n\x1a\n"))

    def test_boundary_prompts_and_workarounds_removed(self):
        init = self.core.handle("initialize", {"protocolVersion": "2025-06-18"})
        instr = init["instructions"]
        self.assertIn("2026-11-26", instr)
        self.assertIn("沙箱", instr)
        self.assertIn("丢弃", instr)
        self.assertIn("小像素点", instr)
        self.assertIn("PowerShell", instr)
        self.assertIn("严禁直接修改", instr)

        tools = self.core.handle("tools/list", {})["tools"]
        names = {t["name"]: t["description"] for t in tools}
        self.assertEqual(len(names), 21)
        self.assertIn("bridge_suggest_ignore_dirs", names)
        for extra_tool in ("find_files", "grep_search", "task_plan"):
            self.assertIn(extra_tool, names)
        for bridge_tool in ("bridge_status", "bridge_upload_media", "bridge_save_generated_media", "bridge_get_task"):
            self.assertIn(bridge_tool, names)
        for removed in ("cdp_browser", "inject_chat_image", "gemini_ask", "gemini_generate", "gemini_status", "gemini_set_cookie"):
            self.assertNotIn(removed, names)
        self.assertIn("小像素点", names["workspace_status"])
        self.assertIn("2026-11-26", names["read_image"])
        self.assertIn("不假定任何第三方库已预装", names["python"])
        self.assertIn("停止当前回合输出", names["bridge_upload_media"])
        self.assertIn("停止当前回合输出", names["bridge_save_generated_media"])

        for removed in ("cdp_browser", "gemini_generate"):
            resp = self.core._process_one({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": removed, "arguments": {}},
            })
            self.assertIn("error", resp)
            self.assertEqual(resp["error"]["code"], -32602)

    def test_local_token_gate_and_issuance(self):
        cfg_path = self.root / "dist_config.json"
        raw_cfg = deep_merge(DEFAULT_CONFIG, {
            "auth": {"enabled": True, "token": ""},
            "workspace": {"initialized": True, "default_dir": str(self.ws)},
            "exec": {"workdir": str(self.ws)},
            "push": {"outbox_dir": str(self.root / "outbox")},
            "log": {"file": str(self.root / "logs" / "gate.log")},
        })
        cfg_path.write_text(json.dumps(raw_cfg), encoding="utf-8")

        self.assertFalse(is_local_token_configured(raw_cfg))
        rc = server_main(["--config", str(cfg_path)])
        self.assertEqual(rc, 2)

        srv = McpServer(("127.0.0.1", 0), Handler, self.core, raw_cfg)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/register",
                data=b'{"redirect_uris":["https://example.com/cb"]}',
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(req, timeout=5)
            self.assertEqual(ctx.exception.code, 403)
            body = json.loads(ctx.exception.read().decode("utf-8"))
            self.assertEqual(body["error"], "local_token_not_issued")
        finally:
            srv.shutdown()
            srv.server_close()

        res1 = issue_local_token(cfg_path)
        self.assertTrue(res1["issued"])
        self.assertTrue(res1["token"].startswith("pcmcp_"))
        loaded = json.loads(cfg_path.read_text(encoding="utf-8"))
        self.assertEqual(loaded["auth"]["token"], res1["token"])

        res2 = issue_local_token(cfg_path, rotate=False)
        self.assertFalse(res2["issued"])
        self.assertTrue(res2["already_configured"])

        oauth_state = self.root / "logs" / "oauth_state.json"
        oauth_state.parent.mkdir(parents=True, exist_ok=True)
        oauth_state.write_text(json.dumps({"tokens": {"old": 9999999999}, "refresh_tokens": {"old_rt": {}}}), encoding="utf-8")
        res3 = issue_local_token(cfg_path, rotate=True)
        self.assertTrue(res3["issued"])
        self.assertNotEqual(res3["token"], res1["token"])
        state_after = json.loads(oauth_state.read_text(encoding="utf-8"))
        self.assertEqual(state_after["tokens"], {})
        self.assertEqual(state_after["refresh_tokens"], {})

        # Verify CLI --issue-token prints plaintext token + save prompt directly in terminal
        import contextlib
        import io
        cli_cfg_path = self.root / "cli_issue_config.json"
        cli_cfg_path.write_text(json.dumps(raw_cfg), encoding="utf-8")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc_issue = server_main(["--config", str(cli_cfg_path), "--issue-token", "--no-gui"])
        self.assertEqual(rc_issue, 0)
        cli_out = buf.getvalue()
        issued_tok = json.loads(cli_cfg_path.read_text(encoding="utf-8"))["auth"]["token"]
        self.assertTrue(issued_tok.startswith("pcmcp_"))
        self.assertIn(f"鉴权 Token : {issued_tok}", cli_out)
        self.assertIn("请立即复制并保存", cli_out)

        # Verify explicit --config stays non-interactive exit code 2 even when stdin.isatty() is True,
        # while interactive double-click wizard issues token + syncs effective_cfg_path + continues cleanly
        from unittest.mock import patch
        from server import _run_interactive_token_wizard

        empty_tok_cfg_path = self.root / "empty_tok_cfg.json"
        empty_tok_cfg_path.write_text(json.dumps(raw_cfg), encoding="utf-8")
        with patch("sys.stdin.isatty", return_value=True):
            rc_auto_strict = server_main(["--config", str(empty_tok_cfg_path)])
        self.assertEqual(rc_auto_strict, 2)

        wiz_src_cfg = self.root / "wiz_src" / "config.json"
        wiz_eff_cfg = self.root / "wiz_ws" / "Gemini-Windows-Mcp" / "config.json"
        wiz_init_obj = deep_merge(raw_cfg, {"workspace": {"initialized": True, "default_dir": str(self.root / "wiz_ws")}})
        wiz_src_cfg.parent.mkdir(parents=True, exist_ok=True)
        wiz_eff_cfg.parent.mkdir(parents=True, exist_ok=True)
        wiz_src_cfg.write_text(json.dumps(wiz_init_obj), encoding="utf-8")
        wiz_eff_cfg.write_text(json.dumps(wiz_init_obj), encoding="utf-8")
        wiz_buf = io.StringIO()
        inputs = iter(["", "", ""])
        with patch("sys.stdin.isatty", return_value=True), patch("builtins.input", lambda _prompt="": next(inputs)), contextlib.redirect_stdout(wiz_buf):
            should_start = _run_interactive_token_wizard(wiz_src_cfg, wiz_eff_cfg)
        self.assertTrue(should_start)
        wiz_tok = json.loads(wiz_eff_cfg.read_text(encoding="utf-8"))["auth"]["token"]
        self.assertTrue(wiz_tok.startswith("pcmcp_"))
        self.assertIn(f"鉴权 Token : {wiz_tok}", wiz_buf.getvalue())

    def test_first_run_workspace_selection_and_copy(self):
        from unittest.mock import patch

        fake_src = self.root / "fake_dist"
        fake_src.mkdir()
        (fake_src / "server.py").write_text("# server", encoding="utf-8")
        (fake_src / "security.py").write_text("# security", encoding="utf-8")
        (fake_src / "__pycache__").mkdir()
        (fake_src / "__pycache__" / "junk.pyc").write_bytes(b"123")
        (fake_src / "logs").mkdir()
        (fake_src / "logs" / "old.log").write_text("old", encoding="utf-8")

        fresh_cfg = {
            "auth": {"enabled": True, "token": ""},
            "workspace": {"initialized": False, "default_dir": ""},
            "exec": {"workdir": ""},
            "push": {"outbox_dir": ""},
            "log": {"file": ""},
        }

        cfg1 = fake_src / "config.json"
        cfg1.write_text(json.dumps(fresh_cfg), encoding="utf-8")
        fake_desktop = self.root / "Desktop"

        # 1) Cancelling / no selection from raw source dir MUST abort cleanly (never silently jump to Desktop!)
        with self.assertRaises(WorkspaceSelectionCancelled):
            ensure_first_run_workspace(
                cfg1,
                requested_workspace=None,
                interactive=False,
                allow_gui=False,
                desktop_dir=fake_desktop,
                source_root=fake_src,
            )
        self.assertFalse((fake_desktop / "pc-work-mcp-workspace").exists())

        # 2) Non-TTY launch (e.g. .vbs / pythonw) with allow_gui=True STILL invokes WinForms picker!
        picked_ws = self.root / "VbsPickedWS"
        with patch("server._pick_folder_winforms", return_value=picked_ws) as mock_picker:
            res_vbs = ensure_first_run_workspace(
                cfg1,
                requested_workspace=None,
                interactive=False,
                use_gui=True,
                allow_gui=True,
                desktop_dir=fake_desktop,
                source_root=fake_src,
            )
            self.assertEqual(mock_picker.call_count, 1)
        expected_picked_mcp = picked_ws.resolve() / "Gemini-Windows-Mcp"
        self.assertTrue(res_vbs["initialized_now"])
        self.assertEqual(res_vbs["mode"], "gui_picker")
        self.assertEqual(Path(res_vbs["workspace_dir"]), picked_ws.resolve())
        self.assertTrue((expected_picked_mcp / "server.py").is_file())
        self.assertFalse((picked_ws / "server.py").exists())
        self.assertFalse((expected_picked_mcp / "__pycache__").exists())
        self.assertFalse((expected_picked_mcp / "logs" / "old.log").exists())

        # 3) Explicit use_desktop_workspace=True creates Desktop\pc-work-mcp-workspace\Gemini-Windows-Mcp
        cfg_desk = fake_src / "cfg_desk.json"
        cfg_desk.write_text(json.dumps(fresh_cfg), encoding="utf-8")
        res_desktop = ensure_first_run_workspace(
            cfg_desk,
            requested_workspace=None,
            interactive=False,
            allow_gui=False,
            use_desktop_workspace=True,
            desktop_dir=fake_desktop,
            source_root=fake_src,
        )
        expected_ws = (fake_desktop / "pc-work-mcp-workspace").resolve()
        expected_mcp = expected_ws / "Gemini-Windows-Mcp"
        self.assertTrue(res_desktop["initialized_now"])
        self.assertEqual(res_desktop["mode"], "desktop_flag")
        self.assertEqual(Path(res_desktop["workspace_dir"]), expected_ws)
        self.assertEqual(Path(res_desktop["mcp_dir"]), expected_mcp)
        self.assertFalse((expected_ws / "server.py").exists())
        self.assertTrue((expected_mcp / "server.py").is_file())
        self.assertTrue((expected_mcp / "logs").is_dir())
        self.assertTrue((expected_mcp / "outbox").is_dir())
        ws_cfg1 = json.loads((expected_mcp / "config.json").read_text(encoding="utf-8"))
        self.assertTrue(ws_cfg1["workspace"]["initialized"])
        self.assertEqual(ws_cfg1["workspace"]["default_dir"], str(expected_ws))

        res_again = ensure_first_run_workspace(cfg_desk, interactive=False, allow_gui=False, desktop_dir=fake_desktop, source_root=fake_src)
        self.assertFalse(res_again["initialized_now"])

        # 4) Already inside Gemini-Windows-Mcp subdir with empty default_dir: load_config & cancel fall back to clean outer dir
        outer_ws = (self.root / "CleanOuterWS").resolve()
        inner_mcp = outer_ws / "Gemini-Windows-Mcp"
        inner_mcp.mkdir(parents=True)
        inner_cfg = inner_mcp / "config.json"
        inner_cfg.write_text(json.dumps(fresh_cfg), encoding="utf-8")
        loaded_inner = load_config(str(inner_cfg))
        self.assertEqual(Path(loaded_inner["workspace"]["default_dir"]), outer_ws)
        self.assertEqual(Path(loaded_inner["exec"]["workdir"]), outer_ws)
        self.assertEqual(Path(loaded_inner["log"]["file"]), inner_mcp / "logs" / "server.log")

        res_inner = ensure_first_run_workspace(
            inner_cfg,
            requested_workspace=None,
            interactive=False,
            allow_gui=False,
            desktop_dir=fake_desktop,
            source_root=inner_mcp,
        )
        self.assertTrue(res_inner["initialized_now"])
        self.assertEqual(res_inner["mode"], "outer_clean_dir")
        self.assertEqual(Path(res_inner["workspace_dir"]), outer_ws)
        self.assertEqual(Path(res_inner["mcp_dir"]), inner_mcp)

        # 5) Explicit --workspace path + token sync
        cfg2 = self.root / "cfg2.json"
        cfg2.write_text(json.dumps(fresh_cfg), encoding="utf-8")
        custom_ws = self.root / "CustomAgentWS"
        res_custom = ensure_first_run_workspace(
            cfg2,
            requested_workspace=str(custom_ws),
            interactive=False,
            allow_gui=False,
            desktop_dir=fake_desktop,
            source_root=fake_src,
        )
        custom_mcp = custom_ws.resolve() / "Gemini-Windows-Mcp"
        self.assertTrue(res_custom["initialized_now"])
        self.assertEqual(Path(res_custom["workspace_dir"]), custom_ws.resolve())
        self.assertEqual(Path(res_custom["mcp_dir"]), custom_mcp)
        self.assertFalse((custom_ws / "server.py").exists())
        self.assertTrue((custom_mcp / "server.py").is_file())
        tok_res = issue_local_token(cfg2)
        self.assertTrue(tok_res["issued"])
        synced = json.loads((custom_mcp / "config.json").read_text(encoding="utf-8"))
        self.assertEqual(synced["auth"]["token"], tok_res["token"])

    def test_tampermonkey_bridge_turn1_upload_and_save_flow(self):
        tok = "pcmcp_test_bridge_token"
        srv_cfg = deep_merge(self.cfg, {
            "auth": {"enabled": True, "token": tok},
        })
        self.core.permissions.set_policy(tab_id="tab_turn1", profile="media_only", scope="session")
        self.core.permissions.set_policy(conversation_id="deadbeef12345678", profile="media_only", scope="session")
        srv = McpServer(("127.0.0.1", 0), Handler, self.core, srv_cfg)
        port = srv.server_address[1]
        base = f"http://127.0.0.1:{port}"
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()

        def http_req(path, method="GET", body=None, auth=True, content_type="application/json"):
            headers = {}
            if auth:
                headers["Authorization"] = f"Bearer {tok}"
            data = None
            if body is not None:
                if isinstance(body, (dict, list)):
                    data = json.dumps(body).encode("utf-8")
                    headers["Content-Type"] = content_type
                else:
                    data = body
                    headers["Content-Type"] = content_type
            req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.read()

        try:
            # 1) Unauthenticated bridge access rejected
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                http_req("/bridge/status", auth=False)
            self.assertEqual(ctx.exception.code, 401)

            # 2) Userscript download injects token and base URL cleanly
            st, js_bytes = http_req(f"/bridge/pc-work-mcp-gemini.user.js?token={tok}", auth=False)
            self.assertEqual(st, 200)
            js_txt = js_bytes.decode("utf-8")
            self.assertIn(tok, js_txt)
            self.assertNotIn(".innerHTML", js_txt)

            # 3) Turn-1 special case: tab is on /app (conversation_id=None) while generating
            http_req("/bridge/heartbeat", method="POST", body={
                "tab_id": "tab_turn1",
                "conversation_id": None,
                "url": "https://gemini.google.com/app",
                "is_generating": True,
                "focused": True,
            })

            sample_img = self.ws / "sample.png"
            sample_img.write_bytes(b"\x89PNG\r\n\x1a\nFAKEPNGDATA")

            up_res = self.core.handle("tools/call", {
                "name": "bridge_upload_media",
                "arguments": {
                    "files": [str(sample_img)],
                    "prompt": "请描述图片",
                    "delay_sec": 1,
                },
            })
            self.assertFalse(up_res["isError"])
            up_task = json.loads(up_res["content"][0]["text"])
            self.assertEqual(up_task["status"], "awaiting_cid")
            self.assertIsNone(up_task["target_conversation_id"])

            # Before Turn 1 finishes (still no cid), poll returns no actions
            _, poll0 = http_req("/bridge/tasks?tab_id=tab_turn1")
            self.assertEqual(json.loads(poll0)["actions"], [])

            # Turn 1 finishes -> URL asynchronously becomes /app/testcid0011223344
            _, hb2 = http_req("/bridge/heartbeat", method="POST", body={
                "tab_id": "tab_turn1",
                "conversation_id": "testcid0011223344",
                "url": "https://gemini.google.com/app/testcid0011223344",
                "is_generating": False,
                "focused": True,
            })
            hb2_obj = json.loads(hb2)
            self.assertIn(up_task["task_id"], hb2_obj["resolved_tasks"])

            # Hidden same-origin iframe (/_/bscframe) sharing tab_id must NOT wipe cid
            _, hb_iframe = http_req("/bridge/heartbeat", method="POST", body={
                "tab_id": "tab_turn1",
                "conversation_id": None,
                "url": "https://gemini.google.com/_/bscframe",
                "is_generating": False,
            })
            self.assertTrue(json.loads(hb_iframe).get("ignored"))
            _, st_after_iframe = http_req("/bridge/status")
            tabs_now = {t["tab_id"]: t for t in json.loads(st_after_iframe)["tabs"]}
            self.assertEqual(tabs_now["tab_turn1"]["conversation_id"], "testcid0011223344")

            # Now polling on that conversation gets the upload_media action
            _, poll1 = http_req("/bridge/tasks?tab_id=tab_turn1&conversation_id=testcid0011223344")
            acts1 = json.loads(poll1)["actions"]
            self.assertEqual(len(acts1), 1)
            self.assertEqual(acts1[0]["action"], "upload_media")

            # Plugin fetches the local file bytes via /bridge/file/<task_id>/0
            _, dl_bytes = http_req(f"/bridge/file/{up_task['task_id']}/0")
            self.assertEqual(dl_bytes, b"\x89PNG\r\n\x1a\nFAKEPNGDATA")

            http_req("/bridge/task_result", method="POST", body={
                "task_id": up_task["task_id"],
                "status": "completed",
                "conversation_id": "testcid0011223344",
                "result": {"uploaded_count": 1, "auto_send": True},
            })

            # 4) Generated media save flow + missing tab auto-open flow
            export_dir = self.ws / "exports"
            sav_res = self.core.handle("tools/call", {
                "name": "bridge_save_generated_media",
                "arguments": {
                    "target_path": str(export_dir),
                    "kind": "image",
                    "conversation_id": "deadbeef12345678",
                },
            })
            self.assertFalse(sav_res["isError"])
            sav_task = json.loads(sav_res["content"][0]["text"])
            self.assertEqual(sav_task["status"], "queued")

            # Existing tab_turn1 (on different cid) gets open_conversation action
            _, poll2 = http_req("/bridge/tasks?tab_id=tab_turn1&conversation_id=testcid0011223344")
            acts2 = json.loads(poll2)["actions"]
            self.assertEqual(acts2[0]["action"], "open_conversation")
            self.assertEqual(acts2[0]["conversation_id"], "deadbeef12345678")

            # Newly opened tab on deadbeef12345678 claims save_media and uploads artifact bytes
            http_req("/bridge/heartbeat", method="POST", body={
                "tab_id": "tab_opened",
                "conversation_id": "deadbeef12345678",
                "url": "https://gemini.google.com/app/deadbeef12345678",
                "is_generating": False,
            })
            _, poll3 = http_req("/bridge/tasks?tab_id=tab_opened&conversation_id=deadbeef12345678")
            acts3 = json.loads(poll3)["actions"]
            self.assertEqual(acts3[0]["action"], "save_media")

            http_req(
                f"/bridge/task_upload?task_id={sav_task['task_id']}&index=0&filename=cat.png&mime=image/png",
                method="POST",
                body=b"\x89PNG\r\n\x1a\nGENERATED_IMG",
                content_type="image/png",
            )
            http_req("/bridge/task_result", method="POST", body={
                "task_id": sav_task["task_id"],
                "status": "completed",
                "conversation_id": "deadbeef12345678",
            })

            saved_file = export_dir / "cat.png"
            self.assertTrue(saved_file.is_file())
            self.assertEqual(saved_file.read_bytes(), b"\x89PNG\r\n\x1a\nGENERATED_IMG")

            task_chk = self.core.handle("tools/call", {
                "name": "bridge_get_task",
                "arguments": {"task_id": sav_task["task_id"]},
            })
            task_chk_obj = json.loads(task_chk["content"][0]["text"])
            self.assertEqual(task_chk_obj["status"], "completed")
            self.assertEqual(len(task_chk_obj["saved_files"]), 1)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_oauth_proxy_base_and_quiet_bridge_logs(self):
        # 1) Proxy headers fallback when public_base_url is empty
        srv_empty = McpServer(("127.0.0.1", 0), Handler, self.core, deep_merge(self.cfg, {
            "auth": {"enabled": True, "token": "tok_proxy"},
            "oauth": {"enabled": True, "public_base_url": ""},
        }))
        port1 = srv_empty.server_address[1]
        t1 = threading.Thread(target=srv_empty.serve_forever, daemon=True)
        t1.start()
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port1}/.well-known/oauth-authorization-server/mcp",
                headers={
                    "Host": "192.0.2.10:15672",
                    "X-Forwarded-Host": "pcmcp.example.com",
                    "X-Forwarded-Port": "14769",
                    "X-Forwarded-Proto": "https",
                },
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                meta = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(meta["registration_endpoint"], "https://pcmcp.example.com:14769/register")
        finally:
            srv_empty.shutdown()
            srv_empty.server_close()

        # 2) Explicit public_base_url wins even if proxy strips X-Forwarded-Host
        srv_pub = McpServer(("127.0.0.1", 0), Handler, self.core, deep_merge(self.cfg, {
            "auth": {"enabled": True, "token": "tok_proxy"},
            "oauth": {"enabled": True, "public_base_url": "https://pcmcp.example.com:14769"},
        }))
        port2 = srv_pub.server_address[1]
        t2 = threading.Thread(target=srv_pub.serve_forever, daemon=True)
        t2.start()
        try:
            req2 = urllib.request.Request(
                f"http://127.0.0.1:{port2}/.well-known/oauth-authorization-server/mcp",
                headers={"Host": "192.0.2.10:15672"},
            )
            with urllib.request.urlopen(req2, timeout=5) as resp:
                meta2 = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(meta2["registration_endpoint"], "https://pcmcp.example.com:14769/register")

            # Verify /bridge/tasks 200 is logged at DEBUG (not INFO)
            records = []
            class Cap(logging.Handler):
                def emit(self, record):
                    records.append((record.levelno, record.getMessage()))
            cap = Cap(level=logging.INFO)
            root = logging.getLogger("pc-work-mcp")
            root.addHandler(cap)
            try:
                req_poll = urllib.request.Request(
                    f"http://127.0.0.1:{port2}/bridge/tasks?tab_id=t1",
                    headers={"Authorization": "Bearer tok_proxy"},
                )
                with urllib.request.urlopen(req_poll, timeout=5) as r:
                    self.assertEqual(r.status, 200)
            finally:
                root.removeHandler(cap)
            self.assertFalse(any("/bridge/tasks" in msg for _, msg in records))
        finally:
            srv_pub.shutdown()
            srv_pub.server_close()

    def test_per_conversation_bridge_permissions_and_isolation(self):
        tok = "pcmcp_local_admin_only"
        perm_store = self.root / "logs" / "bridge_permissions.json"
        cfg_perm = deep_merge(self.cfg, {
            "auth": {"enabled": True, "token": tok},
            "oauth": {"enabled": True, "public_base_url": "https://pcmcp.example.com:14769"},
            "permissions": {
                "per_conversation_enabled": True,
                "new_conversation_default_profile": "ask",
                "ambiguous_window_policy": "ask",
                "approval_timeout_sec": 5,
                "store_file": str(perm_store),
            },
        })
        cfg_file = self.root / "protected_cfg.json"
        cfg_file.write_text(json.dumps(cfg_perm), encoding="utf-8")
        core = McpCore(cfg_perm, approval_cb=lambda *a: (False, False), config_path=cfg_file)
        srv = McpServer(("127.0.0.1", 0), Handler, core, cfg_perm)
        port = srv.server_address[1]
        base = f"http://127.0.0.1:{port}"
        srv_thread = threading.Thread(target=srv.serve_forever, daemon=True)
        srv_thread.start()

        def req(path, method="GET", body=None, bearer=tok):
            headers = {}
            if bearer:
                headers["Authorization"] = f"Bearer {bearer}"
            data = None
            if body is not None:
                data = json.dumps(body).encode("utf-8")
                headers["Content-Type"] = "application/json"
            r = urllib.request.Request(base + path, data=data, headers=headers, method=method)
            try:
                with urllib.request.urlopen(r, timeout=8) as resp:
                    return resp.status, json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                return exc.code, json.loads(exc.read().decode("utf-8"))

        try:
            # 0) No bridge connected -> fallback default mode works & recommends Tampermonkey
            ws_no_bridge = core.handle("tools/call", {"name": "workspace_status", "arguments": {}})
            ws_obj0 = json.loads(ws_no_bridge["content"][0]["text"])
            self.assertEqual(ws_obj0["permission_mode"]["mode"], "fallback_default")
            self.assertIn("Tampermonkey", ws_obj0["permission_mode"]["recommendation"])
            f_ws = self.ws / "fallback.txt"
            res_fb = core.handle("tools/call", {"name": "write_file", "arguments": {"path": str(f_ws), "content": "ok"}})
            self.assertFalse(res_fb["isError"])

            # 1) OAuth token (simulating Google cloud caller) works on /mcp, MUST be rejected on /bridge/permissions!
            oauth_at, _ = srv.oauth.issue_tokens("google_client_1")
            st_mcp, _ = req("/mcp", method="POST", body={"jsonrpc": "2.0", "id": 1, "method": "ping"}, bearer=oauth_at)
            self.assertEqual(st_mcp, 200)
            st_oauth_bridge, body_oauth_bridge = req("/bridge/permissions", bearer=oauth_at)
            self.assertEqual(st_oauth_bridge, 403)
            self.assertEqual(body_oauth_bridge["error"], "local_admin_token_required")

            # 2) Agent cannot modify control-plane files (config.json / bridge_permissions.json)
            res_tamper = core.handle("tools/call", {
                "name": "write_file",
                "arguments": {"path": str(perm_store), "content": "{}"},
            })
            self.assertTrue(res_tamper["isError"])
            self.assertIn("control-plane", res_tamper["content"][0]["text"])
            res_tamper_ps = core.handle("tools/call", {
                "name": "powershell",
                "arguments": {"script": f"Set-Content -Path '{perm_store}' -Value 'hack'"},
            })
            self.assertTrue(res_tamper_ps["isError"])

            # 3) Connect two browser windows with separate conversation URLs
            req("/bridge/heartbeat", method="POST", body={
                "tab_id": "tab_a",
                "conversation_id": "cid_window_aaaa",
                "url": "https://gemini.google.com/app/cid_window_aaaa",
                "title": "Code Chat",
                "is_generating": False,
                "focused": False,
            })
            req("/bridge/heartbeat", method="POST", body={
                "tab_id": "tab_b",
                "conversation_id": "cid_window_bbbb",
                "url": "https://gemini.google.com/app/cid_window_bbbb",
                "title": "Readonly Chat",
                "is_generating": False,
                "focused": True,
            })

            # Set window A to workspace (persistent), window B to readonly (persistent)
            st_set_a, _ = req("/bridge/permissions", method="POST", body={
                "action": "set",
                "conversation_id": "cid_window_aaaa",
                "profile": "workspace",
                "scope": "persistent",
                "title": "Code Chat",
            })
            self.assertEqual(st_set_a, 200)
            st_set_b, _ = req("/bridge/permissions", method="POST", body={
                "action": "set",
                "conversation_id": "cid_window_bbbb",
                "profile": "readonly",
                "scope": "persistent",
                "title": "Readonly Chat",
            })
            self.assertEqual(st_set_b, 200)
            self.assertTrue(perm_store.is_file())

            # Window A generating -> write_file succeeds without popup, powershell waits & gets denied
            req("/bridge/heartbeat", method="POST", body={
                "tab_id": "tab_a",
                "conversation_id": "cid_window_aaaa",
                "url": "https://gemini.google.com/app/cid_window_aaaa",
                "is_generating": True,
            })
            res_wa = core.handle("tools/call", {
                "name": "write_file",
                "arguments": {"path": str(self.ws / "win_a.txt"), "content": "from A"},
            })
            self.assertFalse(res_wa["isError"])

            # Window B generating (A stops) -> read_file succeeds, write_file triggers interactive bridge approval!
            req("/bridge/heartbeat", method="POST", body={
                "tab_id": "tab_a",
                "conversation_id": "cid_window_aaaa",
                "url": "https://gemini.google.com/app/cid_window_aaaa",
                "is_generating": False,
            })
            req("/bridge/heartbeat", method="POST", body={
                "tab_id": "tab_b",
                "conversation_id": "cid_window_bbbb",
                "url": "https://gemini.google.com/app/cid_window_bbbb",
                "is_generating": True,
            })
            res_rb = core.handle("tools/call", {
                "name": "read_file",
                "arguments": {"path": str(self.ws / "win_a.txt")},
            })
            self.assertFalse(res_rb["isError"])
            self.assertIn("from A", res_rb["content"][0]["text"])

            # Start blocked write_file in Window B -> approve via /bridge/permissions/decision as allow_once
            out_holder = {}
            def run_write_b():
                out_holder["res"] = core.handle("tools/call", {
                    "name": "write_file",
                    "arguments": {"path": str(self.ws / "win_b.txt"), "content": "from B"},
                })
            th_b = threading.Thread(target=run_write_b, daemon=True)
            th_b.start()

            apr_id = None
            for _ in range(30):
                _, tasks_b = req("/bridge/tasks?tab_id=tab_b&conversation_id=cid_window_bbbb")
                if tasks_b.get("pending_approvals"):
                    apr_id = tasks_b["pending_approvals"][0]["approval_id"]
                    break
                time.sleep(0.05)
            self.assertIsNotNone(apr_id)

            # Window A should NOT see Window B's non-ambiguous approval!
            _, tasks_a = req("/bridge/tasks?tab_id=tab_a&conversation_id=cid_window_aaaa")
            self.assertEqual(tasks_a.get("pending_approvals"), [])

            st_dec, _ = req("/bridge/permissions/decision", method="POST", body={
                "approval_id": apr_id,
                "decision": "allow_once",
            })
            self.assertEqual(st_dec, 200)
            th_b.join(timeout=5)
            self.assertFalse(out_holder["res"]["isError"])

            # Ambiguous multi-generating windows -> cannot grant persistent profile, only allow_once / deny
            req("/bridge/heartbeat", method="POST", body={
                "tab_id": "tab_a",
                "conversation_id": "cid_window_aaaa",
                "url": "https://gemini.google.com/app/cid_window_aaaa",
                "is_generating": True,
            })
            amb_holder = {}
            def run_amb():
                amb_holder["res"] = core.handle("tools/call", {
                    "name": "write_file",
                    "arguments": {"path": str(self.ws / "amb.txt"), "content": "amb"},
                })
            th_amb = threading.Thread(target=run_amb, daemon=True)
            th_amb.start()

            amb_aid = None
            for _ in range(30):
                _, t_amb = req("/bridge/tasks?tab_id=tab_a&conversation_id=cid_window_aaaa")
                if t_amb.get("pending_approvals"):
                    self.assertTrue(t_amb["pending_approvals"][0]["ambiguous"])
                    amb_aid = t_amb["pending_approvals"][0]["approval_id"]
                    break
                time.sleep(0.05)
            self.assertIsNotNone(amb_aid)
            st_bad_prof, _ = req("/bridge/permissions/decision", method="POST", body={
                "approval_id": amb_aid,
                "decision": "allow_profile",
                "profile": "full",
            })
            self.assertEqual(st_bad_prof, 400)
            req("/bridge/permissions/decision", method="POST", body={
                "approval_id": amb_aid,
                "decision": "deny",
            })
            th_amb.join(timeout=5)
            self.assertTrue(amb_holder["res"]["isError"])

            # 4) Turn-1 promotion: new tab on /app gets workspace policy, then resolves to cid_turn1_zzzz
            req("/bridge/heartbeat", method="POST", body={
                "tab_id": "tab_a",
                "conversation_id": "cid_window_aaaa",
                "url": "https://gemini.google.com/app/cid_window_aaaa",
                "is_generating": False,
            })
            req("/bridge/heartbeat", method="POST", body={
                "tab_id": "tab_b",
                "conversation_id": "cid_window_bbbb",
                "url": "https://gemini.google.com/app/cid_window_bbbb",
                "is_generating": False,
            })
            req("/bridge/heartbeat", method="POST", body={
                "tab_id": "tab_t1",
                "conversation_id": None,
                "url": "https://gemini.google.com/app",
                "title": "New Chat",
                "is_generating": True,
            })
            req("/bridge/permissions", method="POST", body={
                "action": "set",
                "tab_id": "tab_t1",
                "profile": "workspace",
                "scope": "persistent",
            })
            _, hb_prom = req("/bridge/heartbeat", method="POST", body={
                "tab_id": "tab_t1",
                "conversation_id": "cid_turn1_zzzz",
                "url": "https://gemini.google.com/app/cid_turn1_zzzz",
                "title": "Promoted Chat",
                "is_generating": True,
            })
            self.assertEqual(hb_prom["effective_policy"]["profile"], "workspace")
            self.assertEqual(hb_prom["effective_policy"]["conversation_id"], "cid_turn1_zzzz")

            # Navigating tab_t1 back to blank /app must NOT leak Promoted Chat's policy to next new chat
            _, hb_new = req("/bridge/heartbeat", method="POST", body={
                "tab_id": "tab_t1",
                "conversation_id": None,
                "url": "https://gemini.google.com/app",
                "title": "Gemini",
                "is_generating": False,
            })
            self.assertEqual(hb_new["effective_policy"]["profile"], "ask")
        finally:
            srv.shutdown()
            srv.server_close()

    def test_dynamic_workspace_rules_injection_cadence_and_isolation(self):
        from workspace_rules import DEFAULT_REINJECT_EVERY_CALLS, DEFAULT_REINJECT_EVERY_OUTPUT_CHARS, WorkspaceRulesManager

        # Verify production defaults match the quantitative cadence (20 calls / 96,000 output chars)
        default_core = McpCore(self.cfg, approval_cb=lambda *a: (False, False))
        self.assertEqual(default_core.rules.reinject_every_calls, 20)
        self.assertEqual(default_core.rules.reinject_every_output_chars, 96000)
        self.assertEqual(DEFAULT_REINJECT_EVERY_CALLS, 20)
        self.assertEqual(DEFAULT_REINJECT_EVERY_OUTPUT_CHARS, 96000)

        # Verify max_total_chars budget accounts for truncated_note length without overrunning across files
        trunc_dir = self.root / "trunc_rules_ws"
        trunc_dir.mkdir(parents=True, exist_ok=True)
        (trunc_dir / "AGENTS.md").write_text("A" * 2400, encoding="utf-8")
        (trunc_dir / "GEMINI.md").write_text("B" * 800, encoding="utf-8")
        trunc_mgr = WorkspaceRulesManager({"workspace_rules": {"max_total_chars": 2000}}, trunc_dir)
        disc_trunc = trunc_mgr.discover_rules(trunc_dir)
        fmt_trunc = trunc_mgr._format_injection_block(disc_trunc, reason="initial", call_step=1)
        self.assertIn('...[truncated by max_total_chars]...', fmt_trunc)
        self.assertIn('<rule_file path="GEMINI.md" omitted="max_total_chars_exceeded" />', fmt_trunc)
        import re as _re
        inner_bodies = _re.findall(r'<rule_file path="[^"]+" sha256="[^"]+">\n(.*?)\n</rule_file>', fmt_trunc, flags=_re.S)
        self.assertEqual(len(inner_bodies), 1)
        self.assertLessEqual(len(inner_bodies[0]), 2000)

        tok = "pcmcp_rules_admin_tok"
        cfg_rules = deep_merge(self.cfg, {
            "auth": {"enabled": True, "token": tok},
            "oauth": {"enabled": True, "public_base_url": "https://pcmcp.example.com:14769"},
            "permissions": {"per_conversation_enabled": True, "new_conversation_default_profile": "full"},
            "workspace_rules": {
                "enabled": True,
                "reinject_every_calls": 3,
                "reinject_every_output_chars": 600,
                "max_total_chars": 12000,
            },
        })
        core = McpCore(cfg_rules, approval_cb=lambda *a: (False, False))
        srv = McpServer(("127.0.0.1", 0), Handler, core, cfg_rules)
        port = srv.server_address[1]
        base = f"http://127.0.0.1:{port}"
        srv_thread = threading.Thread(target=srv.serve_forever, daemon=True)
        srv_thread.start()

        def req(path, method="GET", body=None, bearer=tok, extra_headers=None):
            headers = dict(extra_headers or {})
            if bearer:
                headers["Authorization"] = f"Bearer {bearer}"
            data = None
            if body is not None:
                data = json.dumps(body).encode("utf-8")
                headers["Content-Type"] = "application/json"
            r = urllib.request.Request(base + path, data=data, headers=headers, method=method)
            try:
                with urllib.request.urlopen(r, timeout=8) as resp:
                    return resp.status, json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                return exc.code, json.loads(exc.read().decode("utf-8"))

        try:
            # 1) Empty workspace -> zero extra rule blocks attached
            ws_empty = core.handle("tools/call", {"name": "workspace_status", "arguments": {}})
            self.assertEqual(len(ws_empty["content"]), 2)
            small_file = self.ws / "note.txt"
            r_init = core.handle("tools/call", {"name": "write_file", "arguments": {"path": str(small_file), "content": "hi"}})
            self.assertEqual(len(r_init["content"]), 1)

            # 2) Create AGENTS.md and .gemini/rules/01-style.md mid-session -> immediate rules_changed merged into last text block
            agents_md = self.ws / "AGENTS.md"
            agents_md.write_text("Rule Alpha: verify everything.", encoding="utf-8")
            rules_sub = self.ws / ".gemini" / "rules"
            rules_sub.mkdir(parents=True, exist_ok=True)
            style_md = rules_sub / "01-style.md"
            style_md.write_text("Style: keep concise.", encoding="utf-8")

            r_changed = core.handle("tools/call", {"name": "workspace_status", "arguments": {}})
            # Single text block + canary PNG (no extra trailing text block that Gemini Web MCP gateway would overwrite with)
            self.assertEqual(len(r_changed["content"]), 2)
            self.assertEqual(r_changed["content"][1]["type"], "image")
            ws_raw, sep, inj_part = r_changed["content"][0]["text"].partition("\n\n<workspace_rules")
            self.assertEqual(sep, "\n\n<workspace_rules")
            ws_changed_obj = json.loads(ws_raw)
            self.assertEqual(len(ws_changed_obj["workspace_rules"]["detected_files"]), 2)
            inj1 = "<workspace_rules" + inj_part
            self.assertIn('reason="rules_changed"', inj1)
            self.assertIn("Rule Alpha: verify everything.", inj1)
            self.assertIn("Style: keep concise.", inj1)

            # 3) Next 2 small calls (< 3 calls, < 600 output chars) do NOT re-inject
            r_c1 = core.handle("tools/call", {"name": "read_file", "arguments": {"path": str(small_file)}})
            self.assertEqual(len(r_c1["content"]), 1)
            self.assertNotIn("<workspace_rules", r_c1["content"][0]["text"])
            r_c2 = core.handle("tools/call", {"name": "read_file", "arguments": {"path": str(small_file)}})
            self.assertEqual(len(r_c2["content"]), 1)
            self.assertNotIn("<workspace_rules", r_c2["content"][0]["text"])

            # 4) 3rd call since last injection hits reinject_every_calls=3 -> periodic_calls merged into single text block
            r_c3 = core.handle("tools/call", {"name": "read_file", "arguments": {"path": str(small_file)}})
            self.assertEqual(len(r_c3["content"]), 1)
            self.assertIn("hi", r_c3["content"][0]["text"])
            self.assertIn('reason="periodic_calls"', r_c3["content"][0]["text"])

            # 5) Big tool output (>= 600 chars) triggers output_volume early on the very first call after periodic
            big_file = self.ws / "big.txt"
            big_file.write_text("X" * 700, encoding="utf-8")
            r_big = core.handle("tools/call", {"name": "read_file", "arguments": {"path": str(big_file)}})
            self.assertEqual(len(r_big["content"]), 1)
            self.assertIn("X" * 700, r_big["content"][0]["text"])
            self.assertIn('reason="output_volume"', r_big["content"][0]["text"])

            # 6) Edit AGENTS.md -> next call immediately detects SHA change (rules_changed)
            agents_md.write_text("Rule Beta: updated instructions.", encoding="utf-8")
            r_edit = core.handle("tools/call", {"name": "read_file", "arguments": {"path": str(small_file)}})
            self.assertEqual(len(r_edit["content"]), 1)
            self.assertIn("hi", r_edit["content"][0]["text"])
            self.assertIn('reason="rules_changed"', r_edit["content"][0]["text"])
            self.assertIn("Rule Beta: updated instructions.", r_edit["content"][0]["text"])

            # 7) Remove all rule files -> emits rules_removed once, then stops injecting
            agents_md.unlink()
            style_md.unlink()
            r_rem = core.handle("tools/call", {"name": "read_file", "arguments": {"path": str(small_file)}})
            self.assertEqual(len(r_rem["content"]), 1)
            self.assertIn("hi", r_rem["content"][0]["text"])
            self.assertIn('reason="rules_removed"', r_rem["content"][0]["text"])
            r_after_rem = core.handle("tools/call", {"name": "read_file", "arguments": {"path": str(small_file)}})
            self.assertEqual(len(r_after_rem["content"]), 1)
            self.assertNotIn("<workspace_rules", r_after_rem["content"][0]["text"])

            # 8) Re-create default AGENTS.md + test HTTP Mcp-Session-Id isolation & /bridge/rules admin guard
            agents_md.write_text("Default Workspace Rule.", encoding="utf-8")
            oauth_at, _ = srv.oauth.issue_tokens("google_rules_client")
            st_oauth_get, body_oauth = req("/bridge/rules", bearer=oauth_at)
            self.assertEqual(st_oauth_get, 403)
            self.assertEqual(body_oauth["error"], "local_admin_token_required")
            st_oauth_post, _ = req("/bridge/rules", method="POST", body={"action": "reset_session"}, bearer=oauth_at)
            self.assertEqual(st_oauth_post, 403)

            # Control-plane protection on bridge_rules.json
            rules_store = self.root / "logs" / "bridge_rules.json"
            r_tamper = core.handle("tools/call", {
                "name": "write_file",
                "arguments": {"path": str(rules_store), "content": "{}"},
            })
            self.assertTrue(r_tamper["isError"])
            self.assertIn("control-plane", r_tamper["content"][0]["text"])

            # Two distinct Mcp-Session-Id sessions each get their own Turn-1 initial injection (merged single text block)
            _, rpc_a1 = req("/mcp", method="POST", bearer=tok, extra_headers={"Mcp-Session-Id": "ses_alpha"}, body={
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": str(small_file)}},
            })
            self.assertEqual(len(rpc_a1["result"]["content"]), 1)
            self.assertIn("hi", rpc_a1["result"]["content"][0]["text"])
            self.assertIn('reason="initial"', rpc_a1["result"]["content"][0]["text"])

            _, rpc_a2 = req("/mcp", method="POST", bearer=tok, extra_headers={"Mcp-Session-Id": "ses_alpha"}, body={
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": str(small_file)}},
            })
            self.assertEqual(len(rpc_a2["result"]["content"]), 1)
            self.assertNotIn("<workspace_rules", rpc_a2["result"]["content"][0]["text"])

            _, rpc_b1 = req("/mcp", method="POST", bearer=tok, extra_headers={"Mcp-Session-Id": "ses_beta"}, body={
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": str(small_file)}},
            })
            self.assertEqual(len(rpc_b1["result"]["content"]), 1)
            self.assertIn("hi", rpc_b1["result"]["content"][0]["text"])
            self.assertIn('reason="initial"', rpc_b1["result"]["content"][0]["text"])

            # 9) Bridge Turn-1 promotion + per-conversation custom rules_dir isolation
            proj_b = self.root / "project_b"
            proj_b.mkdir()
            (proj_b / "AGENTS.md").write_text("Project B Exclusive Rule.", encoding="utf-8")

            req("/bridge/heartbeat", method="POST", body={
                "tab_id": "tab_r1",
                "conversation_id": None,
                "url": "https://gemini.google.com/app",
                "is_generating": True,
            })
            res_t1 = core.handle("tools/call", {"name": "read_file", "arguments": {"path": str(small_file)}})
            self.assertEqual(len(res_t1["content"]), 1)
            self.assertIn("hi", res_t1["content"][0]["text"])
            self.assertIn("Default Workspace Rule.", res_t1["content"][0]["text"])

            # Promote tab_r1 -> cid_r1_promoted; next call must NOT double-inject
            req("/bridge/heartbeat", method="POST", body={
                "tab_id": "tab_r1",
                "conversation_id": "cid_r1_promoted",
                "url": "https://gemini.google.com/app/cid_r1_promoted",
                "is_generating": True,
            })
            res_t2 = core.handle("tools/call", {"name": "read_file", "arguments": {"path": str(small_file)}})
            self.assertEqual(len(res_t2["content"]), 1)
            self.assertNotIn("<workspace_rules", res_t2["content"][0]["text"])

            # Bind custom rules_dir for cid_r1_promoted -> next call injects Project B Exclusive Rule
            st_set_dir, set_resp = req("/bridge/rules", method="POST", body={
                "action": "set_rules_dir",
                "conversation_id": "cid_r1_promoted",
                "rules_dir": str(proj_b),
                "scope": "persistent",
            })
            self.assertEqual(st_set_dir, 200)
            self.assertTrue(set_resp["result"]["is_custom"])
            res_proj_b = core.handle("tools/call", {"name": "read_file", "arguments": {"path": str(small_file)}})
            self.assertEqual(len(res_proj_b["content"]), 1)
            self.assertIn("hi", res_proj_b["content"][0]["text"])
            self.assertIn("Project B Exclusive Rule.", res_proj_b["content"][0]["text"])

            # Force reset via /bridge/rules -> next call re-injects
            st_rst, _ = req("/bridge/rules", method="POST", body={
                "action": "reset_session",
                "conversation_id": "cid_r1_promoted",
            })
            self.assertEqual(st_rst, 200)
            res_rst = core.handle("tools/call", {"name": "read_file", "arguments": {"path": str(small_file)}})
            self.assertEqual(len(res_rst["content"]), 1)
            self.assertIn("hi", res_rst["content"][0]["text"])
            self.assertIn("Project B Exclusive Rule.", res_rst["content"][0]["text"])

            # Returning tab_r1 to blank /app starts a clean new conversation with Default Workspace Rule
            req("/bridge/heartbeat", method="POST", body={
                "tab_id": "tab_r1",
                "conversation_id": None,
                "url": "https://gemini.google.com/app",
                "is_generating": True,
            })
            res_fresh = core.handle("tools/call", {"name": "read_file", "arguments": {"path": str(small_file)}})
            self.assertEqual(len(res_fresh["content"]), 1)
            self.assertIn("hi", res_fresh["content"][0]["text"])
            self.assertIn('reason="initial"', res_fresh["content"][0]["text"])
            self.assertIn("Default Workspace Rule.", res_fresh["content"][0]["text"])
        finally:
            srv.shutdown()
            srv.server_close()

    def test_per_conversation_workspace_switching_and_parity(self):
        tok = "pcmcp_ws_switch_tok"
        ws_a = self.root / "ProjectAlpha"
        ws_b = self.root / "ProjectBeta"
        ws_picked = self.root / "PickedGamma"
        ws_a.mkdir()
        ws_b.mkdir()
        ws_picked.mkdir()
        (self.ws / "default_only.txt").write_text("default_root", encoding="utf-8")
        (ws_a / "alpha.txt").write_text("from_alpha", encoding="utf-8")
        (ws_a / "AGENTS.md").write_text("Rule Alpha: stay inside ProjectAlpha.", encoding="utf-8")
        (ws_b / "beta.txt").write_text("from_beta", encoding="utf-8")
        (ws_b / "AGENTS.md").write_text("Rule Beta: stay inside ProjectBeta.", encoding="utf-8")

        cfg = deep_merge(self.cfg, {
            "auth": {"enabled": True, "token": tok},
            "exec": {"max_inline_chars": 1000},
            "permissions": {
                "per_conversation_enabled": True,
                "new_conversation_default_profile": "full",
            },
            "workspace": {"popup_approval": {"enabled": False}},
        })
        core = McpCore(cfg, approval_cb=lambda *a: (False, False), config_path=self.root / "cfg_ws.json")
        # Mock native Windows folder picker so pick_folder can run headlessly in CI/tests
        core.workspaces.folder_picker = lambda title, init_dir: ws_picked

        srv = McpServer(("127.0.0.1", 0), Handler, core, cfg)
        port = srv.server_address[1]
        base = f"http://127.0.0.1:{port}"
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()

        def req(path, method="GET", body=None, bearer=tok):
            headers = {}
            if bearer:
                headers["Authorization"] = f"Bearer {bearer}"
            data = None
            if body is not None:
                data = json.dumps(body).encode("utf-8")
                headers["Content-Type"] = "application/json"
            r = urllib.request.Request(base + path, data=data, headers=headers, method=method)
            try:
                with urllib.request.urlopen(r, timeout=5) as resp:
                    return resp.status, json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                return exc.code, json.loads(exc.read().decode("utf-8"))

        try:
            # 1) Guard: OAuth access token rejected on /bridge/workspaces; control-plane file blocked from MCP write
            oauth_at, _ = srv.oauth.issue_tokens("google_ws_client")
            st_deny, body_deny = req("/bridge/workspaces", bearer=oauth_at)
            self.assertEqual(st_deny, 403)
            self.assertEqual(body_deny["error"], "local_admin_token_required")

            ws_store = self.root / "logs" / "bridge_workspaces.json"
            r_tamper = core.handle("tools/call", {
                "name": "write_file",
                "arguments": {"path": str(ws_store), "content": "{}"},
            })
            self.assertTrue(r_tamper["isError"])
            self.assertIn("control-plane", r_tamper["content"][0]["text"])

            # 2) Turn-1 pick_folder via Tampermonkey API: saves PickedGamma & binds Turn-1 tab_t1
            req("/bridge/heartbeat", method="POST", body={
                "tab_id": "tab_t1",
                "conversation_id": None,
                "url": "https://gemini.google.com/app",
                "is_generating": True,
            })
            st_pick, pick_res = req("/bridge/workspaces", method="POST", body={
                "action": "pick_folder",
                "tab_id": "tab_t1",
                "bind": True,
                "scope": "persistent",
            })
            self.assertEqual(st_pick, 200)
            self.assertFalse(pick_res["cancelled"])
            self.assertEqual(Path(pick_res["saved"]["path"]), ws_picked.resolve())
            self.assertEqual(Path(pick_res["binding"]["workspace_dir"]), ws_picked.resolve())

            # Turn-1 resolves to cid_gamma -> binding promotes to persistent cid_gamma
            _, hb_prom = req("/bridge/heartbeat", method="POST", body={
                "tab_id": "tab_t1",
                "conversation_id": "cid_gamma",
                "url": "https://gemini.google.com/app/cid_gamma",
                "is_generating": False,
            })
            self.assertEqual(Path(hb_prom["workspace_binding"]["workspace_dir"]), ws_picked.resolve())
            self.assertTrue(hb_prom["workspace_binding"]["is_custom"])

            # 3) Bind cid_a -> ws_a and verify full parity with default workspace!
            st_bind_a, bind_a = req("/bridge/workspaces", method="POST", body={
                "action": "bind",
                "conversation_id": "cid_a",
                "workspace_dir": str(ws_a),
                "scope": "persistent",
            })
            self.assertEqual(st_bind_a, 200)
            self.assertEqual(Path(bind_a["binding"]["workspace_dir"]), ws_a.resolve())

            req("/bridge/heartbeat", method="POST", body={
                "tab_id": "tab_a",
                "conversation_id": "cid_a",
                "url": "https://gemini.google.com/app/cid_a",
                "is_generating": True,
            })

            # workspace_status reports ws_a as default_workspace + merges Rule Alpha into text block
            r_ws_a = core.handle("tools/call", {"name": "workspace_status", "arguments": {}})
            ws_a_raw, sep_a, inj_a = r_ws_a["content"][0]["text"].partition("\n\n<workspace_rules")
            self.assertEqual(sep_a, "\n\n<workspace_rules")
            ws_a_status = json.loads(ws_a_raw)
            self.assertEqual(Path(ws_a_status["default_workspace"]), ws_a.resolve())
            self.assertTrue(ws_a_status["workspace_binding"]["is_switched"])
            self.assertIn("Rule Alpha: stay inside ProjectAlpha.", inj_a)

            # Relative list_dir(".") and read_file("alpha.txt") resolve inside ws_a!
            r_list_a = core.handle("tools/call", {"name": "list_dir", "arguments": {"path": "."}})
            self.assertIn("alpha.txt", r_list_a["content"][0]["text"])
            r_read_a = core.handle("tools/call", {"name": "read_file", "arguments": {"path": "alpha.txt"}})
            self.assertIn("from_alpha", r_read_a["content"][0]["text"])

            # Relative write_file + edit_file snapshot inside ws_a/.mcp_snapshots (Green Zone!)
            r_wr_a = core.handle("tools/call", {
                "name": "write_file",
                "arguments": {"path": "sub/out.txt", "content": "v1"},
            })
            self.assertFalse(r_wr_a["isError"])
            r_ed_a = core.handle("tools/call", {
                "name": "edit_file",
                "arguments": {"path": "sub/out.txt", "old_text": "v1", "new_text": "v2"},
            })
            self.assertFalse(r_ed_a["isError"])
            self.assertIn("snapshot:", r_ed_a["content"][0]["text"])
            self.assertTrue(any((ws_a / ".mcp_snapshots").glob("out.txt.*.bak")))
            self.assertFalse((self.ws / "sub").exists())

            # Python default cwd is ws_a, and oversized output bypasses into ws_a/.tmp_outputs!
            r_py_a = core.handle("tools/call", {
                "name": "python",
                "arguments": {"code": "import os; print(os.getcwd()); print('Z' * 1300)"},
            })
            py_txt = r_py_a["content"][0]["text"]
            self.assertIn(str(ws_a.resolve()), py_txt)
            self.assertTrue(any((ws_a / ".tmp_outputs").glob("cmd_*.log")))

            # While switched to ws_a, writing to server's original default_dir is Red Zone (denied)!
            r_cross = core.handle("tools/call", {
                "name": "write_file",
                "arguments": {"path": str(self.ws / "leak.txt"), "content": "nope"},
            })
            self.assertTrue(r_cross["isError"])
            self.assertIn("PermissionDenied", r_cross["content"][0]["text"])

            # 4) Concurrent second tab cid_b bound to ws_b stays completely isolated from cid_a!
            req("/bridge/workspaces", method="POST", body={
                "action": "bind",
                "conversation_id": "cid_b",
                "workspace_dir": str(ws_b),
                "scope": "session",
            })
            req("/bridge/heartbeat", method="POST", body={
                "tab_id": "tab_a",
                "conversation_id": "cid_a",
                "url": "https://gemini.google.com/app/cid_a",
                "is_generating": False,
            })
            req("/bridge/heartbeat", method="POST", body={
                "tab_id": "tab_b",
                "conversation_id": "cid_b",
                "url": "https://gemini.google.com/app/cid_b",
                "is_generating": True,
            })
            r_read_b = core.handle("tools/call", {"name": "read_file", "arguments": {"path": "beta.txt"}})
            self.assertIn("from_beta", r_read_b["content"][0]["text"])
            self.assertIn("Rule Beta: stay inside ProjectBeta.", r_read_b["content"][-1]["text"])

            # 5) Persistence across restart + unbind restores default workspace
            core2 = McpCore(cfg, config_path=self.root / "cfg_ws.json")
            saved_paths = [Path(x["path"]) for x in core2.workspaces.snapshot()["saved_workspaces"]]
            self.assertIn(ws_a.resolve(), saved_paths)
            self.assertIn(ws_b.resolve(), saved_paths)
            self.assertIn(ws_picked.resolve(), saved_paths)
            self.assertEqual(Path(core2.workspaces.get_effective_workspace(cid="cid_a")["workspace_dir"]), ws_a.resolve())
            self.assertFalse(core2.workspaces.get_effective_workspace(cid="cid_b")["is_custom"])  # session-scoped

            st_unb, unb_res = req("/bridge/workspaces", method="POST", body={
                "action": "unbind",
                "conversation_id": "cid_a",
            })
            self.assertEqual(st_unb, 200)
            self.assertFalse(unb_res["binding"]["is_custom"])
            self.assertEqual(Path(unb_res["binding"]["workspace_dir"]), self.ws.resolve())
        finally:
            srv.shutdown()
            srv.server_close()

    def test_native_readonly_search_and_switched_workspace(self):
        tok = "pcmcp_search_tok_123"
        cfg = deep_merge(self.cfg, {
            "auth": {"enabled": True, "token": tok},
            "permissions": {
                "per_conversation_enabled": True,
                "new_conversation_default_profile": "readonly",
                "approval_timeout_sec": 0.4,
            },
            "workspace": {"popup_approval": {"enabled": False}},
        })
        (self.ws / "src").mkdir(exist_ok=True)
        (self.ws / "src" / "alpha.py").write_text("def greet():\n    return 'HelloSearchWorld'\n", encoding="utf-8")
        (self.ws / ".git").mkdir(exist_ok=True)
        (self.ws / ".git" / "hidden.py").write_text("HelloSearchWorld\n", encoding="utf-8")
        (self.ws / "bin.dat").write_bytes(b"\x00\x01HelloSearchWorld")

        alt_ws = self.root / "SearchAlt"
        alt_ws.mkdir(parents=True, exist_ok=True)
        (alt_ws / "alt_mod.py").write_text("ALT_TOKEN = 'OnlyInAltWorkspace'\n", encoding="utf-8")

        core = McpCore(cfg, config_path=self.root / "cfg_search.json")
        # Connect single tab with readonly profile (no exec capability)
        core.bridge.heartbeat({
            "tab_id": "tab_ro",
            "conversation_id": "cid_ro",
            "url": "https://gemini.google.com/app/cid_ro",
            "is_generating": True,
        })

        # Verify readonly works for find_files, grep_search & push_file without hitting exec/write denial
        r_find = core.handle("tools/call", {"name": "find_files", "arguments": {"pattern": "*.py"}})
        self.assertFalse(r_find["isError"])
        find_txt = r_find["content"][0]["text"]
        self.assertIn("src/alpha.py", find_txt)
        self.assertNotIn(".git/hidden.py", find_txt)

        r_grep = core.handle("tools/call", {
            "name": "grep_search",
            "arguments": {"query": "HelloSearchWorld", "include": "*.py", "context_lines": 1},
        })
        self.assertFalse(r_grep["isError"])
        grep_txt = r_grep["content"][0]["text"]
        self.assertIn("src/alpha.py:2: ", grep_txt)
        self.assertNotIn("bin.dat", grep_txt)

        r_push_ro = core.handle("tools/call", {
            "name": "push_file",
            "arguments": {"path": "src/alpha.py", "inline_preview": False},
        })
        self.assertFalse(r_push_ro["isError"])
        push_ro_obj = json.loads(r_push_ro["content"][0]["text"])
        self.assertTrue(push_ro_obj["pushed"])
        self.assertIn("/files/", push_ro_obj["download_url"])

        # exec tool is still denied under readonly
        r_exec = core.handle("tools/call", {"name": "python", "arguments": {"code": "print(1)"}})
        self.assertTrue(r_exec["isError"])
        self.assertIn("PermissionDenied", r_exec["content"][0]["text"])

        # Switch workspace -> find_files & grep_search follow active_ws
        core.workspaces.bind_workspace(conversation_id="cid_ro", workspace_dir=str(alt_ws))
        r_grep_alt = core.handle("tools/call", {
            "name": "grep_search",
            "arguments": {"query": "OnlyInAltWorkspace"},
        })
        self.assertIn("alt_mod.py:1:", r_grep_alt["content"][0]["text"])
        self.assertNotIn("alpha.py", r_grep_alt["content"][0]["text"])

        # Custom workspace.ignored_dirs + built-in browser profile dirs are filtered cleanly across list_dir/find_files/grep_search
        (alt_ws / ".brave-agent-profile").mkdir(exist_ok=True)
        (alt_ws / ".brave-agent-profile" / "noise.py").write_text("NOISE_HIT\n", encoding="utf-8")
        (alt_ws / "legacy_v5_src").mkdir(exist_ok=True)
        (alt_ws / "legacy_v5_src" / "old.py").write_text("OLD_VERSION_HIT\n", encoding="utf-8")
        cfg_ign = deep_merge(cfg, {"workspace": {"ignored_dirs": ["legacy_v*"]}})
        core_ign = McpCore(cfg_ign, config_path=self.root / "cfg_ign.json")
        core_ign.bridge.heartbeat({
            "tab_id": "tab_ign",
            "conversation_id": "cid_ign",
            "url": "https://gemini.google.com/app/cid_ign",
            "is_generating": True,
        })
        core_ign.workspaces.bind_workspace(conversation_id="cid_ign", workspace_dir=str(alt_ws))
        list_ign = core_ign.handle("tools/call", {"name": "list_dir", "arguments": {"path": ".", "recursive": True}})["content"][0]["text"]
        self.assertNotIn(".brave-agent-profile", list_ign)
        self.assertNotIn("legacy_v5_src", list_ign)
        find_ign = core_ign.handle("tools/call", {"name": "find_files", "arguments": {"pattern": "*.py"}})["content"][0]["text"]
        self.assertNotIn("noise.py", find_ign)
        self.assertNotIn("old.py", find_ign)
        grep_ign = core_ign.handle("tools/call", {"name": "grep_search", "arguments": {"query": "HIT"}})["content"][0]["text"]
        self.assertIn("(no matches)", grep_ign)
        grep_incl = core_ign.handle("tools/call", {"name": "grep_search", "arguments": {"query": "OLD_VERSION_HIT", "include_ignored": True}})["content"][0]["text"]
        self.assertIn("legacy_v5_src/old.py", grep_incl)

    def test_post_edit_checks_syntax_and_exec_gate(self):
        tok = "pcmcp_checks_tok_123"
        cfg = deep_merge(self.cfg, {
            "auth": {"enabled": True, "token": tok},
            "permissions": {"per_conversation_enabled": True, "new_conversation_default_profile": "workspace"},
            "workspace": {"popup_approval": {"enabled": False}},
        })
        # Workspace check file that exits non-zero with structured failure text
        (self.ws / ".gemini").mkdir(exist_ok=True)
        (self.ws / ".gemini" / "checks.json").write_text(json.dumps({
            "enabled": True,
            "on_edit": True,
            "timeout_sec": 15,
            "commands": [
                {
                    "name": "mini_test",
                    "engine": "python",
                    "cmd": "import sys; print('FAIL_ASSERT_LINE_42'); sys.exit(1)",
                    "extensions": [".py"],
                }
            ],
        }), encoding="utf-8")

        core = McpCore(cfg, config_path=self.root / "cfg_chk.json")
        core.bridge.heartbeat({
            "tab_id": "tab_w",
            "conversation_id": "cid_chk",
            "url": "https://gemini.google.com/app/cid_chk",
            "is_generating": True,
        })

        # 1) Under 'workspace' profile (no exec): syntax check catches broken Python, workspace checks.json skipped safely!
        r_bad_py = core.handle("tools/call", {
            "name": "write_file",
            "arguments": {"path": "broken.py", "content": "def f(:\n    pass\n"},
        })
        self.assertFalse(r_bad_py["isError"])
        txt_bad = r_bad_py["content"][0]["text"]
        self.assertIn("python_syntax", txt_bad)
        self.assertIn('"ok": false', txt_bad)
        self.assertIn("workspace_checks_require_exec_capability", txt_bad)

        # Fix broken.py via edit_file -> syntax passes!
        r_fix_py = core.handle("tools/call", {
            "name": "edit_file",
            "arguments": {"path": "broken.py", "old_text": "def f(:", "new_text": "def f():"},
        })
        self.assertIn('"python_syntax: ok"', r_fix_py["content"][0]["text"])

        # JSON syntax check catches invalid JSON
        r_bad_json = core.handle("tools/call", {
            "name": "write_file",
            "arguments": {"path": "bad.json", "content": "{bad_json"},
        })
        self.assertIn("json_syntax", r_bad_json["content"][0]["text"])
        self.assertIn('"ok": false', r_bad_json["content"][0]["text"])

        # TOML syntax check (Python 3.11+ tomllib)
        r_ok_toml = core.handle("tools/call", {
            "name": "write_file",
            "arguments": {"path": "good.toml", "content": '[pkg]\nname = "pc-work-mcp"\n'},
        })
        self.assertIn('"toml_syntax: ok"', r_ok_toml["content"][0]["text"])
        r_bad_toml = core.handle("tools/call", {
            "name": "write_file",
            "arguments": {"path": "bad.toml", "content": '[pkg\nname = 123\n'},
        })
        self.assertIn("toml_syntax", r_bad_toml["content"][0]["text"])
        self.assertIn('"ok": false', r_bad_toml["content"][0]["text"])

        # PowerShell syntax check via Language.Parser (when pwsh_exe is available on Windows)
        if core.runner.pwsh_exe:
            r_ok_ps1 = core.handle("tools/call", {
                "name": "write_file",
                "arguments": {"path": "ok_script.ps1", "content": "# 中文注释\nWrite-Output 'ok'\n"},
            })
            self.assertIn('"powershell_syntax: ok"', r_ok_ps1["content"][0]["text"])
            r_bad_ps1 = core.handle("tools/call", {
                "name": "write_file",
                "arguments": {"path": "bad_script.ps1", "content": "if ($true {\n  Write-Output 'oops'\n"},
            })
            self.assertIn("powershell_syntax", r_bad_ps1["content"][0]["text"])
            self.assertIn('"ok": false', r_bad_ps1["content"][0]["text"])

        # 2) Grant 'full' (includes exec) -> .gemini/checks.json command executes and feeds back failure lines!
        core.permissions.set_policy(conversation_id="cid_chk", profile="full", scope="persistent")
        r_full_edit = core.handle("tools/call", {
            "name": "edit_file",
            "arguments": {"path": "broken.py", "old_text": "pass", "new_text": "return 1"},
        })
        txt_full = r_full_edit["content"][0]["text"]
        self.assertIn("mini_test", txt_full)
        self.assertIn("FAIL_ASSERT_LINE_42", txt_full)
        self.assertIn('"exit_code": 1', txt_full)

    def test_task_plan_and_bounded_self_wake_bridge(self):
        tok = "pcmcp_plan_tok_123"
        cfg = deep_merge(self.cfg, {
            "auth": {"enabled": True, "token": tok},
            "permissions": {"per_conversation_enabled": True, "new_conversation_default_profile": "workspace"},
            "workspace": {"popup_approval": {"enabled": False}},
            "task_plan": {"default_max_auto_turns": 2, "min_cooldown_sec": 5, "max_handoff_chars": 80},
        })
        core = McpCore(cfg, config_path=self.root / "cfg_plan.json")
        srv = McpServer(("127.0.0.1", 0), Handler, core, cfg)
        port = srv.server_address[1]
        base = f"http://127.0.0.1:{port}"
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            def req(path, method="GET", body=None, token=tok):
                data = json.dumps(body).encode("utf-8") if body is not None else None
                headers = {"Authorization": f"Bearer {token}"} if token else {}
                if data is not None:
                    headers["Content-Type"] = "application/json"
                r = urllib.request.Request(base + path, data=data, headers=headers, method=method)
                try:
                    with urllib.request.urlopen(r, timeout=5) as resp:
                        return resp.status, json.loads(resp.read().decode("utf-8"))
                except urllib.error.HTTPError as exc:
                    return exc.code, json.loads(exc.read().decode("utf-8"))

            # Protected write guard blocks direct MCP overwrite of logs/task_plans.json
            core.bridge.heartbeat({"tab_id": "tab_p1", "conversation_id": None, "url": "https://gemini.google.com/app", "is_generating": True})
            r_prot = core.handle("tools/call", {
                "name": "write_file",
                "arguments": {"path": str(self.root / "logs" / "task_plans.json"), "content": "{}"},
            })
            self.assertTrue(r_prot["isError"])
            self.assertIn("PermissionDenied", r_prot["content"][0]["text"])

            # Turn-1 (/app): set plan (mark step 1 in_progress) + schedule_continue -> awaits cid; quota NOT deducted yet
            r_set = core.handle("tools/call", {
                "name": "task_plan",
                "arguments": {
                    "action": "set",
                    "goal": "Refactor core module and verify",
                    "steps": [
                        {"title": "Inspect module", "status": "in_progress"},
                        "Patch bug",
                        "Run tests",
                    ],
                },
            })
            set_obj = json.loads(r_set["content"][0]["text"])
            self.assertEqual(set_obj["plan"]["progress"], "0/3")

            long_handoff = "A" * 140  # Exceeds max_handoff_chars=80 -> clipped tightly
            r_sched_dup = core.handle("tools/call", {
                "name": "task_plan",
                "arguments": {"action": "schedule_continue", "handoff": "Superseded draft"},
            })
            dup_obj = json.loads(r_sched_dup["content"][0]["text"])
            r_sched = core.handle("tools/call", {
                "name": "task_plan",
                "arguments": {"action": "schedule_continue", "handoff": long_handoff, "delay_sec": 1},
            })
            sched_obj = json.loads(r_sched["content"][0]["text"])
            self.assertEqual(sched_obj["task"]["kind"], "continue_turn")
            self.assertEqual(sched_obj["task"]["status"], "awaiting_cid")
            self.assertEqual(sched_obj["task"]["delay_sec"], 5)  # Clamped to min_cooldown_sec=5
            self.assertEqual(sched_obj["scheduled_turn_index"], 1)  # Superseding draft did NOT burn turn 1
            self.assertEqual(sched_obj["plan"]["auto_turns_used"], 0)
            self.assertLessEqual(len(sched_obj["plan"]["last_handoff"]), 80)
            self.assertEqual(core.bridge.get_task(dup_obj["task"]["task_id"])["status"], "cancelled")

            # Turn-1 settles to cid_plan_99 -> promotes plan + unqueues continue_turn; quota still 0 until actually sent
            _, hb = req("/bridge/heartbeat", method="POST", body={
                "tab_id": "tab_p1",
                "conversation_id": "cid_plan_99",
                "url": "https://gemini.google.com/app/cid_plan_99",
                "is_generating": False,
            })
            self.assertIn(sched_obj["task"]["task_id"], hb["resolved_tasks"])
            self.assertEqual(hb["task_plan"]["auto_turns_used"], 0)

            _, poll = req("/bridge/tasks?tab_id=tab_p1&conversation_id=cid_plan_99")
            self.assertEqual(len(poll["actions"]), 1)
            self.assertEqual(poll["actions"][0]["action"], "continue_turn")
            wake_prompt = poll["actions"][0]["task"]["prompt"]
            self.assertIn("进行中[#1:Inspect module]", wake_prompt)
            self.assertIn("下步待办[#2:Patch bug]", wake_prompt)
            self.assertIn("无需再调 task_plan(get)", wake_prompt)
            req("/bridge/task_result", method="POST", body={
                "task_id": sched_obj["task"]["task_id"],
                "status": "completed",
                "conversation_id": "cid_plan_99",
            })
            self.assertEqual(core.task_plans.get_plan(cid="cid_plan_99", tab_id="tab_p1")["plan"]["auto_turns_used"], 1)

            # Failed send does NOT burn quota
            core.bridge.heartbeat({
                "tab_id": "tab_p1",
                "conversation_id": "cid_plan_99",
                "url": "https://gemini.google.com/app/cid_plan_99",
                "is_generating": True,
            })
            core.handle("tools/call", {
                "name": "task_plan",
                "arguments": {"action": "update", "step_updates": [{"id": 1, "status": "done"}]},
            })
            r_fail = core.handle("tools/call", {
                "name": "task_plan",
                "arguments": {"action": "schedule_continue", "handoff": "Retry step 2"},
            })
            fail_obj = json.loads(r_fail["content"][0]["text"])
            req("/bridge/task_result", method="POST", body={
                "task_id": fail_obj["task"]["task_id"],
                "status": "failed",
                "error": "input_box_not_found",
                "conversation_id": "cid_plan_99",
            })
            self.assertEqual(core.task_plans.get_plan(cid="cid_plan_99", tab_id="tab_p1")["plan"]["auto_turns_used"], 1)

            # Turn 2 wakeup completes -> auto_turns_used reaches max_auto_turns=2 -> 3rd schedule rejected
            r_sched2 = core.handle("tools/call", {
                "name": "task_plan",
                "arguments": {"action": "schedule_continue", "handoff": "Run step 2"},
            })
            sched2 = json.loads(r_sched2["content"][0]["text"])
            self.assertEqual(sched2["scheduled_turn_index"], 2)
            req("/bridge/task_result", method="POST", body={
                "task_id": sched2["task"]["task_id"],
                "status": "completed",
                "conversation_id": "cid_plan_99",
            })
            self.assertEqual(core.task_plans.get_plan(cid="cid_plan_99", tab_id="tab_p1")["plan"]["auto_turns_used"], 2)

            with self.assertRaises(JsonRpcError):
                core.handle("tools/call", {
                    "name": "task_plan",
                    "arguments": {"action": "schedule_continue", "handoff": "Exceed cap"},
                })

            # Reset plan, queue a new continue_turn, and verify stop button cancels pending continue_turn
            core.handle("tools/call", {
                "name": "task_plan",
                "arguments": {"action": "set", "goal": "Cancel check", "steps": ["Only step"]},
            })
            r_sched3 = core.handle("tools/call", {
                "name": "task_plan",
                "arguments": {"action": "schedule_continue", "handoff": "Pending before stop"},
            })
            sched3 = json.loads(r_sched3["content"][0]["text"])
            st_stop, stop_res = req("/bridge/task_plan", method="POST", body={
                "action": "stop",
                "conversation_id": "cid_plan_99",
                "tab_id": "tab_p1",
            })
            self.assertEqual(st_stop, 200)
            self.assertIn(sched3["task"]["task_id"], stop_res["cancelled_task_ids"])
            self.assertEqual(stop_res["plan"]["status"], "stopped")
            self.assertEqual(stop_res["plan"]["auto_turns_used"], 0)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_startup_dual_stack_tcp_self_check_lock(self):
        # 0) Default config keeps startup_tcp_check=False so running without domain/proxy never exits unexpectedly
        self.assertFalse(DEFAULT_CONFIG["oauth"]["startup_tcp_check"])

        # 1) Loopback / RFC1918 / non-global addresses are cleanly skipped; public domain runs probe
        self.assertEqual(verify_public_tcp_reachability("https://127.0.0.1:15672")["status"], "skipped")
        self.assertEqual(verify_public_tcp_reachability("https://192.0.2.10:15672")["status"], "skipped")
        self.assertEqual(verify_public_tcp_reachability("https://pub.example.com:15672", probe_fn=lambda h, p, fam: {"state": "open"})["status"], "reachable")

        # 2) China broadband IPv6-only scenario: IPv4 dns_missing/timeout while IPv6 open -> reachable!
        def v6_only_probe(host, port, fam):
            if fam == "6":
                return {"state": "open", "provider": "mock", "family": "6"}
            return {"state": "dns_missing", "provider": "mock", "family": "4"}

        res_v6 = verify_public_tcp_reachability("https://ddns.example.com:14769", probe_fn=v6_only_probe)
        self.assertEqual(res_v6["status"], "reachable")
        self.assertEqual(res_v6["reachable_families"], ["IPv6"])

        # 3) External probe API outage -> unavailable (does not brick startup)
        res_api_down = verify_public_tcp_reachability(
            "https://ddns.example.com:14769",
            probe_fn=lambda h, p, fam: {"state": "api_error", "provider": "mock", "family": fam},
        )
        self.assertEqual(res_api_down["status"], "unavailable")

        # 4) Explicit startup_tcp_check=True with unreachable endpoint aborts server_main with exit code 2
        from unittest.mock import patch
        cfg_path = self.root / "lock_cfg.json"
        lock_cfg = deep_merge(DEFAULT_CONFIG, {
            "auth": {"enabled": True, "token": "pcmcp_lock_test_tok"},
            "listen": {"host": "127.0.0.1", "port": 0},
            "oauth": {"enabled": True, "public_base_url": "https://dead.example.com:14769", "startup_tcp_check": True},
            "workspace": {"initialized": True, "default_dir": str(self.ws)},
            "exec": {"workdir": str(self.ws)},
            "push": {"outbox_dir": str(self.root / "outbox")},
            "log": {"file": str(self.root / "logs" / "lock.log")},
        })
        cfg_path.write_text(json.dumps(lock_cfg), encoding="utf-8")

        with patch("server.verify_public_tcp_reachability", return_value={
            "status": "unreachable",
            "host": "dead.example.com",
            "port": 14769,
            "reachable_families": [],
            "families": {"ipv6": {"state": "closed"}, "ipv4": {"state": "dns_missing"}},
        }) as mock_probe:
            rc_locked = server_main(["--config", str(cfg_path)])
            self.assertEqual(rc_locked, 2)
            rc_cli_chk = server_main(["--config", str(cfg_path), "--check-public-url"])
            self.assertEqual(rc_cli_chk, 2)
            self.assertGreaterEqual(mock_probe.call_count, 2)

        # 5) Bridge /bridge/public_url & /bridge/check_public_url require local admin token and allow Tampermonkey testing + save
        tok = "pcmcp_pub_bridge_tok"
        srv_cfg = deep_merge(self.cfg, {
            "auth": {"enabled": True, "token": tok},
            "oauth": {"enabled": True, "public_base_url": "", "startup_tcp_check": False},
        })
        bridge_cfg_path = self.root / "bridge_pub_cfg.json"
        bridge_cfg_path.write_text(json.dumps(srv_cfg), encoding="utf-8")
        core = McpCore(srv_cfg, config_path=bridge_cfg_path)
        srv = McpServer(("127.0.0.1", 0), Handler, core, srv_cfg)
        port = srv.server_address[1]
        base = f"http://127.0.0.1:{port}"
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            def call(path, method="GET", body=None, bearer=tok):
                headers = {"Authorization": f"Bearer {bearer}"}
                data = None
                if body is not None:
                    data = json.dumps(body).encode("utf-8")
                    headers["Content-Type"] = "application/json"
                req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
                try:
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        return resp.status, json.loads(resp.read().decode("utf-8"))
                except urllib.error.HTTPError as he:
                    return he.code, json.loads(he.read().decode("utf-8"))

            # Unregistered token gets 401; real Google OAuth access token gets 403
            st_unauth, _ = call("/bridge/public_url", bearer="invalid_token")
            self.assertEqual(st_unauth, 401)
            oauth_at, _ = srv.oauth.issue_tokens("google_client_pub")
            st_forbid, _ = call("/bridge/public_url", bearer=oauth_at)
            self.assertEqual(st_forbid, 403)

            st0, g0 = call("/bridge/public_url")
            self.assertEqual(st0, 200)
            self.assertFalse(g0["startup_tcp_check"])
            self.assertEqual(g0["public_base_url"], "")

            with patch("server.verify_public_tcp_reachability", return_value={
                "status": "reachable",
                "host": "pub.example.com",
                "port": 14769,
                "reachable_families": ["IPv6"],
                "families": {"ipv6": {"state": "open"}, "ipv4": {"state": "dns_missing"}},
            }):
                st1, p1 = call("/bridge/check_public_url", method="POST", body={
                    "public_base_url": "https://pub.example.com:14769/",
                    "save": True,
                })
            self.assertEqual(st1, 200)
            self.assertTrue(p1["saved"])
            self.assertEqual(p1["public_base_url"], "https://pub.example.com:14769")
            self.assertEqual(p1["check"]["status"], "reachable")
            self.assertEqual(srv.oauth.configured_base, "https://pub.example.com:14769")
            saved_disk = json.loads(bridge_cfg_path.read_text(encoding="utf-8"))
            self.assertEqual(saved_disk["oauth"]["public_base_url"], "https://pub.example.com:14769")
        finally:
            srv.shutdown()
            srv.server_close()

    def test_global_whitelist_cross_conversation_and_bridge_api(self):
        diary_rw = self.root / "my_diary_rw"
        diary_rw.mkdir(parents=True, exist_ok=True)
        (diary_rw / "2026-11-26.md").write_text("today note alpha", encoding="utf-8")

        notes_ro = self.root / "archive_ro"
        notes_ro.mkdir(parents=True, exist_ok=True)
        (notes_ro / "ref.txt").write_text("readonly reference", encoding="utf-8")

        outside_dir = self.root / "outside_other"
        outside_dir.mkdir(parents=True, exist_ok=True)
        (outside_dir / "secret.txt").write_text("outside secret", encoding="utf-8")

        tok = "pcmcp_wl_admin_tok"
        cfg_path = self.root / "wl_cfg.json"
        wl_cfg = deep_merge(self.cfg, {
            "auth": {"enabled": True, "token": tok},
            "oauth": {"enabled": True, "public_base_url": "https://pcmcp.example.com:14769"},
            "workspace": {
                "initialized": True,
                "default_dir": str(self.ws),
                "extra_allowed_dirs": [
                    str(diary_rw),  # Legacy string format -> readwrite, allow_exec=False
                    {"path": str(notes_ro), "mode": "readonly", "label": "ArchiveRO"},
                ],
                "popup_approval": {"enabled": False, "timeout_sec": 5},
            },
            "permissions": {
                "per_conversation_enabled": True,
                "new_conversation_default_profile": "ask",
                "approval_timeout_sec": 5,
            },
        })
        cfg_path.write_text(json.dumps(wl_cfg), encoding="utf-8")
        core = McpCore(wl_cfg, approval_cb=lambda *a: (False, False), config_path=cfg_path)
        srv = McpServer(("127.0.0.1", 0), Handler, core, wl_cfg)
        port = srv.server_address[1]
        base = f"http://127.0.0.1:{port}"
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()

        def req(path, method="GET", body=None, bearer=tok):
            headers = {"Authorization": f"Bearer {bearer}"} if bearer else {}
            data = None
            if body is not None:
                data = json.dumps(body).encode("utf-8")
                headers["Content-Type"] = "application/json"
            r = urllib.request.Request(base + path, data=data, headers=headers, method=method)
            try:
                with urllib.request.urlopen(r, timeout=8) as resp:
                    return resp.status, json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                return exc.code, json.loads(exc.read().decode("utf-8"))

        try:
            # 1) New conversation on default "ask" profile: reads & writes inside readwrite whitelist succeed without prompt
            core.bridge.heartbeat({
                "tab_id": "tab_wl_1",
                "conversation_id": "cid_wl_chat1",
                "url": "https://gemini.google.com/app/cid_wl_chat1",
                "is_generating": True,
            })

            st_ws = core.handle("tools/call", {"name": "workspace_status", "arguments": {}})
            ws_obj = json.loads(st_ws["content"][0]["text"])
            wl_paths = {w["path"]: w for w in ws_obj["global_whitelist"]}
            self.assertEqual(wl_paths[str(diary_rw.resolve())]["mode"], "readwrite")
            self.assertEqual(wl_paths[str(notes_ro.resolve())]["mode"], "readonly")

            r_list = core.handle("tools/call", {"name": "list_dir", "arguments": {"path": str(diary_rw)}})
            self.assertFalse(r_list["isError"])
            self.assertIn("2026-11-26.md", r_list["content"][0]["text"])

            r_find = core.handle("tools/call", {"name": "find_files", "arguments": {"path": str(diary_rw), "pattern": "*.md"}})
            self.assertFalse(r_find["isError"])
            self.assertIn("2026-11-26.md", r_find["content"][0]["text"])

            r_grep = core.handle("tools/call", {"name": "grep_search", "arguments": {"path": str(diary_rw), "query": "alpha"}})
            self.assertFalse(r_grep["isError"])
            self.assertIn("today note alpha", r_grep["content"][0]["text"])

            r_read = core.handle("tools/call", {"name": "read_file", "arguments": {"path": str(diary_rw / "2026-11-26.md")}})
            self.assertFalse(r_read["isError"])
            self.assertIn("today note alpha", r_read["content"][0]["text"])

            r_write = core.handle("tools/call", {
                "name": "write_file",
                "arguments": {"path": str(diary_rw / "new_entry.md"), "content": "written from ask chat"},
            })
            self.assertFalse(r_write["isError"])
            self.assertEqual((diary_rw / "new_entry.md").read_text(encoding="utf-8"), "written from ask chat")

            r_edit = core.handle("tools/call", {
                "name": "edit_file",
                "arguments": {"path": str(diary_rw / "new_entry.md"), "old_text": "ask chat", "new_text": "edited ask chat"},
            })
            self.assertFalse(r_edit["isError"])
            self.assertEqual((diary_rw / "new_entry.md").read_text(encoding="utf-8"), "written from edited ask chat")

            r_bupl = core.handle("tools/call", {
                "name": "bridge_upload_media",
                "arguments": {"files": [str(diary_rw / "new_entry.md")], "prompt": "read diary"},
            })
            self.assertFalse(r_bupl["isError"])
            r_bsav = core.handle("tools/call", {
                "name": "bridge_save_generated_media",
                "arguments": {"target_path": str(diary_rw / "generated")},
            })
            self.assertFalse(r_bsav["isError"])

            # 2) Readonly whitelist entry allows read/search/push_file, blocks write_file
            r_ro_read = core.handle("tools/call", {"name": "read_file", "arguments": {"path": str(notes_ro / "ref.txt")}})
            self.assertFalse(r_ro_read["isError"])
            self.assertIn("readonly reference", r_ro_read["content"][0]["text"])

            r_ro_push = core.handle("tools/call", {
                "name": "push_file",
                "arguments": {"path": str(notes_ro / "ref.txt"), "inline_preview": False},
            })
            self.assertFalse(r_ro_push["isError"])
            self.assertTrue(json.loads(r_ro_push["content"][0]["text"])["pushed"])

            core.permissions.approval_timeout_sec = 1
            r_ro_write = core.handle("tools/call", {
                "name": "write_file",
                "arguments": {"path": str(notes_ro / "mutate.txt"), "content": "nope"},
            })
            self.assertTrue(r_ro_write["isError"])
            self.assertFalse((notes_ro / "mutate.txt").exists())

            # Normal outside path STILL blocked under "ask"
            r_out = core.handle("tools/call", {"name": "read_file", "arguments": {"path": str(outside_dir / "secret.txt")}})
            self.assertTrue(r_out["isError"])

            # Default allow_exec=False STILL gates python even with cwd inside whitelist
            r_exec_blocked = core.handle("tools/call", {
                "name": "python",
                "arguments": {"code": "print(1+1)", "cwd": str(diary_rw)},
            })
            self.assertTrue(r_exec_blocked["isError"])

            # 3) Control plane /bridge/whitelist security + CRUD + hot reload + allow_exec
            oauth_at, _ = srv.oauth.issue_tokens("google_wl_client")
            st_forbid, _ = req("/bridge/whitelist", bearer=oauth_at)
            self.assertEqual(st_forbid, 403)
            st_unauth, _ = req("/bridge/whitelist", bearer="bad_tok")
            self.assertEqual(st_unauth, 401)

            dynamic_dir = self.root / "dynamic_notes"
            dynamic_dir.mkdir(parents=True, exist_ok=True)
            (dynamic_dir / "hello.md").write_text("dynamic hi", encoding="utf-8")

            st_add, add_res = req("/bridge/whitelist", method="POST", body={
                "action": "add",
                "path": f'"{dynamic_dir}"',
                "mode": "readwrite",
                "allow_exec": False,
            })
            self.assertEqual(st_add, 200)
            self.assertTrue(any(e["path"] == str(dynamic_dir.resolve()) for e in add_res["entries"]))

            saved_cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
            self.assertTrue(any(
                isinstance(x, dict) and x.get("path") == str(dynamic_dir.resolve())
                for x in saved_cfg["workspace"]["extra_allowed_dirs"]
            ))

            # Immediately readable without restart in the same "ask" conversation
            r_dyn = core.handle("tools/call", {"name": "read_file", "arguments": {"path": str(dynamic_dir / "hello.md")}})
            self.assertFalse(r_dyn["isError"])
            self.assertIn("dynamic hi", r_dyn["content"][0]["text"])

            # Enable allow_exec=True for diary_rw -> cwd=diary_rw passes without external write, but writing outside still blocks
            st_upd, upd_res = req("/bridge/whitelist", method="POST", body={
                "action": "update",
                "path": str(diary_rw),
                "allow_exec": True,
            })
            self.assertEqual(st_upd, 200)
            self.assertTrue(upd_res["entry"]["allow_exec"])

            r_py_ok = core.handle("tools/call", {
                "name": "python",
                "arguments": {"code": "print('WL_EXEC_OK')", "cwd": str(diary_rw)},
            })
            self.assertFalse(r_py_ok["isError"])
            self.assertIn("WL_EXEC_OK", r_py_ok["content"][0]["text"])

            r_py_escape = core.handle("tools/call", {
                "name": "python",
                "arguments": {
                    "code": f"open(r'{outside_dir / 'evil.txt'}', 'w').write('x')",
                    "cwd": str(diary_rw),
                },
            })
            self.assertTrue(r_py_escape["isError"])
            self.assertFalse((outside_dir / "evil.txt").exists())

            # Protected control-plane files remain unmodifiable even if parent folder is whitelisted
            st_add_root, _ = req("/bridge/whitelist", method="POST", body={
                "action": "add",
                "path": str(self.root),
                "mode": "readwrite",
            })
            self.assertEqual(st_add_root, 200)
            r_prot = core.handle("tools/call", {
                "name": "write_file",
                "arguments": {"path": str(cfg_path), "content": "{}"},
            })
            self.assertTrue(r_prot["isError"])
            self.assertIn("PermissionDenied", r_prot["content"][0]["text"])

            # Removing entry revokes instant access on "ask"
            st_rem, _ = req("/bridge/whitelist", method="POST", body={"action": "remove", "path": str(self.root)})
            self.assertEqual(st_rem, 200)
            st_rem2, _ = req("/bridge/whitelist", method="POST", body={"action": "remove", "path": str(dynamic_dir)})
            self.assertEqual(st_rem2, 200)
            r_revoked = core.handle("tools/call", {"name": "read_file", "arguments": {"path": str(dynamic_dir / "hello.md")}})
            self.assertTrue(r_revoked["isError"])

            # 4) Explicit "deny" conversation profile ALWAYS wins even over global whitelist
            core.permissions.set_policy(conversation_id="cid_wl_chat1", profile="deny", scope="persistent")
            r_denied = core.handle("tools/call", {"name": "read_file", "arguments": {"path": str(diary_rw / "2026-11-26.md")}})
            self.assertTrue(r_denied["isError"])
            self.assertIn("禁止", r_denied["content"][0]["text"])

            # 5) Blocked prefix cannot be added to global whitelist
            st_blk, _ = req("/bridge/whitelist", method="POST", body={
                "action": "add",
                "path": str(self.blocked),
            })
            self.assertEqual(st_blk, 400)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_bridge_ignored_dirs_management_and_async_suggestion(self):
        tok = "pcmcp_ign_tok_777"
        cfg_path = self.root / "cfg_ign_bridge.json"
        cfg = deep_merge(self.cfg, {
            "auth": {"enabled": True, "token": tok},
            "permissions": {"per_conversation_enabled": True, "new_conversation_default_profile": "readonly"},
            "workspace": {"popup_approval": {"enabled": False}, "ignored_dirs": []},
        })
        cfg_path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
        core = McpCore(cfg, config_path=cfg_path)
        srv = McpServer(("127.0.0.1", 0), Handler, core, cfg)
        port = srv.server_address[1]
        base = f"http://127.0.0.1:{port}"
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            def req(path, method="GET", body=None, bearer=tok):
                data = json.dumps(body).encode("utf-8") if body is not None else None
                headers = {"Authorization": f"Bearer {bearer}"} if bearer else {}
                if data is not None:
                    headers["Content-Type"] = "application/json"
                r = urllib.request.Request(base + path, data=data, headers=headers, method=method)
                try:
                    with urllib.request.urlopen(r, timeout=5) as resp:
                        return resp.status, json.loads(resp.read().decode("utf-8"))
                except urllib.error.HTTPError as exc:
                    return exc.code, json.loads(exc.read().decode("utf-8"))

            noisy_dir = self.ws / "noisy_logs"
            noisy_dir.mkdir(exist_ok=True)
            (noisy_dir / "trace.py").write_text("NOISY_TRACE_TOKEN = 1\n", encoding="utf-8")
            keep_dir = self.ws / "keep_src"
            keep_dir.mkdir(exist_ok=True)
            (keep_dir / "app.py").write_text("CLEAN_APP = 1\n", encoding="utf-8")

            # 1) Local-admin token gate rejects Google OAuth at_* tokens
            oauth_at, _ = srv.oauth.issue_tokens("google_ign_client")
            st_forb, _ = req("/bridge/ignored_dirs", bearer=oauth_at)
            self.assertEqual(st_forb, 403)

            # 2) Direct Tampermonkey /bridge/ignored_dirs CRUD persists to config.json & hot-reloads
            st_add, add_res = req("/bridge/ignored_dirs", method="POST", body={
                "action": "add",
                "dirs": [str(self.ws / "temp_build"), "legacy_*"],
            })
            self.assertEqual(st_add, 200)
            self.assertIn("temp_build", add_res["ignored_dirs"])
            self.assertIn("legacy_*", add_res["ignored_dirs"])
            saved = json.loads(cfg_path.read_text(encoding="utf-8"))
            self.assertIn("temp_build", saved["workspace"]["ignored_dirs"])

            st_rem, rem_res = req("/bridge/ignored_dirs", method="POST", body={
                "action": "remove",
                "dir": "temp_build",
            })
            self.assertEqual(st_rem, 200)
            self.assertNotIn("temp_build", rem_res["ignored_dirs"])

            # 3) Turn-1 (/app): agent sees noisy_logs -> pushes async suggestion & stops
            core.bridge.heartbeat({
                "tab_id": "tab_ign1",
                "conversation_id": None,
                "url": "https://gemini.google.com/app",
                "is_generating": True,
            })
            r_sug = core.handle("tools/call", {
                "name": "bridge_suggest_ignore_dirs",
                "arguments": {
                    "dirs": [str(noisy_dir), "cache_dump"],
                    "reason": "根目录检索杂音过多",
                },
            })
            self.assertFalse(r_sug["isError"])
            sug_obj = json.loads(r_sug["content"][0]["text"])
            self.assertTrue(sug_obj["queued"])
            self.assertEqual(sug_obj["dirs"], ["noisy_logs", "cache_dump"])
            self.assertIn("停止当前回合", sug_obj["instruction"])

            # Turn-1 settles to cid_ign_888 -> suggestion promotes & appears in heartbeat
            _, hb = req("/bridge/heartbeat", method="POST", body={
                "tab_id": "tab_ign1",
                "conversation_id": "cid_ign_888",
                "url": "https://gemini.google.com/app/cid_ign_888",
                "is_generating": False,
            })
            self.assertEqual(len(hb["pending_ignore_suggestions"]), 1)
            self.assertEqual(hb["pending_ignore_suggestions"][0]["suggestion_id"], sug_obj["suggestion_id"])

            # 4) User approves only ["noisy_logs"] from popup -> persisted permanently & hot-applied to list_dir/find_files/grep
            st_dec, dec_res = req("/bridge/ignored_dirs/decision", method="POST", body={
                "suggestion_id": sug_obj["suggestion_id"],
                "decision": "approve",
                "dirs": ["noisy_logs"],
            })
            self.assertEqual(st_dec, 200)
            self.assertIn("noisy_logs", dec_res["ignored_dirs"])
            self.assertNotIn("cache_dump", dec_res["ignored_dirs"])
            saved_after = json.loads(cfg_path.read_text(encoding="utf-8"))
            self.assertIn("noisy_logs", saved_after["workspace"]["ignored_dirs"])

            _, hb2 = req("/bridge/heartbeat", method="POST", body={
                "tab_id": "tab_ign1",
                "conversation_id": "cid_ign_888",
                "url": "https://gemini.google.com/app/cid_ign_888",
                "is_generating": False,
            })
            self.assertEqual(hb2["pending_ignore_suggestions"], [])

            r_list = core.handle("tools/call", {"name": "list_dir", "arguments": {"path": "."}})
            self.assertNotIn("noisy_logs", r_list["content"][0]["text"])
            self.assertIn("keep_src", r_list["content"][0]["text"])

            # Suggesting already-ignored dir returns queued=False without nagging user
            r_dup = core.handle("tools/call", {
                "name": "bridge_suggest_ignore_dirs",
                "arguments": {"dirs": ["noisy_logs"]},
            })
            dup_obj = json.loads(r_dup["content"][0]["text"])
            self.assertFalse(dup_obj["queued"])
            self.assertTrue(dup_obj["already_ignored"])
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
