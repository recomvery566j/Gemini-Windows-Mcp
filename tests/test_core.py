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
    deep_merge,
    ensure_first_run_workspace,
    is_local_token_configured,
    issue_local_token,
    main as server_main,
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

    def test_output_guard_bypass(self):
        og = OutputGuard(self.ws / ".tmp_outputs", max_inline_chars=1200, head_chars=300, tail_chars=300)
        big = "\n".join(f"row-{i:04d}" for i in range(500))
        out, log_path = og.format_or_bypass(big, prefix="unit")
        self.assertIsNotNone(log_path)
        self.assertTrue(log_path.is_file())
        self.assertIn(".tmp_outputs", out)
        self.assertLess(len(out), len(big))

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
        self.assertEqual(len(names), 20)
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

    def test_first_run_workspace_selection_and_copy(self):
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
        }

        cfg1 = fake_src / "config.json"
        cfg1.write_text(json.dumps(fresh_cfg), encoding="utf-8")
        fake_desktop = self.root / "Desktop"
        res_desktop = ensure_first_run_workspace(
            cfg1,
            requested_workspace=None,
            interactive=False,
            desktop_dir=fake_desktop,
            source_root=fake_src,
        )
        expected_ws = (fake_desktop / "pc-work-mcp-workspace").resolve()
        self.assertTrue(res_desktop["initialized_now"])
        self.assertEqual(Path(res_desktop["workspace_dir"]), expected_ws)
        self.assertTrue((expected_ws / "server.py").is_file())
        self.assertTrue((expected_ws / "security.py").is_file())
        self.assertFalse((expected_ws / "__pycache__").exists())
        self.assertFalse((expected_ws / "logs" / "old.log").exists())
        self.assertTrue((expected_ws / "logs").is_dir())
        self.assertTrue((expected_ws / "outbox").is_dir())
        ws_cfg1 = json.loads((expected_ws / "config.json").read_text(encoding="utf-8"))
        self.assertTrue(ws_cfg1["workspace"]["initialized"])
        self.assertEqual(ws_cfg1["workspace"]["default_dir"], str(expected_ws))

        res_again = ensure_first_run_workspace(cfg1, interactive=False, desktop_dir=fake_desktop, source_root=fake_src)
        self.assertFalse(res_again["initialized_now"])

        cfg2 = self.root / "cfg2.json"
        cfg2.write_text(json.dumps(fresh_cfg), encoding="utf-8")
        custom_ws = self.root / "CustomAgentWS"
        res_custom = ensure_first_run_workspace(
            cfg2,
            requested_workspace=str(custom_ws),
            interactive=False,
            desktop_dir=fake_desktop,
            source_root=fake_src,
        )
        self.assertTrue(res_custom["initialized_now"])
        self.assertEqual(Path(res_custom["workspace_dir"]), custom_ws.resolve())
        self.assertTrue((custom_ws / "server.py").is_file())
        tok_res = issue_local_token(cfg2)
        self.assertTrue(tok_res["issued"])
        synced = json.loads((custom_ws / "config.json").read_text(encoding="utf-8"))
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
        from workspace_rules import DEFAULT_REINJECT_EVERY_CALLS, DEFAULT_REINJECT_EVERY_OUTPUT_CHARS

        # Verify production defaults match the quantitative cadence (20 calls / 48,000 output chars)
        default_core = McpCore(self.cfg, approval_cb=lambda *a: (False, False))
        self.assertEqual(default_core.rules.reinject_every_calls, 20)
        self.assertEqual(default_core.rules.reinject_every_output_chars, 48000)
        self.assertEqual(DEFAULT_REINJECT_EVERY_CALLS, 20)
        self.assertEqual(DEFAULT_REINJECT_EVERY_OUTPUT_CHARS, 48000)

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

            # 2) Create AGENTS.md and .gemini/rules/01-style.md mid-session -> immediate rules_changed injection
            agents_md = self.ws / "AGENTS.md"
            agents_md.write_text("Rule Alpha: verify everything.", encoding="utf-8")
            rules_sub = self.ws / ".gemini" / "rules"
            rules_sub.mkdir(parents=True, exist_ok=True)
            style_md = rules_sub / "01-style.md"
            style_md.write_text("Style: keep concise.", encoding="utf-8")

            r_changed = core.handle("tools/call", {"name": "workspace_status", "arguments": {}})
            self.assertEqual(len(r_changed["content"]), 3)
            # content[0] remains clean JSON and content[1] remains canary PNG while content[2] holds <workspace_rules>
            ws_changed_obj = json.loads(r_changed["content"][0]["text"])
            self.assertEqual(len(ws_changed_obj["workspace_rules"]["detected_files"]), 2)
            self.assertEqual(r_changed["content"][1]["type"], "image")
            inj1 = r_changed["content"][2]["text"]
            self.assertIn('reason="rules_changed"', inj1)
            self.assertIn("Rule Alpha: verify everything.", inj1)
            self.assertIn("Style: keep concise.", inj1)

            # 3) Next 2 small calls (< 3 calls, < 600 output chars) do NOT re-inject
            r_c1 = core.handle("tools/call", {"name": "read_file", "arguments": {"path": str(small_file)}})
            self.assertEqual(len(r_c1["content"]), 1)
            r_c2 = core.handle("tools/call", {"name": "read_file", "arguments": {"path": str(small_file)}})
            self.assertEqual(len(r_c2["content"]), 1)

            # 4) 3rd call since last injection hits reinject_every_calls=3 -> periodic_calls
            r_c3 = core.handle("tools/call", {"name": "read_file", "arguments": {"path": str(small_file)}})
            self.assertEqual(len(r_c3["content"]), 2)
            self.assertIn('reason="periodic_calls"', r_c3["content"][1]["text"])

            # 5) Big tool output (>= 600 chars) triggers output_volume early on the very first call after periodic
            big_file = self.ws / "big.txt"
            big_file.write_text("X" * 700, encoding="utf-8")
            r_big = core.handle("tools/call", {"name": "read_file", "arguments": {"path": str(big_file)}})
            self.assertEqual(len(r_big["content"]), 2)
            self.assertIn('reason="output_volume"', r_big["content"][1]["text"])

            # 6) Edit AGENTS.md -> next call immediately detects SHA change (rules_changed)
            agents_md.write_text("Rule Beta: updated instructions.", encoding="utf-8")
            r_edit = core.handle("tools/call", {"name": "read_file", "arguments": {"path": str(small_file)}})
            self.assertEqual(len(r_edit["content"]), 2)
            self.assertIn('reason="rules_changed"', r_edit["content"][1]["text"])
            self.assertIn("Rule Beta: updated instructions.", r_edit["content"][1]["text"])

            # 7) Remove all rule files -> emits rules_removed once, then stops injecting
            agents_md.unlink()
            style_md.unlink()
            r_rem = core.handle("tools/call", {"name": "read_file", "arguments": {"path": str(small_file)}})
            self.assertEqual(len(r_rem["content"]), 2)
            self.assertIn('reason="rules_removed"', r_rem["content"][1]["text"])
            r_after_rem = core.handle("tools/call", {"name": "read_file", "arguments": {"path": str(small_file)}})
            self.assertEqual(len(r_after_rem["content"]), 1)

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

            # Two distinct Mcp-Session-Id sessions each get their own Turn-1 initial injection
            _, rpc_a1 = req("/mcp", method="POST", bearer=tok, extra_headers={"Mcp-Session-Id": "ses_alpha"}, body={
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": str(small_file)}},
            })
            self.assertEqual(len(rpc_a1["result"]["content"]), 2)
            self.assertIn('reason="initial"', rpc_a1["result"]["content"][1]["text"])

            _, rpc_a2 = req("/mcp", method="POST", bearer=tok, extra_headers={"Mcp-Session-Id": "ses_alpha"}, body={
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": str(small_file)}},
            })
            self.assertEqual(len(rpc_a2["result"]["content"]), 1)

            _, rpc_b1 = req("/mcp", method="POST", bearer=tok, extra_headers={"Mcp-Session-Id": "ses_beta"}, body={
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": str(small_file)}},
            })
            self.assertEqual(len(rpc_b1["result"]["content"]), 2)
            self.assertIn('reason="initial"', rpc_b1["result"]["content"][1]["text"])

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
            self.assertEqual(len(res_t1["content"]), 2)
            self.assertIn("Default Workspace Rule.", res_t1["content"][1]["text"])

            # Promote tab_r1 -> cid_r1_promoted; next call must NOT double-inject
            req("/bridge/heartbeat", method="POST", body={
                "tab_id": "tab_r1",
                "conversation_id": "cid_r1_promoted",
                "url": "https://gemini.google.com/app/cid_r1_promoted",
                "is_generating": True,
            })
            res_t2 = core.handle("tools/call", {"name": "read_file", "arguments": {"path": str(small_file)}})
            self.assertEqual(len(res_t2["content"]), 1)

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
            self.assertEqual(len(res_proj_b["content"]), 2)
            self.assertIn("Project B Exclusive Rule.", res_proj_b["content"][1]["text"])

            # Force reset via /bridge/rules -> next call re-injects
            st_rst, _ = req("/bridge/rules", method="POST", body={
                "action": "reset_session",
                "conversation_id": "cid_r1_promoted",
            })
            self.assertEqual(st_rst, 200)
            res_rst = core.handle("tools/call", {"name": "read_file", "arguments": {"path": str(small_file)}})
            self.assertEqual(len(res_rst["content"]), 2)
            self.assertIn("Project B Exclusive Rule.", res_rst["content"][1]["text"])

            # Returning tab_r1 to blank /app starts a clean new conversation with Default Workspace Rule
            req("/bridge/heartbeat", method="POST", body={
                "tab_id": "tab_r1",
                "conversation_id": None,
                "url": "https://gemini.google.com/app",
                "is_generating": True,
            })
            res_fresh = core.handle("tools/call", {"name": "read_file", "arguments": {"path": str(small_file)}})
            self.assertEqual(len(res_fresh["content"]), 2)
            self.assertIn('reason="initial"', res_fresh["content"][1]["text"])
            self.assertIn("Default Workspace Rule.", res_fresh["content"][1]["text"])
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

            # workspace_status reports ws_a as default_workspace + injects Rule Alpha
            r_ws_a = core.handle("tools/call", {"name": "workspace_status", "arguments": {}})
            ws_a_status = json.loads(r_ws_a["content"][0]["text"])
            self.assertEqual(Path(ws_a_status["default_workspace"]), ws_a.resolve())
            self.assertTrue(ws_a_status["workspace_binding"]["is_switched"])
            self.assertIn("Rule Alpha: stay inside ProjectAlpha.", r_ws_a["content"][-1]["text"])

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

        # Verify readonly works for find_files & grep_search without hitting exec denial
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

            # Turn-1 (/app): set plan + schedule_continue -> awaits cid
            r_set = core.handle("tools/call", {
                "name": "task_plan",
                "arguments": {
                    "action": "set",
                    "goal": "Refactor core module and verify",
                    "steps": ["Inspect module", "Patch bug", "Run tests"],
                },
            })
            set_obj = json.loads(r_set["content"][0]["text"])
            self.assertEqual(set_obj["plan"]["progress"], "0/3")

            long_handoff = "A" * 140  # Exceeds max_handoff_chars=80 -> clipped tightly
            r_sched = core.handle("tools/call", {
                "name": "task_plan",
                "arguments": {"action": "schedule_continue", "handoff": long_handoff, "delay_sec": 1},
            })
            sched_obj = json.loads(r_sched["content"][0]["text"])
            self.assertEqual(sched_obj["task"]["kind"], "continue_turn")
            self.assertEqual(sched_obj["task"]["status"], "awaiting_cid")
            self.assertEqual(sched_obj["task"]["delay_sec"], 5)  # Clamped to min_cooldown_sec=5
            self.assertLessEqual(len(sched_obj["plan"]["last_handoff"]), 80)

            # Turn-1 settles to cid_plan_99 -> promotes plan + unqueues continue_turn
            _, hb = req("/bridge/heartbeat", method="POST", body={
                "tab_id": "tab_p1",
                "conversation_id": "cid_plan_99",
                "url": "https://gemini.google.com/app/cid_plan_99",
                "is_generating": False,
            })
            self.assertIn(sched_obj["task"]["task_id"], hb["resolved_tasks"])
            self.assertEqual(hb["task_plan"]["auto_turns_used"], 1)

            _, poll = req("/bridge/tasks?tab_id=tab_p1&conversation_id=cid_plan_99")
            self.assertEqual(len(poll["actions"]), 1)
            self.assertEqual(poll["actions"][0]["action"], "continue_turn")
            req("/bridge/task_result", method="POST", body={
                "task_id": sched_obj["task"]["task_id"],
                "status": "completed",
                "conversation_id": "cid_plan_99",
            })

            # Turn 2 wakeup + hit max_auto_turns=2 -> 3rd schedule rejected
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
            r_sched2 = core.handle("tools/call", {
                "name": "task_plan",
                "arguments": {"action": "schedule_continue", "handoff": "Run step 2"},
            })
            sched2 = json.loads(r_sched2["content"][0]["text"])
            self.assertEqual(sched2["plan"]["auto_turns_used"], 2)

            with self.assertRaises(JsonRpcError):
                core.handle("tools/call", {
                    "name": "task_plan",
                    "arguments": {"action": "schedule_continue", "handoff": "Exceed cap"},
                })

            # User clicks stop on Tampermonkey chip -> cancels pending continue_turn & sets stopped
            st_stop, stop_res = req("/bridge/task_plan", method="POST", body={
                "action": "stop",
                "conversation_id": "cid_plan_99",
                "tab_id": "tab_p1",
            })
            self.assertEqual(st_stop, 200)
            self.assertIn(sched2["task"]["task_id"], stop_res["cancelled_task_ids"])
            self.assertEqual(stop_res["plan"]["status"], "stopped")
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
