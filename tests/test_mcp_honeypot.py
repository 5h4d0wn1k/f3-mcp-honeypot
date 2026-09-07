import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from firmware.mcp_honeypot import (  # noqa: E402
    TRIPWIRE,
    McpHoneypot,
    agent_roundtrip,
    main,
    rpc_request,
    rpc_response,
    start_server,
    stop_server,
)


class RpcHelpersTest(unittest.TestCase):
    def test_request_shape(self):
        msg = rpc_request("tools/list", _id=7)
        self.assertEqual(msg["jsonrpc"], "2.0")
        self.assertEqual(msg["id"], 7)
        self.assertEqual(msg["method"], "tools/list")

    def test_response_shape(self):
        msg = rpc_response(1, result={"ok": True})
        self.assertEqual(msg["result"], {"ok": True})
        self.assertNotIn("error", msg)
        err = rpc_response(1, error={"code": -32601})
        self.assertEqual(err["error"]["code"], -32601)


class HoneypotTest(unittest.TestCase):
    def setUp(self):
        self.hp = McpHoneypot()

    def test_list_tools_is_harmless_set(self):
        tools = self.hp.list_tools()
        names = {t["name"] for t in tools}
        self.assertIn("warmup", names)
        self.assertIn("read_public_doc", names)
        for t in tools:
            self.assertIn("inputSchema", t)

    def test_call_logs_and_traps(self):
        resp = self.hp.call("warmup", {"who": "agent-x"}, client="198.51.100.1:1")
        self.assertIn("result", resp)
        self.assertIn("greeting", resp["result"])
        self.assertEqual(len(self.hp.log), 1)
        rec = self.hp.log[0]
        self.assertEqual(rec["tool"], "warmup")
        self.assertEqual(rec["client"], "198.51.100.1:1")
        self.assertEqual(rec["outcome"], "ok")

    def test_trap_marker_present(self):
        resp = self.hp.call("hash_sum", {"text": "zzz"}, client="c")
        self.assertIn("_trap", resp["result"])
        self.assertTrue(TRIPWIRE in resp["result"]["_trap"])

    def test_unknown_tool_is_an_error(self):
        resp = self.hp.call("ftpd", {}, client="c")
        self.assertEqual(resp["error"]["code"], -32601)

    def test_dispatch_tools_call(self):
        body = rpc_request("tools/call",
                           {"name": "read_public_doc",
                            "arguments": {"doc": "readme"}}, _id=3)
        resp = self.hp.dispatch(body, client="203.0.113.9:2")
        self.assertIn("result", resp)
        self.assertEqual(resp["result"]["status"], "public")

    def test_dispatch_method_not_found(self):
        resp = self.hp.dispatch(rpc_request("nope", _id=1), client="c")
        self.assertEqual(resp["error"]["code"], -32601)

    def test_log_snapshot_is_json(self):
        self.hp.call("warmup", {}, client="c")
        snap = self.hp.log_snapshot()
        self.assertEqual(len(snap), 1)
        json.loads(snap[0])


class ServerTest(unittest.TestCase):
    def test_full_roundtrip_on_localhost(self):
        server, _ = start_server(port=0)
        port = server.server_address[1]
        try:
            events, tools, calls = agent_roundtrip(port)
            self.assertGreater(len(tools), 2)
            call_events = [e for e in events if e["event"] == "tools/call"]
            self.assertEqual(len(call_events), len(tools))
            for e in call_events:
                self.assertTrue(e["trap_snagged"])
            self.assertEqual(len(calls), len(tools))
        finally:
            stop_server(server)


class CliTest(unittest.TestCase):
    def test_main_demo_exit_zero(self):
        with tempfile.TemporaryDirectory() as td:
            rp = os.path.join(td, "report.md")
            code = main(["--report", rp])
            self.assertEqual(code, 0)
            self.assertTrue(os.path.exists(rp))

    def test_main_json_report(self):
        with tempfile.TemporaryDirectory() as td:
            rp = os.path.join(td, "report.json")
            code = main(["--report", rp])
            self.assertEqual(code, 0)
            data = json.loads(open(rp).read())
            self.assertIn("events", data)


if __name__ == "__main__":
    unittest.main()