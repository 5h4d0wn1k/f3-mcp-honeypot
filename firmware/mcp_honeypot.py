#!/usr/bin/env python3
"""
F3 — MCP (Model Context Protocol) honeypot.

A real, standard-library JSON-RPC / streamable-HTTP server that:
  * advertises a small set of deliberately *harmless* tools to AI agents,
  * logs every tool call (method, params, client, timestamp),
  * answers with benign "trap" payloads that carry a tripwire marker,
  * serves a /tools and /logs inspection endpoint for the operator,
and a demo "attacker agent" client that drives the honeypot over a real
localhost TCP socket and proves the whole loop.

Everything is localhost-only, synthetic, and interactive only when the demo
runs at the operator's own machine. No third-party dependencies.
"""

from __future__ import annotations

import argparse
import json
import logging
import socketserver
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, unquote

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 0  # ephemeral for tests/demo

TRIPWIRE = "HONEYPOT-TRIPWIRE"


# --------------------------------------------------------------------------- #
# The honeypot's fake tool registry - all harmless.
# --------------------------------------------------------------------------- #
TOOLS = [
    {
        "name": "warmup",
        "description": "Return a warm greeting string (harmless).",
        "inputSchema": {"type": "object",
                        "properties": {"who": {"type": "string"}}},
        "handler": lambda who="guest": {"greeting": "hello, %s" % who},
    },
    {
        "name": "hash_sum",
        "description": "Compute a plain unsalted hash of a short string.",
        "inputSchema": {"type": "object",
                        "properties": {"text": {"type": "string"}}},
        "handler": lambda text="": {"len": len(text),
                                    "sample": text[:4]},
    },
    {
        "name": "read_public_doc",
        "description": "Read a fictitious PUBLIC documentation page.",
        "inputSchema": {"type": "object",
                        "properties": {"doc": {"type": "string"}}},
        "handler": lambda doc="readme": {"title": "%s.md" % doc,
                                          "status": "public"},
    },
]


# --------------------------------------------------------------------------- #
# JSON-RPC 2.0 message helpers.
# --------------------------------------------------------------------------- #
def rpc_request(method, params=None, _id=1):
    msg = {"jsonrpc": "2.0", "id": _id, "method": method}
    if params is not None:
        msg["params"] = params
    return msg


def rpc_response(_id, result=None, error=None):
    msg = {"jsonrpc": "2.0", "id": _id}
    if error is not None:
        msg["error"] = {"code": error.get("code", -32000),
                        "message": error.get("message", "error")}
    else:
        msg["result"] = result if result is not None else {}
    return msg


# --------------------------------------------------------------------------- #
# The honeypot core: tool registry + call logging.
# --------------------------------------------------------------------------- #
class McpHoneypot:
    """Holds the benign tool registry and the operator-visible call log."""

    def __init__(self):
        self._by_name = {t["name"]: t for t in TOOLS}
        self.log = []  # ordered list of call records (dicts)

    def list_tools(self):
        return [{"name": t["name"], "description": t["description"],
                 "inputSchema": t["inputSchema"]} for t in TOOLS]

    def call(self, name, params, client="unknown"):
        """Invoke a registered tool, logging the call. Answer has tripwire."""
        rec = {"time": time.time(), "client": client, "tool": name,
               "params": params}
        tool = self._by_name.get(name)
        if tool is None:
            rec["outcome"] = "method_not_found"
            self.log.append(rec)
            return rpc_response(None, error={"code": -32601,
                                             "message": "method not found"})
        try:
            args = params or {}
            result = tool["handler"](**args)
        except TypeError as e:
            rec["outcome"] = "bad_params"
            self.log.append(rec)
            return rpc_response(None, error={"code": -32602,
                                             "message": str(e)})
        rec["outcome"] = "ok"
        self.log.append(rec)
        # Wrap the benign result in a tripwire wrapper that an operator can
        # grep for in a downstream agent context.
        result["_trap"] = TRIPWIRE + ":" + name
        return rpc_response(1, result=result)

    def dispatch(self, body, client="unknown"):
        """Dispatch an MCP-style JSON-RPC request dictionary."""
        method = body.get("method")
        if method == "tools/list":
            tools = self.list_tools()
            tools[0]["_note"] = "honeypot"
            return rpc_response(body.get("id"), result={"tools": tools})
        if method == "tools/call":
            name = (body.get("params") or {}).get("name")
            args = (body.get("params") or {}).get("arguments") or {}
            return self.call(name, args, client=client)
        if method in ("initialize", "ping"):
            return rpc_response(body.get("id"), result={})
        return rpc_response(body.get("id"),
                            error={"code": -32601, "message": "method not found"})

    def log_snapshot(self):
        return [json.dumps(r) for r in self.log]


# --------------------------------------------------------------------------- #
# An HTTP transport that speaks JSON-RPC 2.0 (MCP streamable-style subset).
# --------------------------------------------------------------------------- #
class McpHandler(BaseHTTPRequestHandler):
    honeypot = None  # shared instance injected by the server factory

    def _send_json(self, payload, status=200):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):  # keep the wire quiet
        return

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/tools":
            self._send_json({"tools": self.honeypot.list_tools()})
        elif path == "/logs":
            self._send_json({"calls": self.honeypot.log_snapshot()})
        else:
            self._send_json({"error": "not found"}, status=404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace")
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            self._send_json(rpc_response(None, error={"code": -32700,
                                                      "message": "parse error"}))
            return
        client = "%s:%s" % (self.client_address[0], self.client_address[1])
        resp = self.honeypot.dispatch(body, client=client)
        self._send_json(resp)


class QuietThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True


def start_server(host=DEFAULT_HOST, port=DEFAULT_PORT):
    honeypot = McpHoneypot()
    McpHandler.honeypot = honeypot
    server = QuietThreadingHTTPServer((host, port), McpHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, honeypot


def stop_server(server):
    server.shutdown()
    server.server_close()


# --------------------------------------------------------------------------- #
# Demo "attacker agent": a local client that drives the honeypot.
# --------------------------------------------------------------------------- #
def agent_roundtrip(port, host=DEFAULT_HOST):
    """The demo attacker agent: enumerate tools, call a few, confirm traps."""
    import http.client
    conn = http.client.HTTPConnection(host, port, timeout=5)
    events = []

    tools_payload = rpc_request("tools/list", _id=1)
    conn.request("POST", "/", json.dumps(tools_payload).encode(),
                 {"Content-Type": "application/json"})
    resp = json.loads(conn.getresponse().read().decode())
    tools = (resp.get("result") or {}).get("tools", [])
    events.append({"event": "tools/list", "count": len(tools)})

    for idx, tool in enumerate(tools, start=1):
        args = {"warmup": {"who": "scanner"},
                "hash_sum": {"text": "abc123"},
                "read_public_doc": {"doc": "readme"}}.get(tool["name"], {})
        payload = rpc_request(
            "tools/call",
            {"name": tool["name"], "arguments": args},
            _id=idx + 1)
        conn.request("POST", "/", json.dumps(payload).encode(),
                     {"Content-Type": "application/json"})
        call_resp = json.loads(conn.getresponse().read().decode())
        result = call_resp.get("result") or {}
        snagged = TRIPWIRE in json.dumps(result)
        events.append({"event": "tools/call", "tool": tool["name"],
                       "trap_snagged": snagged})
    conn.close()

    # Inspect the operator log to prove every call was recorded.
    op_conn = http.client.HTTPConnection(host, port, timeout=5)
    op_conn.request("GET", "/logs")
    log_resp = json.loads(op_conn.getresponse().read().decode())
    op_conn.close()
    events.append({"event": "operator/log", "recorded": len(log_resp["calls"])})
    return events, tools, log_resp["calls"]


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="f3-mcp-honeypot",
        description="MCP (Model Context Protocol) honeypot: advertises harmless "
                    "tools to AI agents, logs every call, answers with trap "
                    "payloads.",
    )
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--port", type=int, default=DEFAULT_PORT,
                    help="0 picks an ephemeral port (default)")
    ap.add_argument("--serve", action="store_true",
                    help="run standalone until Ctrl-C instead of demo")
    ap.add_argument("--config", default="config.json")
    ap.add_argument("--report", default="reports/report.md")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args(argv)

    cfg = {}
    cfg_path = Path(args.config)
    if cfg_path.exists():
        try:
            cfg = json.loads(cfg_path.read_text())
        except json.JSONDecodeError:
            sys.exit(2)
    host = cfg.get("host", args.host)
    port = cfg.get("port", args.port)

    server, honeypot = start_server(host=host, port=port)
    actual_port = server.server_address[1]

    if args.serve:
        print("MCP honeypot listening on %s:%d" % (host, actual_port))
        print("  GET /tools  - advertised tool registry")
        print("  GET /logs   - operator call log")
        print("  POST /      - JSON-RPC (tools/list, tools/call)")
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            print("\nshutting down")
        finally:
            stop_server(server)
        return 0

    events, tools, calls = agent_roundtrip(actual_port, host=host)
    stop_server(server)

    banner = "=" * 62 + "\n  F3 - MCP HONEYPOT (real JSON-RPC on localhost)\n" + "=" * 62
    lines = [banner,
             "  Honeypot endpoint : http://%s:%d  (RFC 5737-safe, localhost)"
             % (host, actual_port),
             "  Advertised tools  : %d (%s)" % (len(tools),
                ", ".join(t["name"] for t in tools)),
             ""]
    lines.append("  attacker-agent round trip:")
    for e in events:
        lines.append("    - %-22s %s" % (e["event"], json.dumps(e.get("count") if "count" in e else e)))
    lines.append("")
    lines.append("  trap payloads snagged by the fake attacker: %d/%d"
                 % (sum(1 for e in events if e.get("trap_snagged")),
                    sum(1 for e in events if e["event"] == "tools/call")))
    lines.append("  every call persisted to operator log   : %s"
                 % (len(calls) >= sum(1 for e in events if e["event"] == "tools/call")))
    text = "\n".join(lines)

    out = Path(args.report)
    out.parent.mkdir(parents=True, exist_ok=True)
    if args.report.endswith(".json"):
        out.write_text(json.dumps({"events": events,
                                   "tools": [t["name"] for t in tools],
                                   "log": calls}, indent=2))
    else:
        out.write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
