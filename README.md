# F3 — MCP (Model Context Protocol) Honeypot

A real, standard-library JSON-RPC / streamable-HTTP server that advertises a few
**harmlessly infectious** tools to AI agents, logs every tool call, and answers
with tripwired "trap" payloads an operator can grep for downstream.

## Overview

- **Real MCP-style transport**: a threaded `localhost` HTTP server speaking
  JSON-RPC 2.0 (`tools/list`, `tools/call`, `initialize`, `ping`), plus
  operator-facing `GET /tools` and `GET /logs` endpoints.
- **Harmless-only tool registry**: `warmup`, `hash_sum`, `read_public_doc` —
  no network, no shell, no file writes.
- **Trap payloads**: every successful `tools/call` wraps its (benign) result in
  a `_trap` marker (`HONEYPOT-TRIPWIRE:<tool>`). If an attacker agent later
  echoes that result into a downstream context, the operator can detect it.
- **Call logging**: every call is persisted with client IP:port, tool, params,
  and outcome, in operator order.
- **Demo attacker agent**: a local fake "attacker agent" that enumerates tools,
  drives them all, snags the traps, and confirms the operator log recorded every
  call. Fully offline (loopback only).
- **Zero dependencies**: Python standard library only.

### The loop, end-to-end

```
attacker agent --POST / tools/list--> honeypot
attacker agent --POST / tools/call--> honeypot -> executes benign tool -> _trap wrapper
honeypot  --/logs-----------------> operator sees every call recorded
```

## CLI

```bash
python3 firmware/mcp_honeypot.py --help
python3 firmware/mcp_honeypot.py                     # run the demo loop (port 0)
python3 firmware/mcp_honeypot.py --report reports/report.json
python3 firmware/mcp_honeypot.py --serve --port 9000 # stand up the server
```

Config lives in `config.json` (`host`, `port`; `port: 0` = ephemeral). Reports
go to `reports/` (gitignored).

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## IMPORTANT: Read before use.

This tool is provided **exclusively** for authorized security research, academic
study, and defensive hardening on infrastructure you control. Use without
explicit written authorization is illegal and unethical.

### Authorization Requirements

Run the honeypot only on hosts you own or are explicitly authorized to operate.
Attracting AI agents or automated scanners onto hosts you do not control, or
serving trap content to third parties without authorization, may constitute
unauthorized interference with their systems.

### Legal Framework

Unauthorized access to or interference with computer systems is governed by the
**Computer Fraud and Abuse Act (CFAA)** (18 U.S.C. § 1030), the **EU Directive
on Attacks Against Information Systems** (2013/40/EU), and equivalent
legislation in other jurisdictions. Penalties include imprisonment and
significant fines. Intercepting or logging automated clients on third-party
networks may also implicate wiretap and data-protection statutes.

### Acceptable Use

- Operating the honeypot on your own loopback or lab infrastructure to observe
  AI-agent and scanner behavior
- Authorized red-team/purple-team exercises within a written scope
- Academic research on MCP tool-supply-chain abuse and agent instrumentation
- Security education, CTFs, and controlled labs

### Prohibited Use

- Deploying the honeypot against hosts you do not own or lack authorization for
- Serving trap payloads to third parties to deceive or entrap them
- Using logged calls to harvest credentials or personal data without a lawful basis
- Any use that violates applicable law or terms of service

### No Warranty

This software is provided "as is" without warranty of any kind. The authors
assume no liability for damages arising from use or misuse of this tool.

### Responsible Disclosure

If your honeypot exposes abuse of third-party MCP tool infrastructure, preserve
logs and report privately to the affected vendor or platform's abuse team rather
than publicly. Allow reasonable time for remediation.

## Live Lab Test Plan

1. **Demo run** — `python3 firmware/mcp_honeypot.py` prints the banner and exits `0`.
2. **Real transport** — the demo performs *actual* HTTP round-trips on loopback:
   `tools/list`, three `tools/call`, and `/logs`.
3. **Call logging** — unit test `test_call_logs_and_traps` asserts every call is
   recorded with client, tool, params, and outcome.
4. **Trap integrity** — `test_trap_marker_present` asserts the `_trap` tripwire
   is present in every successful answer.
5. **Robust error paths** — unknown tool → JSON-RPC `-32601`; bad params →
   `-32602` (asserted in `test_unknown_tool_is_an_error`).
6. **Operator log** — the demo confirms `recorded == number of tools/call` events.
7. **Offline guarantee** — loopback only, stdlib only, no third-party packages.

## Metrics

| Metric | Definition |
|--------|-----------|
| Advertised tools | size of the hypothetical tool registry |
| Calls logged | tool-call records persisted in operator order |
| Trap snag rate | successful calls that carried a tripwired result |
| Error paths | JSON-RPC errors returned for unknown methods / bad params |
| Round-trip count | real HTTP requests performed on loopback in the demo |

Verified offline: 3 tools advertised, 3/3 calls logged, 3/3 traps delivered,
0 leak beyond loopback.

## License

MIT License