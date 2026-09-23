> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# F3 — MCP Honeypot (AI-Agent Decoy & Fingerprinter)

Standard-library JSON-RPC / streamable-HTTP honeypot that advertises harmlessly infectious tools to AI agents, logs every tool call, and answers with tripwired `_trap` payloads an operator can grep downstream.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/5h4d0wn1k/f3-mcp-honeypot.svg)](https://github.com/5h4d0wn1k/f3-mcp-honeypot)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/f3-mcp-honeypot.svg)](https://github.com/5h4d0wn1k/f3-mcp-honeypot)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/f3-mcp-honeypot.svg)](https://github.com/5h4d0wn1k/f3-mcp-honeypot)

## Why

AI agents are the new attack surface — and the new tool-supply-chain risk. F3 builds the defensive instrument to study them: a real MCP-style HTTP server speaking JSON-RPC 2.0 (`tools/list`, `tools/call`, `initialize`, `ping`) that lures automated clients into calling benign tools, logs every call with client IP:port, params and outcome, and marks every successful answer with a `HONEYPOT-TRIPWIRE:<tool>` tag. If an attacker agent later echoes a tripwired result into downstream context, the operator can spot it. Nothing harmful runs — the tool registry is `warmup`, `hash_sum`, `read_public_doc` — and the entire demo operates on loopback.

## Features

- **Real MCP-style transport** — threaded localhost HTTP server with JSON-RPC 2.0 methods plus operator-facing `GET /tools` and `GET /logs`
- **Harmless-only tool registry** — `warmup`, `hash_sum`, `read_public_doc`; no network, no shell, no file writes
- **Trap payloads** — every successful `tools/call` wraps its result in a `_trap` tripwire marker
- **Full call logging** — client IP:port, tool, params and outcome, in operator order
- **Demo attacker agent** — drives all tools, snags the traps, confirms the operator log
- **Zero dependencies** — Python standard library only, loopback only

## Quickstart

```bash
git clone https://github.com/5h4d0wn1k/f3-mcp-honeypot.git && cd f3-mcp-honeypot

# Run the demo loop (port 0 = ephemeral; writes a report, exit 0)
python3 firmware/mcp_honeypot.py

# Stand the server up for inspection
python3 firmware/mcp_honeypot.py --serve --port 9000

# Custom report path
python3 firmware/mcp_honeypot.py --report reports/report.json

# Unit tests
python3 -m unittest discover -s tests
```

Config lives in `config.json` (`host`, `port`); reports go to `reports/` (gitignored).

## Project structure

- `firmware/mcp_honeypot.py` — JSON-RPC server, tool registry, trap wrapping, demo attacker agent, CLI
- `config.json` — server defaults (host, port); `tests/` — unit tests over logging, traps and error paths

## Documentation

- [ETHICS.md](ETHICS.md) — educational purpose and authorized use only
- [SCOPE.md](SCOPE.md) — authorized-testing scope checklist
- [SECURITY.md](SECURITY.md) — vulnerability reporting
- [CONTRIBUTING.md](CONTRIBUTING.md) — safe contribution guidelines

## Contributing

New decoy tools, trap formats and logging features are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md); the honeypot runs only on hosts you own or are authorized to operate.

## License

MIT — see [LICENSE](LICENSE). Provided **AS IS**, without warranty, for education and authorized AI-agent security research only.