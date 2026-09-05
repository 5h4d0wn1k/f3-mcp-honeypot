# F3 — MCP / Tool Supply-Chain Honeypot + Name-Squatting Radar

Offline tooling for detecting MCP/tool supply-chain abuse: name-squatting radar, canary-description monitoring, PyPI-name hallucination checks, and a description-injection linter.

## Overview

- **Typosquatting-name generator**: produces edit-distance variants (missing/double char, transposition, lookalike substitution, hyphen/underscore swap, prefix/suffix squatting) of a known package or MCP server name
- **Canary-description monitor**: embeds a unique canary token in tool descriptions and logs which consumer retrieves or configures them
- **PyPI-name-hallucination checker**: validates claimed PyPI names against a small embedded registry index
- **Description-injection linter**: flags tool/MCP configs whose descriptions contain malicious tokens, embedded code blocks, overlong text, repeated n-grams, or imperative pressure
- **Radar report + linter findings**: render a full report table on embedded sample configs
- Fully offline and deterministic — standard library only

## Features

- **Edit-Distance Variants**: missing-char, double-char, transposition, vowel/lookalike substitution, separator swap, and prefix/suffix kits
- **Levenshtein Radar**: ranks registered names near your package by edit distance and flags confusable ones (distance ≤ 2)
- **Canary Planting + Retrieval Detection**: token-seeded descriptions exposed to consumers; any fetch/config logs the consumer identity
- **Hallucination Guard**: known-name check for claimed PyPI imports, encouraging verification before trust
- **Injection Linter**: multi-pattern scanner (`ignore previous instructions`, `exfil*`, `base64`, `powershell`, `curl`/`wget`, etc.) plus overlong/duplication/imperative heuristics
- **Zero Dependencies**: Python standard library only

## Installation

No external dependencies required — uses Python standard library only.

```bash
python3 firmware/mcp_honeypot.py
```

## Usage

```python
from firmware.mcp_honeypot import typosquat_radar, lint_configs
from firmware.mcp_honeypot import CanaryMonitor, check_hallucination

# 1. Radar: is "requests" being squatted in your monitored registry?
hits, n_generated = typosquat_radar("requests", {"requestz", "requests-sdk"})
for dist, cand in hits:
    print(dist, cand)

# 2. Lint tool/MCP descriptions
findings = lint_configs(sample_configs())
print([f["name"] for f in findings if not f["safe"]])

# 3. Canary monitor on your own MCP registry
m = CanaryMonitor()
desc = m.plant("Sync CloudWatch alarms to ops pager")
m.observe_fetch("suspicious-agent", desc)      # logs it
print(m.report())

# 4. Hallucination guard before trusting a claimed dependency
_, unknown = check_hallucination(["reqests-ultra"])
print(unknown)
```

## Example Output

```
======================================================================
  F3 - MCP / TOOL-SUPPLY-CHAIN HONEYPOT - RADAR REPORT
======================================================================
  Known package  : requests
  Variants generated : 42

  SQUATTED NAMES FOUND (levenshtein distance from 'requests'):
----------------------------------------------------------------------
  Registered name                  distance   confusable
  request                          1          YES
  requestz                         1          YES
  requezts                         1          YES
  reqeusts                         2          YES
...
======================================================================
  F3 - DESCRIPTION-INJECTION LINTER (tool/MCP configs)
----------------------------------------------------------------------
  [CLEAN  ] github-mcp-server      -
  [FLAGGED] fake-tools-mcp         malicious-tokens:base64,exfiltrate,ignore previous instructions;imperative-pressure
  [FLAGGED] duplicate-cerebro-mcp  repeated-ngrams
...
======================================================================
```

## IMPORTANT: Read before use.

This tool is provided **exclusively** for authorized security research, academic study, and defensive hardening. Use without explicit written authorization is illegal and unethical.

### Authorization Requirements

Use this tooling only on infrastructure and package registries you own or are explicitly authorized to monitor. Deploying honeypot canaries into third-party registries, tool ecosystems, or agent runtimes without authorization is unlawful.

### Legal Framework

Unauthorized access to or interference with computer systems is governed by the **Computer Fraud and Abuse Act (CFAA)** (18 U.S.C. § 1030), the **EU Directive on Attacks Against Information Systems** (2013/40/EU), and equivalent legislation in other jurisdictions. Penalties include imprisonment and significant fines.

### Acceptable Use

- Monitoring your own package/MCP names for squatting and typosquatting
- Embedding canaries in your own tool descriptions and registries
- Auditing your own agent/tool configuration files for injection patterns
- Academic research on supply-chain security
- Defensive name-registration and dependency-verification workflows

### Prohibited Use

- Registering squatted names of packages you do not own to deceive users
- Planting canaries or honeypots in third-party registries without authorization
- Using the injection linter to craft attacks against other systems
- Impersonating or squatting legitimate package names to phish or abuse supply chains

### No Warranty

This software is provided "as is" without warranty of any kind. The authors assume no liability for damages arising from use or misuse of this tool.

### Responsible Disclosure

If you discover a squatted package or malicious MCP configuration in the wild, report it to the registry operator and the affected maintainer directly, and allow reasonable time for remediation before public disclosure.

## License

MIT License