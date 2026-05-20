---
name: splunk-diag-analyzer
description: "Use when a Splunk admin needs to pre-triage a Splunk diagnostic (diag) archive before sending to Splunk Support. Deeply analyzes configs, logs, resource stats, and security posture inside .tgz diag files — produces markdown, JSON, or dark-themed HTML reports with critical/warning/info findings, evidence, and actionable recommendations. Zero dependencies, stdlib-only Python."
version: 1.0.0
author: Hermes Agent
license: Apache-2.0
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [splunk, diagnostics, triage, logging, admin, diag, analyzer]
    related_skills: [splunk, system-administration]
---

# Splunk Diag Analyzer

Deep analysis of Splunk diagnostic (`.tar.gz`) archives. Extracts, parses, and cross-references configuration files, log files, resource statistics, and security settings to produce a structured triage report **before** you send the diag to Splunk Support.

## When to Use

- Splunk Support requests a diag and you want to pre-triage the issues yourself
- Investigating a Splunk crash, performance degradation, or indexing backlog
- Auditing a Splunk deployment's configuration and security posture
- Comparing multiple diags to spot regressions between time periods
- **Don't use for:** live Splunk querying, SPL searches, or real-time monitoring

## Quick Start

```bash
# No installation needed — stdlib-only Python 3.8+
python3 src/splunk_diag_analyzer/__main__.py diag-file.tar.gz -o report.md

# Or install as a CLI tool
pip install -e .
splunk-diag-analyzer diag-file.tar.gz -o report.md

# Dark HTML report (recommended for sharing with team)
python3 src/splunk_diag_analyzer/__main__.py diag-file.tar.gz --html -o report.html

# JSON output for programmatic consumption
python3 src/splunk_diag_analyzer/__main__.py diag-file.tar.gz --json

# Interactive TUI for log browsing
python3 src/splunk_diag_analyzer/tui.py diag-file.tar.gz
```

## What It Detects

### Critical
- License quota exceeded or violations
- Index frozen data (data loss)
- Forwarder connectivity failures (TCP/SSL)
- Disk space critically low (<5%)
- Splunk process crashes / segfaults

### Warnings
- Index nearing capacity thresholds
- Long-running searches consuming resources
- Certificate expiry warnings
- Misconfigured inputs/outputs
- Forwarder backlog accumulation
- KV store performance degradation
- Audit logging gaps

### Informational
- Deployment topology clues (standalone, clustered, SHC)
- App inventory and version audit
- Resource utilization baselines
- Configuration drift indicators

## Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| Markdown | `-o report.md` (default) | Human-readable report for sharing |
| JSON | `--json` | Programmatic parsing, dashboards |
| Stdout | (no flags) | Quick terminal scan |

## Architecture

Zero external dependencies. Pure Python stdlib:
- `tarfile` — archive extraction with path traversal protection
- `re` / `json` / `dataclasses` — parsing and data modeling
- `tempfile` / `shutil` — safe extract → analyze → cleanup lifecycle

The analyzer runs entirely offline. No data leaves the machine.

## Files

```
splunk-diag-analyzer/
├── SKILL.md                          # This file — skill definition
├── README.md                         # User-facing documentation
├── INSTALL.md                        # Installation & setup guide
├── AGENTS.md                         # AI agent context (opencode/codex)
├── pyproject.toml                    # pip-installable package metadata
├── Makefile                          # make install / test / analyze
├── src/splunk_diag_analyzer/
│   ├── __init__.py
│   └── __main__.py                   # Main analyzer engine (~1100 lines)
└── tests/
    └── test_analyzer.py              # Smoke tests
```

## For AI Agents (opencode, Claude Code, Codex)

When this repo is loaded as a skill via `npx skills add` or dropped into a project with `AGENTS.md`, agents should:

1. **Run the analyzer** on any `.tar.gz` file the user identifies as a Splunk diag
2. **Summarize findings** by severity (Critical → Warning → Info)
3. **Highlight evidence** — quote specific log lines and config stanzas
4. **Recommend actions** — use the analyzer's built-in recommendations
5. **Never modify** the diag archive — analysis is read-only

## Manual Setup (If Automated Install Fails)

See `INSTALL.md` for detailed human-readable setup instructions covering:
- Requirements verification
- Multiple installation methods (pip, venv, direct execution)
- Common troubleshooting steps
- Verified test procedure
