# Splunk Diag Analyzer — Agent Context

## What This Project Is

A **zero-dependency Python tool** that deeply analyzes Splunk diagnostic (`.tar.gz`) archives. It extracts, parses, and cross-references configs, logs, resource stats, and security settings to produce a structured triage report.

## Key Facts for Agents

- **No dependencies** — pure Python stdlib only. If Python 3.8+ is available, this runs.
- **Single entry point** — `src/splunk_diag_analyzer/__main__.py`
- **Two output modes** — Markdown report (`-o report.md`) or JSON (`--json`)
- **Read-only** — never modifies the diag archive or any Splunk config
- **Auto-cleanup** — extracted temp files are deleted after analysis
- **~1100 lines** — the entire analyzer is in one file

## How to Run

```bash
# Direct (no install needed)
python3 src/splunk_diag_analyzer/__main__.py /path/to/diag.tar.gz -o report.md

# After pip install
splunk-diag-analyzer /path/to/diag.tar.gz -o report.md

# JSON for programmatic use
python3 src/splunk_diag_analyzer/__main__.py /path/to/diag.tar.gz --json
```

## When the User Mentions These Terms

| User says... | You should... |
|---|---|
| "Splunk diag" / "diag file" / "support bundle" | Run the analyzer on it |
| "What's wrong with Splunk?" | Run the analyzer, summarize Critical/Warning findings |
| "Pre-triage before sending to support" | Run the analyzer, highlight findings the user should mention to Splunk Support |
| "Splunk crash" / "Splunk slow" / "indexing backlog" | Run the analyzer, look for related findings |
| "Splunk config audit" | Run the analyzer, focus on config_issues and security findings |

## What the Analyzer Detects

### Severity Levels
- **CRITICAL** — Data loss, service outages, security breaches
- **WARNING** — Degraded performance, misconfigurations, approaching limits
- **INFO** — Topology info, app inventory, baseline stats

### Detection Categories
- `config` — Broken stanzas, deprecated settings, conflicting configs
- `log` — Error patterns, crash signatures, forwarding failures
- `resource` — Disk pressure, memory limits, CPU bottlenecks
- `security` — Weak ciphers, exposed ports, audit gaps
- `topology` — Deployment type inference, cluster health clues

## Workflow for Agents

1. **Locate the diag file** — ask the user for the path if not provided
2. **Run the analyzer** — `python3 src/splunk_diag_analyzer/__main__.py <path> -o report.md`
3. **Read the report** — `cat report.md` or read_file
4. **Summarize by severity** — lead with Critical, then Warnings, then Info
5. **Quote evidence** — include specific log lines and config snippets from the report
6. **Recommend actions** — use the analyzer's built-in recommendations
7. **Offer JSON** — if the user wants structured data for dashboards: `--json`

## What NOT to Do

- **Do NOT** try to parse the diag file manually — the analyzer does this comprehensively
- **Do NOT** modify the diag archive — it's read-only
- **Do NOT** send data anywhere — the tool is fully offline
- **Do NOT** install additional Python packages — zero dependencies by design
- **Do NOT** suggest the user run Splunk commands on a production system — analyze the diag offline

## Project Structure

```
├── SKILL.md                          # Skill definition for npx skills / Hermes
├── AGENTS.md                         # This file — agent context
├── README.md                         # Human-facing documentation
├── INSTALL.md                        # Detailed setup & troubleshooting guide
├── pyproject.toml                    # Package metadata (no deps)
├── Makefile                          # make install / test / analyze
├── src/splunk_diag_analyzer/
│   ├── __init__.py                   # Package marker (version string)
│   └── __main__.py                   # Main analyzer (~1100 lines, stdlib only)
└── tests/
    └── test_analyzer.py              # Smoke tests with pytest
```

## Testing

```bash
# Quick smoke test
make test

# Or manually
python3 -m pytest tests/ -v
```
