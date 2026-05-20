# Splunk Diag Analyzer

Deep analysis tool for Splunk diagnostic (`splunk diag`) archives. Extracts, parses, and
reports on configuration issues, error patterns, resource problems, and actionable
recommendations — all from a single `.tar.gz` file.

> **Zero dependencies.** Pure Python stdlib. Runs anywhere Python 3.8+ is available.

## Quick Start

```bash
# Clone and run immediately — no install needed
git clone https://github.com/YOUR_USERNAME/splunk-diag-analyzer.git
cd splunk-diag-analyzer

# Analyze a diag archive
python3 -m splunk_diag_analyzer /path/to/diag-hostname-2026-05-20.tar.gz

# Save report to file
python3 -m splunk_diag_analyzer diag-hostname-2026-05-20.tar.gz -o report.md

# JSON output for programmatic consumption
python3 -m splunk_diag_analyzer diag-hostname-2026-05-20.tar.gz --json -o report.json
```

## What It Analyzes

### 🔴 Critical Findings
| Check | Detection |
|-------|-----------|
| Weak inter-server auth | `pass4SymmKey = changeme` or default values |
| License violations | Exceeded quota, expired, violated |
| Queue overflow | indexqueue, parsingqueue, typingqueue full |
| Replication failure | Bucket replication errors |
| SSL/TLS errors | Handshake failures, cert verification |
| Disk exhaustion | No space left, critical usage |
| Process crashes | SIGSEGV, panic, core dumps |
| Data corruption | Bucket/index/journal corruption |
| KV Store failure | MongoDB/KVStore errors |
| Access denied | Permission/authentication failures |

### 🟡 Configuration Warnings
| Check | Impact |
|-------|--------|
| Deprecated SSL protocols | TLS 1.0/1.1 still enabled |
| `indexAndForward = true` | Data duplication on forwarders |
| Infinite retention | `frozenTimePeriodInSecs = 0` |
| `SHOULD_LINEMERGE = true` | Deprecated, slow line merging |
| Duplicate config stanzas | Conflicting app precedence |
| Low ulimit | Open file limit < 10240 |
| Unbounded indexes | No `maxTotalDataSizeMB` cap |

### 📝 Log Analysis
- **splunkd.log** — Error/warning patterns across all components
- **metrics.log** — Throughput and indexing statistics
- **mongod.log** — KV Store health
- **searches.log** — Search performance issues
- **license_usage.log** — License consumption patterns
- **python.log** — Scripted input failures
- **confdeployment.log** — Bundle deployment issues

### 💻 System Resources
- Disk usage per mount (>80% warning, >90% critical)
- Open file limits (ulimit -n)
- Process inventory (zombie detection, runaway scripts)
- Network connection states (TIME_WAIT storms)
- OS/kernel information

### 📦 App Inventory
Complete list of installed apps with version, label, and enabled/disabled status.

## Terminal UI (TUI)

Browse diag archives interactively with a ncurses-based interface:

```bash
# Launch the TUI
python3 src/splunk_diag_analyzer/tui.py diag-hostname-2026-05-20.tar.gz
```

Features:
- **Split-pane layout** — file tree on the left, log viewer on the right
- **Syntax highlighting** — ERROR lines in red, WARN in yellow, INFO in cyan
- **Search** — press `/` to search within the current file, `n`/`N` to navigate results
- **Filters** — press `f` to show only errors/warnings, `F` for critical-only, `r` to reset
- **Navigation** — `j`/`k` or arrow keys, `g`/`G` for top/bottom, `Tab` to switch panes
- **Zero dependencies** — uses Python's built-in `curses` module

## Output Formats

### Markdown Report (default)
Human-readable report with severity-ordered findings, evidence snippets,
and actionable recommendations. Ideal for pre-triage before sending to Splunk Support.

```bash
python3 -m splunk_diag_analyzer diag.tar.gz -o report.md
```

### JSON Output
Machine-readable for pipeline integration, dashboard ingestion, or custom tooling.

```bash
python3 -m splunk_diag_analyzer diag.tar.gz --json -o report.json
```

### Dark HTML Report
A self-contained, dark-themed HTML dashboard with severity cards, collapsible log sections, and a responsive layout. Opens in any browser — no server needed.

```bash
python3 -m splunk_diag_analyzer diag.tar.gz --html -o report.html
```

Features:
- **Summary cards** — critical/warning/info counts at a glance
- **Severity badges** — color-coded findings with evidence snippets
- **Collapsible logs** — expandable error/warning tables per log file
- **Resource stats grid** — disk, ulimit, process inventory
- **App inventory table** — sortable list of installed apps
- **Recommendations** — prioritized action items
- **Configuration precedence (btool-style)** — see which config files win when stanzas conflict
- **Mobile responsive** — works on any screen size
- **Zero dependencies** — single HTML file, no external CSS/JS

### Configuration Precedence Analysis (btool-style)

When the same `.conf` file exists in multiple locations (e.g., `system/local/inputs.conf` and `apps/TA-weblogs/local/inputs.conf`), Splunk loads them in a specific precedence order. This tool automatically resolves which file's settings win for each stanza and key:

| Precedence | Location | Priority |
|------------|----------|----------|
| Highest | `etc/system/local/` | 4 |
| ↑ | `etc/apps/<app>/local/` | 3 |
| ↓ | `etc/apps/<app>/default/` | 2 |
| Lowest | `etc/system/default/` | 1 |

Within the same priority level, apps are loaded alphabetically — **later = higher precedence**.

The analyzer reports:
- **Key shadowing** — when a higher-precedence file overrides a key from a lower one
- **File precedence chain** — shows the full load order for each `.conf` file
- **Winner identification** — which file's value is actually active

This is especially useful for triaging issues where a setting in `system/local/` silently overrides what you configured in an app's `local/` directory.

### Verbose Mode
Print detailed per-log-file analysis during processing.

```bash
python3 -m splunk_diag_analyzer diag.tar.gz --verbose
```

## CLI Reference

```
usage: __main__.py [-h] [--output FILE] [--json] [--html] [--verbose] [--max-log-lines N] diag_file

positional arguments:
  diag_file             Path to the Splunk diag .tar.gz file

options:
  -h, --help            Show this help message
  -o, --output FILE     Output file path (default: stdout)
  -j, --json            Output as JSON instead of markdown
  -H, --html            Output as dark-themed HTML report
  -v, --verbose         Include detailed log output
  --max-log-lines N     Maximum log lines to analyze per file (default: 10000)
```

## Security

- **No network calls.** The tool operates entirely offline on local files.
- **No data exfiltration.** Your diag contents never leave your machine.
- **Automatic cleanup.** Extracted files are deleted from temp after analysis.
- **Safe archive extraction.** Uses `filter="data"` on Python 3.12+ to prevent
  path traversal during extraction.

## Requirements

- **Python 3.8+** (stdlib only — no pip install needed)
- **Splunk diag archive** (generated via `splunk diag` command)

## Typical Workflow

1. Generate diag on the affected Splunk instance:
   ```bash
   splunk diag --output=/tmp/diag-hostname-$(date +%F).tar.gz
   ```

2. Copy the diag file to your analysis workstation (or run locally if permitted).

3. Run the analyzer:
   ```bash
   python3 -m splunk_diag_analyzer diag-hostname-2026-05-20.tar.gz -o pre-triage.md
   ```

4. Review the report, identify root causes, and attach both the diag and
   your pre-triage report to the Splunk Support case.

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

## Disclaimer

This tool provides automated analysis based on known patterns and best practices.
It is not a substitute for Splunk Support's official diagnosis. Always correlate
findings with the actual issue timeline and your environment's context.
