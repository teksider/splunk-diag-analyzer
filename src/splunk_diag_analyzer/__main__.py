#!/usr/bin/env python3
"""
Splunk Diag Analyzer — Deep analysis of Splunk diagnostic (diag) archives.

Usage:
    python3 analyze_diag.py <diag_file.tar.gz> [options]

Produces a structured markdown report identifying configuration issues,
error patterns, resource problems, and actionable recommendations.
"""

import argparse
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional


# ─── Data Classes ───────────────────────────────────────────────────────────

@dataclass
class Finding:
    severity: str  # CRITICAL, WARNING, INFO
    category: str  # config, log, resource, security, topology
    title: str
    description: str
    file_path: str = ""
    evidence: str = ""
    recommendation: str = ""


@dataclass
class DiagInfo:
    hostname: str = ""
    date_str: str = ""
    splunk_version: str = ""
    deployment_type: str = "unknown"
    diag_path: str = ""
    total_size_mb: float = 0
    file_count: int = 0


@dataclass
class AnalysisReport:
    diag_info: DiagInfo = field(default_factory=DiagInfo)
    findings: list = field(default_factory=list)
    config_issues: list = field(default_factory=list)
    log_errors: dict = field(default_factory=lambda: defaultdict(list))
    log_warnings: dict = field(default_factory=lambda: defaultdict(list))
    resource_stats: dict = field(default_factory=dict)
    app_inventory: list = field(default_factory=list)
    topology_clues: list = field(default_factory=list)
    recommendations: list = field(default_factory=list)


# ─── Error/Warning Pattern Definitions ──────────────────────────────────────

CRITICAL_PATTERNS = [
    (r"FATAL", "Fatal error detected"),
    (r"Out of memory|Cannot allocate memory|Memory allocation failed", "Memory allocation failure"),
    (r"No space left on device|Disk.*space.*critical|disk.*full", "Disk space exhausted"),
    (r"License.*expired|license.*violation|License.*exceeded|LMTracker.*exceeded", "License issue"),
    (r"queue.*full|Queue.*blocked|parsingqueue.*full|indexqueue.*full|typingqueue.*full|aggqueue.*full", "Queue overflow"),
    (r"replication.*fail|bucket.*replication.*fail|replication.*error", "Replication failure"),
    (r"Connection.*refused|TCP.*error|tcp.*connect.*fail", "Connection failure"),
    (r"SSL.*error|handshake.*fail|certificate.*verify|CERTIFICATE_VERIFY_FAILED", "SSL/TLS error"),
    (r"Access denied|permission.*denied|Unauthorized|authentication.*fail", "Access/permission failure"),
    (r"MongoDB.*error|mongod.*error|kvstore.*fail|KVStore.*error", "KV Store failure"),
    (r"bucket.*corrupt|index.*corrupt|journal.*corrupt", "Data corruption"),
    (r"panic|crash|segfault|SIGSEGV|core dump", "Process crash"),
    (r"index.*does.*not.*exist|index.*not.*found", "Missing index"),
]

WARNING_PATTERNS = [
    (r"WARN.*LMTracker|license.*warning|approaching.*limit", "License usage warning"),
    (r"WARN.*TcpOutput|forwarding.*queue|TcpOutputProc.*blocked", "Forwarding queue backup"),
    (r"WARN.*DateParserVerbose|timestamp.*parse|TIME_PARSE", "Timestamp parsing failure"),
    (r"WARN.*LineBreakingProcessor|line.*breaking|LINE_BREAK", "Line breaking issues"),
    (r"WARN.*AggregatorMiningProcessor|aggregation.*issue", "Event aggregation problems"),
    (r"WARN.*HttpListener|Socket.*error.*HttpListener", "HTTP listener issues"),
    (r"WARN.*AutoLB|load.*balancing", "Load balancing issues"),
    (r"WARN.*replication|replication.*lag|replication.*delay", "Replication lag"),
    (r"WARN.*PeriodicReapingTimeout|reaping.*search.*artifact", "Search artifact cleanup slow"),
    (r"WARN.*search.*skip|skip.*search|scheduled.*search.*skip", "Skcheduled search skipped"),
    (r"WARN.*disk.*usage|disk.*usage.*high", "Disk usage warning"),
    (r"WARN.*thruput|throughput.*limit|maxKBps", "Throughput throttling"),
    (r"WARN.*ssl|SSL.*cipher|deprecated.*cipher|sslVersion", "SSL configuration warning"),
    (r"WARN.*bloom|bloomfilter|bucket.*summary", "Bloom filter / bucket summary issues"),
    (r"WARN.*bundle.*push|bundle.*distribution|bundle.*validation", "Bundle distribution issues"),
    (r"WARN.*introspection|introspection.*endpoint", "Introspection endpoint issues"),
]

# Config patterns that indicate problems
CONFIG_ISSUES = [
    {
        "file": "server.conf",
        "checks": [
            {
                "pattern": r"pass4SymmKey\s*=\s*(?:changeme|password|123456)",
                "severity": "CRITICAL",
                "title": "Default or weak pass4SymmKey",
                "desc": "The inter-server authentication key appears to be using a default or weak value.",
                "rec": "Set a strong, unique pass4SymmKey in [general] and [clustering] stanzas.",
            },
            {
                "pattern": r"sslVersions\s*=.*(?<![0-9])(?:ssl3|ssl2|tls1\.0)(?![\d.])",
                "severity": "WARNING",
                "title": "Deprecated SSL/TLS version enabled",
                "desc": "SSLv2, SSLv3, or TLS 1.0 is enabled in sslVersions.",
                "rec": "Remove deprecated protocols. Use sslVersions = tls1.2 for Splunk 7.2+.",
            },
            {
                "pattern": r"mode\s*=\s*master",
                "severity": "INFO",
                "title": "Cluster Manager role detected",
                "desc": "This instance is configured as an indexer cluster manager.",
                "rec": "",
            },
            {
                "pattern": r"mode\s*=\s*slave",
                "severity": "INFO",
                "title": "Indexer cluster peer role detected",
                "desc": "This instance is configured as an indexer cluster peer.",
                "rec": "",
            },
            {
                "pattern": r"mode\s*=\s*searchhead",
                "severity": "INFO",
                "title": "Search head cluster peer role detected",
                "desc": "This instance is part of a search head cluster.",
                "rec": "",
            },
        ],
    },
    {
        "file": "inputs.conf",
        "checks": [
            {
                "pattern": r"disabled\s*=\s*1",
                "severity": "INFO",
                "title": "Disabled inputs found",
                "desc": "Some inputs are explicitly disabled. Verify this is intentional.",
                "rec": "Review disabled inputs to ensure data collection is as expected.",
            },
            {
                "pattern": r"TRUNCATE\s*=\s*0\b",
                "severity": "WARNING",
                "title": "TRUNCATE=0 (unlimited)",
                "desc": "TRUNCATE is set to 0 (unlimited line length). This can cause memory issues with very long lines.",
                "rec": "Consider setting TRUNCATE to a reasonable value (e.g., 10000-50000).",
            },
        ],
    },
    {
        "file": "outputs.conf",
        "checks": [
            {
                "pattern": r"indexAndForward\s*=\s*true",
                "severity": "WARNING",
                "title": "indexAndForward enabled",
                "desc": "Heavy forwarder is both indexing and forwarding data. This impacts performance and may cause data duplication.",
                "rec": "Unless intentional, set indexAndForward = false on forwarding-tier nodes.",
            },
            {
                "pattern": r"server\s*=\s*(?:localhost|127\.0\.0\.1)",
                "severity": "WARNING",
                "title": "Forwarding to localhost",
                "desc": "An outputs.conf server entry points to localhost. Verify this is intentional.",
                "rec": "Ensure forwarding targets are correct indexer addresses.",
            },
        ],
    },
    {
        "file": "indexes.conf",
        "checks": [
            {
                "pattern": r"frozenTimePeriodInSecs\s*=\s*0\b",
                "severity": "WARNING",
                "title": "frozenTimePeriodInSecs=0 (infinite retention)",
                "desc": "Data retention is set to infinite. This will cause unbounded disk growth.",
                "rec": "Set frozenTimePeriodInSecs to a reasonable retention period.",
            },
            {
                "pattern": r"maxTotalDataSizeMB\s*=\s*0\b",
                "severity": "WARNING",
                "title": "maxTotalDataSizeMB=0 (unlimited)",
                "desc": "No size limit on this index. Monitor disk usage closely.",
                "rec": "Set maxTotalDataSizeMB to prevent unbounded growth.",
            },
        ],
    },
    {
        "file": "limits.conf",
        "checks": [
            {
                "pattern": r"kvstore\s*=.*disabled",
                "severity": "WARNING",
                "title": "KV Store disabled",
                "desc": "KV Store is disabled in limits.conf. This breaks Enterprise Security and other apps.",
                "rec": "Enable KV Store unless you have a specific reason to disable it.",
            },
            {
                "pattern": r"maxKBps\s*=\s*0\b",
                "severity": "INFO",
                "title": "Unlimited throughput (maxKBps=0)",
                "desc": "No throughput limit configured. This is fine for receiving indexers but may overwhelm forwarders.",
                "rec": "",
            },
        ],
    },
    {
        "file": "props.conf",
        "checks": [
            {
                "pattern": r"SHOULD_LINEMERGE\s*=\s*true\b",
                "severity": "WARNING",
                "title": "SHOULD_LINEMERGE=true",
                "desc": "Line merging is enabled. This is deprecated in favor of LINE_BREAKER and is slower.",
                "rec": "Migrate to LINE_BREAKER for better performance.",
            },
            {
                "pattern": r"TRUNCATE\s*=\s*10000\b",
                "severity": "INFO",
                "title": "Default TRUNCATE value (10000)",
                "desc": "Using default TRUNCATE=10000. Events longer than 10KB will be truncated.",
                "rec": "If your data has longer events, increase TRUNCATE appropriately.",
            },
        ],
    },
]


# ─── Analysis Engine ────────────────────────────────────────────────────────

class SplunkDiagAnalyzer:
    def __init__(self, diag_path: str, verbose: bool = False, max_log_lines: int = 10000):
        self.diag_path = Path(diag_path)
        self.verbose = verbose
        self.max_log_lines = max_log_lines
        self.extract_dir: Optional[Path] = None
        self.report = AnalysisReport()

    def run(self) -> AnalysisReport:
        """Run the full analysis pipeline."""
        self.report.diag_info.diag_path = str(self.diag_path)
        self.report.diag_info.total_size_mb = self.diag_path.stat().st_size / (1024 * 1024)

        self._extract()
        self._catalog()
        self._detect_topology()
        self._analyze_configs()
        self._analyze_logs()
        self._analyze_system_info()
        self._scan_apps()
        self._generate_recommendations()
        self._cleanup()
        return self.report

    def _extract(self):
        """Extract the diag archive."""
        print(f"[*] Extracting {self.diag_path.name}...")
        self.extract_dir = Path(tempfile.mkdtemp(prefix="splunk_diag_"))

        try:
            with tarfile.open(self.diag_path, "r:gz") as tar:
                try:
                    tar.extractall(path=self.extract_dir, filter="data")
                except TypeError:
                    # Older Python versions don't support filter parameter
                    tar.extractall(path=self.extract_dir)
        except tarfile.TarError as e:
            print(f"[!] Failed to extract archive: {e}")
            sys.exit(1)

        # Find the top-level diag directory
        contents = list(self.extract_dir.iterdir())
        if len(contents) == 1 and contents[0].is_dir():
            self.diag_root = contents[0]
        else:
            # Might have been extracted directly
            self.diag_root = self.extract_dir

        self.report.diag_info.diag_path = str(self.diag_root)
        print(f"[+] Extracted to: {self.diag_root}")

    def _catalog(self):
        """Build file inventory."""
        print(f"[*] Cataloging diag contents...")
        file_count = 0
        dir_counts = Counter()

        for root, dirs, files in os.walk(self.diag_root):
            rel = Path(root).relative_to(self.diag_root)
            dir_counts[str(rel).split("/")[0] if "/" not in str(rel) else str(rel)] += len(files)
            file_count += len(files)

        self.report.diag_info.file_count = file_count
        print(f"[+] Found {file_count} files")

    def _detect_topology(self):
        """Determine Splunk deployment role from config clues."""
        server_conf = self.diag_root / "etc" / "system" / "local" / "server.conf"
        if not server_conf.exists():
            server_conf = self.diag_root / "etc" / "system" / "default" / "server.conf"

        if not server_conf.exists():
            self.report.findings.append(Finding(
                severity="INFO", category="topology",
                title="server.conf not found in expected location",
                description="Cannot determine topology from server.conf"
            ))
            return

        content = server_conf.read_text(errors="replace")

        # Check for clustering
        if re.search(r"mode\s*=\s*master", content):
            self.report.diag_info.deployment_type = "Indexer Cluster Manager"
            self.report.topology_clues.append("clustering mode=master")
        elif re.search(r"mode\s*=\s*slave", content):
            self.report.diag_info.deployment_type = "Indexer Cluster Peer"
            self.report.topology_clues.append("clustering mode=slave")
        elif re.search(r"\[shclustering\]", content):
            self.report.diag_info.deployment_type = "Search Head Cluster"
            self.report.topology_clues.append("shclustering stanza present")
        else:
            # Check if it's a forwarder
            outputs_conf = self.diag_root / "etc" / "system" / "local" / "outputs.conf"
            if not outputs_conf.exists():
                outputs_conf = self._find_first("outputs.conf")

            if outputs_conf and outputs_conf.exists():
                content_out = outputs_conf.read_text(errors="replace")
                if "indexAndForward" in content_out:
                    self.report.diag_info.deployment_type = "Heavy Forwarder"
                    self.report.topology_clues.append("outputs.conf with indexAndForward")
                else:
                    self.report.diag_info.deployment_type = "Universal Forwarder"
                    self.report.topology_clues.append("outputs.conf present, no indexAndForward")
            else:
                self.report.diag_info.deployment_type = "Standalone"
                self.report.topology_clues.append("No clustering or forwarding config")

        # Extract Splunk version from version.conf or manifest
        version_conf = self.diag_root / "etc" / "system" / "local" / "version.conf"
        if not version_conf.exists():
            version_conf = self.diag_root / "etc" / "system" / "default" / "version.conf"

        if version_conf.exists():
            ver_content = version_conf.read_text(errors="replace")
            ver_match = re.search(r"version\s*=\s*([^\s]+)", ver_content)
            if ver_match:
                self.report.diag_info.splunk_version = ver_match.group(1)

        # Try manifest.txt
        manifest = self.diag_root / "manifest.txt"
        if manifest.exists():
            manifest_content = manifest.read_text(errors="replace")
            ver_match = re.search(r"splunk[_-]version[=:\s]+([^\s]+)", manifest_content, re.IGNORECASE)
            if ver_match and not self.report.diag_info.splunk_version:
                self.report.diag_info.splunk_version = ver_match.group(1)

        # Extract hostname and date from directory name
        dir_name = self.diag_root.name
        match = re.match(r"diag-(.+?)-(\d{4}-\d{2}-\d{2})", dir_name)
        if match:
            self.report.diag_info.hostname = match.group(1)
            self.report.diag_info.date_str = match.group(2)
        else:
            match2 = re.match(r"diag-(.+?)-(\d+)", dir_name)
            if match2:
                self.report.diag_info.hostname = match2.group(1)
                self.report.diag_info.date_str = match2.group(2)

        print(f"[+] Deployment type: {self.report.diag_info.deployment_type}")
        if self.report.diag_info.splunk_version:
            print(f"[+] Splunk version: {self.report.diag_info.splunk_version}")
        if self.report.diag_info.hostname:
            print(f"[+] Hostname: {self.report.diag_info.hostname}")

    def _find_first(self, filename: str) -> Optional[Path]:
        """Find the first occurrence of a file by name."""
        for root, dirs, files in os.walk(self.diag_root):
            if filename in files:
                return Path(root) / filename
        return None

    def _find_all(self, filename: str) -> list[Path]:
        """Find all occurrences of a file by name."""
        results = []
        for root, dirs, files in os.walk(self.diag_root):
            if filename in files:
                results.append(Path(root) / filename)
        return results

    def _analyze_configs(self):
        """Analyze configuration files for issues."""
        print(f"[*] Analyzing configuration files...")

        for config_def in CONFIG_ISSUES:
            conf_files = self._find_all(config_def["file"])
            for conf_file in conf_files:
                content = conf_file.read_text(errors="replace")
                rel_path = str(conf_file.relative_to(self.diag_root))

                for check in config_def["checks"]:
                    if re.search(check["pattern"], content, re.IGNORECASE | re.MULTILINE):
                        finding = Finding(
                            severity=check["severity"],
                            category="config",
                            title=check["title"],
                            description=check["desc"],
                            file_path=rel_path,
                            recommendation=check["rec"],
                        )
                        self.report.findings.append(finding)
                        if check["rec"]:
                            self.report.recommendations.append(f"[{check['severity']}] {check['rec']}")

        # Additional config analysis: check for conflicting stanzas
        self._check_config_conflicts()

        # Check indexes.conf for storage issues
        self._check_indexes()

    def _check_config_conflicts(self):
        """Look for potential config conflicts across apps."""
        # Check for duplicate input stanzas
        inputs_files = self._find_all("inputs.conf")
        stanza_sources = defaultdict(list)

        for inp_file in inputs_files:
            content = inp_file.read_text(errors="replace")
            for match in re.finditer(r"^\[(.+?)\]\s*$", content, re.MULTILINE):
                stanza = match.group(1).strip()
                if stanza and not stanza.startswith("#"):
                    rel_path = str(inp_file.relative_to(self.diag_root))
                    stanza_sources[stanza].append(rel_path)

        for stanza, sources in stanza_sources.items():
            if len(sources) > 1:
                self.report.findings.append(Finding(
                    severity="WARNING",
                    category="config",
                    title=f"Duplicate input stanza: [{stanza}]",
                    description=f"Found in {len(sources)} locations. Only the highest-precedence copy will be used.",
                    evidence=" | ".join(sources),
                    recommendation="Review which app's config takes precedence using btool.",
                ))

    def _check_indexes(self):
        """Analyze indexes.conf for storage and retention issues."""
        indexes_files = self._find_all("indexes.conf")
        for idx_file in indexes_files:
            content = idx_file.read_text(errors="replace")
            rel_path = str(idx_file.relative_to(self.diag_root))

            # Look for volume over-allocation
            volumes = {}
            total_max = 0
            for match in re.finditer(r"\[volume:(.+?)\].*?maxVolumeDataSizeMB\s*=\s*(\d+)", content, re.DOTALL):
                vol_name = match.group(1)
                max_mb = int(match.group(2))
                volumes[vol_name] = max_mb
                total_max += max_mb

            if total_max > 0:
                self.report.findings.append(Finding(
                    severity="INFO",
                    category="config",
                    title=f"Index volume allocation: {total_max}MB ({total_max/1024:.1f}GB) total",
                    description=f"Allocated across {len(volumes)} volumes: {', '.join(f'{k}={v}MB' for k, v in volumes.items())}",
                    file_path=rel_path,
                ))

    def _analyze_logs(self):
        """Analyze log files for error and warning patterns."""
        print(f"[*] Analyzing log files...")

        log_dir = self.diag_root / "var" / "log" / "splunk"
        if not log_dir.exists():
            # Try alternative location
            log_dir = self._find_dir_containing("splunkd.log")
            if not log_dir:
                print(f"[!] No Splunk log directory found")
                return

        # Analyze splunkd.log (and rotated versions)
        splunkd_logs = sorted(log_dir.glob("splunkd.log*"))
        for log_file in splunkd_logs:
            self._analyze_log_file(log_file, "splunkd")

        # Analyze other log files
        other_logs = {
            "metrics": log_dir.glob("metrics.log*"),
            "searches": log_dir.glob("searches.log*"),
            "mongod": log_dir.glob("mongod.log*"),
            "license_usage": log_dir.glob("license_usage.log*"),
            "python": log_dir.glob("python.log*"),
            "confdeployment": log_dir.glob("confdeployment.log*"),
        }

        for log_type, log_files in other_logs.items():
            for log_file in sorted(log_files):
                self._analyze_log_file(log_file, log_type)

    def _analyze_log_file(self, log_file: Path, log_type: str):
        """Analyze a single log file for patterns."""
        if not log_file.exists() or not log_file.is_file():
            return

        rel_path = str(log_file.relative_to(self.diag_root))
        file_size_mb = log_file.stat().st_size / (1024 * 1024)

        try:
            lines = []
            with open(log_file, "r", errors="replace") as f:
                for i, line in enumerate(f):
                    if i >= self.max_log_lines:
                        break
                    lines.append(line)
        except Exception as e:
            print(f"[!] Error reading {rel_path}: {e}")
            return

        if not lines:
            return

        # Count errors and warnings
        error_count = 0
        warning_count = 0
        error_messages = []
        warning_messages = []

        for line in lines:
            # Check critical patterns
            for pattern, desc in CRITICAL_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    error_count += 1
                    if len(error_messages) < 5:
                        error_messages.append({
                            "pattern": desc,
                            "line": line.strip()[:200],
                        })
                    break

            # Check warning patterns
            for pattern, desc in WARNING_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    warning_count += 1
                    if len(warning_messages) < 5:
                        warning_messages.append({
                            "pattern": desc,
                            "line": line.strip()[:200],
                        })
                    break

        if error_count > 0:
            self.report.log_errors[log_type].append({
                "file": rel_path,
                "count": error_count,
                "size_mb": round(file_size_mb, 2),
                "examples": error_messages,
            })

            # Add findings for significant error counts
            if error_count > 10:
                self.report.findings.append(Finding(
                    severity="CRITICAL" if error_count > 50 else "WARNING",
                    category="log",
                    title=f"{log_type} log: {error_count} errors found",
                    description=f"High error count in {rel_path} ({file_size_mb:.1f}MB)",
                    evidence=f"Top errors:\n" + "\n".join(f"  - {e['pattern']}: {e['line']}" for e in error_messages[:3]),
                    recommendation=f"Review {log_type} log for root cause. Focus on the most frequent error patterns.",
                ))

        if warning_count > 0:
            self.report.log_warnings[log_type].append({
                "file": rel_path,
                "count": warning_count,
                "size_mb": round(file_size_mb, 2),
                "examples": warning_messages,
            })

            if warning_count > 20:
                self.report.findings.append(Finding(
                    severity="WARNING",
                    category="log",
                    title=f"{log_type} log: {warning_count} warnings found",
                    description=f"Elevated warning count in {rel_path} ({file_size_mb:.1f}MB)",
                    evidence=f"Top warnings:\n" + "\n".join(f"  - {w['pattern']}: {w['line']}" for w in warning_messages[:3]),
                    recommendation=f"Review recurring warnings for potential issues.",
                ))

    def _analyze_system_info(self):
        """Analyze system diagnostics."""
        print(f"[*] Analyzing system information...")

        diag_dir = self.diag_root / "diagnostics"
        if not diag_dir.exists():
            # Try to find diagnostics folder
            diag_dir = self._find_dir_containing("ps.txt")
            if not diag_dir:
                print(f"[!] No diagnostics directory found")
                return

        # Check df.txt for disk usage
        df_file = diag_dir / "df.txt"
        if df_file.exists():
            self._analyze_disk_usage(df_file)

        # Check ulimit.txt
        ulimit_file = diag_dir / "ulimit.txt"
        if ulimit_file.exists():
            self._analyze_ulimits(ulimit_file)

        # Check ps.txt for process issues
        ps_file = diag_dir / "ps.txt"
        if ps_file.exists():
            self._analyze_processes(ps_file)

        # Check netstat.txt
        netstat_file = diag_dir / "netstat.txt"
        if netstat_file.exists():
            self._analyze_network(netstat_file)

        # Check uname.txt
        uname_file = diag_dir / "uname.txt"
        if uname_file.exists():
            content = uname_file.read_text(errors="replace").strip()
            self.report.resource_stats["os_info"] = content

    def _analyze_disk_usage(self, df_file: Path):
        """Analyze disk usage from df output."""
        try:
            content = df_file.read_text(errors="replace")
            for line in content.strip().split("\n")[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 5:
                    try:
                        usage_pct = int(parts[4].replace("%", ""))
                        mount = parts[5] if len(parts) > 5 else parts[-1]
                        self.report.resource_stats.setdefault("disk_usage", []).append({
                            "mount": mount,
                            "usage_pct": usage_pct,
                            "size": parts[1],
                            "used": parts[2],
                            "avail": parts[3],
                        })

                        if usage_pct > 90:
                            self.report.findings.append(Finding(
                                severity="CRITICAL",
                                category="resource",
                                title=f"Disk usage critical: {mount} at {usage_pct}%",
                                description=f"Mount {mount} is {usage_pct}% full.",
                                evidence=f"Size: {parts[1]}, Used: {parts[2]}, Available: {parts[3]}",
                                recommendation="Free disk space immediately. Splunk may stop indexing when disk is full.",
                            ))
                        elif usage_pct > 80:
                            self.report.findings.append(Finding(
                                severity="WARNING",
                                category="resource",
                                title=f"Disk usage high: {mount} at {usage_pct}%",
                                description=f"Mount {mount} is {usage_pct}% full.",
                                recommendation="Plan disk capacity expansion or data retention cleanup.",
                            ))
                    except (ValueError, IndexError):
                        continue
        except Exception as e:
            print(f"[!] Error analyzing disk usage: {e}")

    def _analyze_ulimits(self, ulimit_file: Path):
        """Analyze resource limits."""
        try:
            content = ulimit_file.read_text(errors="replace")
            for line in content.strip().split("\n"):
                if "open files" in line or "nofile" in line:
                    match = re.search(r"(\d+)", line)
                    if match:
                        nofile = int(match.group(1))
                        self.report.resource_stats["nofile"] = nofile
                        if nofile < 10240:
                            self.report.findings.append(Finding(
                                severity="WARNING",
                                category="resource",
                                title=f"Low open file limit: {nofile}",
                                description=f"ulimit -n is {nofile}. Splunk recommends at least 10240.",
                                recommendation="Increase ulimit -n to at least 10240 (preferably 65535).",
                            ))
        except Exception as e:
            print(f"[!] Error analyzing ulimits: {e}")

    def _analyze_processes(self, ps_file: Path):
        """Analyze process listing."""
        try:
            content = ps_file.read_text(errors="replace")
            splunk_procs = [l for l in content.strip().split("\n") if "splunk" in l.lower()]
            self.report.resource_stats["splunk_process_count"] = len(splunk_procs)

            # Check for zombie processes
            zombies = [l for l in splunk_procs if "Z" in l.split() if len(l.split()) > 7]
            if zombies:
                self.report.findings.append(Finding(
                    severity="WARNING",
                    category="resource",
                    title=f"Zombie Splunk processes detected: {len(zombies)}",
                    description="Zombie processes may indicate crashes or resource issues.",
                    recommendation="Investigate why Splunk processes are becoming zombies.",
                ))

            # Check for excessive python processes (scripted inputs)
            python_procs = [l for l in splunk_procs if "python" in l.lower()]
            if len(python_procs) > 20:
                self.report.findings.append(Finding(
                    severity="WARNING",
                    category="resource",
                    title=f"High number of Python processes: {len(python_procs)}",
                    description="Many Python processes running (likely scripted inputs).",
                    recommendation="Review scripted inputs for stuck or runaway processes.",
                ))
        except Exception as e:
            print(f"[!] Error analyzing processes: {e}")

    def _analyze_network(self, netstat_file: Path):
        """Analyze network connections."""
        try:
            content = netstat_file.read_text(errors="replace")
            lines = content.strip().split("\n")[2:]  # Skip headers

            state_counts = Counter()
            for line in lines:
                parts = line.split()
                if parts:
                    # State is usually the last column
                    state = parts[-1] if len(parts) > 1 else ""
                    state_counts[state] += 1

            self.report.resource_stats["network_states"] = dict(state_counts)

            if state_counts.get("TIME_WAIT", 0) > 1000:
                self.report.findings.append(Finding(
                    severity="WARNING",
                    category="resource",
                    title=f"High TIME_WAIT count: {state_counts['TIME_WAIT']}",
                    description="Many connections in TIME_WAIT state may indicate connection churn.",
                    recommendation="Review forwarding configuration and connection pooling.",
                ))
        except Exception as e:
            print(f"[!] Error analyzing network: {e}")

    def _scan_apps(self):
        """Inventory installed apps."""
        print(f"[*] Scanning installed apps...")

        apps_dir = self.diag_root / "etc" / "apps"
        if not apps_dir.exists():
            return

        for app_dir in sorted(apps_dir.iterdir()):
            if not app_dir.is_dir():
                continue

            app_info = {"name": app_dir.name, "enabled": True}

            # Check if app is disabled
            local_conf = app_dir / "local" / "app.conf"
            default_conf = app_dir / "default" / "app.conf"
            conf_file = local_conf if local_conf.exists() else default_conf

            if conf_file.exists():
                content = conf_file.read_text(errors="replace")
                if re.search(r"disabled\s*=\s*1", content, re.IGNORECASE):
                    app_info["enabled"] = False

                # Try to get version and label
                label_match = re.search(r"label\s*=\s*(.+)", content)
                version_match = re.search(r"version\s*=\s*(.+)", content)
                if label_match:
                    app_info["label"] = label_match.group(1).strip()
                if version_match:
                    app_info["version"] = version_match.group(1).strip()

            self.report.app_inventory.append(app_info)

        enabled = sum(1 for a in self.report.app_inventory if a["enabled"])
        disabled = sum(1 for a in self.report.app_inventory if not a["enabled"])
        print(f"[+] Apps: {len(self.report.app_inventory)} total ({enabled} enabled, {disabled} disabled)")

    def _generate_recommendations(self):
        """Generate actionable recommendations based on findings."""
        # Already collected during analysis, just deduplicate
        seen = set()
        unique_recs = []
        for rec in self.report.recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recs.append(rec)
        self.report.recommendations = unique_recs

    def _find_dir_containing(self, filename: str) -> Optional[Path]:
        """Find a directory containing the given file."""
        for root, dirs, files in os.walk(self.diag_root):
            if filename in files:
                return Path(root)
        return None

    def _cleanup(self):
        """Clean up extracted files."""
        if self.extract_dir and self.extract_dir.exists():
            try:
                shutil.rmtree(self.extract_dir)
                print(f"[*] Cleaned up temp directory: {self.extract_dir}")
            except Exception as e:
                print(f"[!] Cleanup warning: {e}")


# ─── Report Generation ──────────────────────────────────────────────────────

def generate_markdown_report(report: AnalysisReport) -> str:
    """Generate a human-readable markdown report."""
    lines = []
    lines.append("# Splunk Diag Analysis Report")
    lines.append("")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"**Diag file:** `{report.diag_info.diag_path}`")
    lines.append("")

    # ── Summary ──
    lines.append("## 📋 Summary")
    lines.append("")
    lines.append(f"| Attribute | Value |")
    lines.append(f"|-----------|-------|")
    lines.append(f"| **Deployment Type** | {report.diag_info.deployment_type} |")
    lines.append(f"| **Splunk Version** | {report.diag_info.splunk_version or 'Unknown'} |")
    lines.append(f"| **Hostname** | {report.diag_info.hostname or 'Unknown'} |")
    lines.append(f"| **Diag Date** | {report.diag_info.date_str or 'Unknown'} |")
    lines.append(f"| **File Count** | {report.diag_info.file_count} |")
    lines.append(f"| **Archive Size** | {report.diag_info.total_size_mb:.1f} MB |")
    lines.append(f"| **Apps Installed** | {len(report.app_inventory)} |")
    lines.append("")

    if report.topology_clues:
        lines.append("**Topology indicators:**")
        for clue in report.topology_clues:
            lines.append(f"- {clue}")
        lines.append("")

    # ── Severity counts ──
    severity_counts = Counter(f.severity for f in report.findings)
    if severity_counts:
        lines.append("## 🚨 Findings Summary")
        lines.append("")
        for sev in ["CRITICAL", "WARNING", "INFO"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                emoji = {"CRITICAL": "🔴", "WARNING": "🟡", "INFO": "🔵"}.get(sev, "⚪")
                lines.append(f"- {emoji} **{sev}**: {count}")
        lines.append("")

    # ── Critical Findings ──
    critical = [f for f in report.findings if f.severity == "CRITICAL"]
    if critical:
        lines.append("## 🔴 Critical Findings")
        lines.append("")
        for i, f in enumerate(critical, 1):
            lines.append(f"### {i}. {f.title}")
            lines.append(f"- **Category:** {f.category}")
            if f.file_path:
                lines.append(f"- **File:** `{f.file_path}`")
            lines.append(f"- **Description:** {f.description}")
            if f.evidence:
                lines.append(f"- **Evidence:**\n```\n{f.evidence}\n```")
            if f.recommendation:
                lines.append(f"- **Recommendation:** {f.recommendation}")
            lines.append("")

    # ── Warnings ──
    warnings = [f for f in report.findings if f.severity == "WARNING"]
    if warnings:
        lines.append("## 🟡 Warnings")
        lines.append("")
        for i, f in enumerate(warnings, 1):
            lines.append(f"### {i}. {f.title}")
            lines.append(f"- **Category:** {f.category}")
            if f.file_path:
                lines.append(f"- **File:** `{f.file_path}`")
            lines.append(f"- **Description:** {f.description}")
            if f.evidence:
                lines.append(f"- **Evidence:**\n```\n{f.evidence}\n```")
            if f.recommendation:
                lines.append(f"- **Recommendation:** {f.recommendation}")
            lines.append("")

    # ── Info ──
    infos = [f for f in report.findings if f.severity == "INFO"]
    if infos:
        lines.append("## 🔵 Informational")
        lines.append("")
        for i, f in enumerate(infos, 1):
            lines.append(f"- **{f.title}**: {f.description}")
        lines.append("")

    # ── Log Analysis ──
    if report.log_errors or report.log_warnings:
        lines.append("## 📝 Log Analysis")
        lines.append("")

        if report.log_errors:
            lines.append("### Errors by Log Type")
            lines.append("")
            lines.append("| Log Type | File | Errors | Size (MB) |")
            lines.append("|----------|------|--------|-----------|")
            for log_type, entries in report.log_errors.items():
                for entry in entries:
                    lines.append(f"| {log_type} | `{entry['file']}` | {entry['count']} | {entry['size_mb']} |")
            lines.append("")

            # Show sample error lines
            for log_type, entries in report.log_errors.items():
                for entry in entries:
                    if entry["examples"]:
                        lines.append(f"**Sample {log_type} errors:**")
                        lines.append("```")
                        for ex in entry["examples"][:5]:
                            lines.append(f"[{ex['pattern']}] {ex['line']}")
                        lines.append("```")
                        lines.append("")

        if report.log_warnings:
            lines.append("### Warnings by Log Type")
            lines.append("")
            lines.append("| Log Type | File | Warnings | Size (MB) |")
            lines.append("|----------|------|----------|-----------|")
            for log_type, entries in report.log_warnings.items():
                for entry in entries:
                    lines.append(f"| {log_type} | `{entry['file']}` | {entry['count']} | {entry['size_mb']} |")
            lines.append("")

    # ── Resource Analysis ──
    if report.resource_stats:
        lines.append("## 💻 System Resources")
        lines.append("")

        if "disk_usage" in report.resource_stats:
            lines.append("### Disk Usage")
            lines.append("")
            lines.append("| Mount | Usage % | Size | Used | Available |")
            lines.append("|-------|---------|------|------|-----------|")
            for disk in report.resource_stats["disk_usage"]:
                lines.append(f"| {disk['mount']} | {disk['usage_pct']}% | {disk['size']} | {disk['used']} | {disk['avail']} |")
            lines.append("")

        if "nofile" in report.resource_stats:
            lines.append(f"**Open file limit (ulimit -n):** {report.resource_stats['nofile']}")
            lines.append("")

        if "splunk_process_count" in report.resource_stats:
            lines.append(f"**Splunk processes:** {report.resource_stats['splunk_process_count']}")
            lines.append("")

        if "network_states" in report.resource_stats:
            lines.append("### Network Connection States")
            lines.append("")
            lines.append("| State | Count |")
            lines.append("|-------|-------|")
            for state, count in sorted(report.resource_stats["network_states"].items(), key=lambda x: -x[1]):
                lines.append(f"| {state} | {count} |")
            lines.append("")

        if "os_info" in report.resource_stats:
            lines.append(f"**OS:** {report.resource_stats['os_info']}")
            lines.append("")

    # ── App Inventory ──
    if report.app_inventory:
        lines.append("## 📦 App Inventory")
        lines.append("")
        lines.append("| App Name | Label | Version | Status |")
        lines.append("|----------|-------|---------|--------|")
        for app in sorted(report.app_inventory, key=lambda x: x["name"]):
            status = "✅" if app["enabled"] else "❌ Disabled"
            label = app.get("label", "")
            version = app.get("version", "")
            lines.append(f"| {app['name']} | {label} | {version} | {status} |")
        lines.append("")

    # ── Recommendations ──
    if report.recommendations:
        lines.append("## 💡 Recommendations")
        lines.append("")
        for i, rec in enumerate(report.recommendations, 1):
            lines.append(f"{i}. {rec}")
        lines.append("")

    # ── Footer ──
    lines.append("---")
    lines.append("")
    lines.append("*Report generated by Splunk Diag Analyzer. Review all findings before sending to Splunk Support.*")
    lines.append("")
    lines.append("**Note:** This analysis is based on a snapshot in time. Some errors may be transient or resolved. Always correlate findings with the actual issue timeline.")
    lines.append("")

    return "\n".join(lines)


def generate_json_report(report: AnalysisReport) -> str:
    """Generate a JSON report."""
    data = {
        "generated": datetime.now().isoformat(),
        "diag_info": {
            "deployment_type": report.diag_info.deployment_type,
            "splunk_version": report.diag_info.splunk_version,
            "hostname": report.diag_info.hostname,
            "date_str": report.diag_info.date_str,
            "file_count": report.diag_info.file_count,
            "total_size_mb": report.diag_info.total_size_mb,
        },
        "findings": [
            {
                "severity": f.severity,
                "category": f.category,
                "title": f.title,
                "description": f.description,
                "file_path": f.file_path,
                "evidence": f.evidence,
                "recommendation": f.recommendation,
            }
            for f in report.findings
        ],
        "log_errors": {
            k: v for k, v in report.log_errors.items()
        },
        "log_warnings": {
            k: v for k, v in report.log_warnings.items()
        },
        "resource_stats": report.resource_stats,
        "app_inventory": report.app_inventory,
        "recommendations": report.recommendations,
    }
    return json.dumps(data, indent=2)


# ─── CLI ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Analyze Splunk diagnostic (diag) archives for issues"
    )
    parser.add_argument("diag_file", help="Path to the Splunk diag .tar.gz file")
    parser.add_argument(
        "--output", "-o",
        help="Output file path (default: stdout)",
    )
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output as JSON instead of markdown",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Include detailed log output",
    )
    parser.add_argument(
        "--max-log-lines",
        type=int,
        default=10000,
        help="Maximum log lines to analyze per file (default: 10000)",
    )

    args = parser.parse_args()

    if not os.path.isfile(args.diag_file):
        print(f"Error: File not found: {args.diag_file}")
        sys.exit(1)

    analyzer = SplunkDiagAnalyzer(
        diag_path=args.diag_file,
        verbose=args.verbose,
        max_log_lines=args.max_log_lines,
    )

    report = analyzer.run()

    if args.json:
        output = generate_json_report(report)
    else:
        output = generate_markdown_report(report)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"\n[+] Report written to: {args.output}")
    else:
        print("\n" + output)


if __name__ == "__main__":
    main()
