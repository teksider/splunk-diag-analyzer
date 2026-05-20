"""Basic smoke tests for Splunk Diag Analyzer."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

# Path to the mock diag created by the test fixture
MOCK_DIAG = Path("/tmp/test_splunk_diag.tar.gz")


@pytest.fixture(scope="session", autouse=True)
def ensure_mock_diag():
    """Create mock diag if it doesn't exist."""
    if not MOCK_DIAG.exists():
        create_script = Path(__file__).parent.parent / "tests" / "create_test_diag.py"
        if create_script.exists():
            subprocess.run([sys.executable, str(create_script)], check=True)
        else:
            pytest.skip("Mock diag not found at /tmp/test_splunk_diag.tar.gz")


def test_analyze_markdown_output(tmp_path):
    """Test that markdown report is generated successfully."""
    output = tmp_path / "report.md"
    result = subprocess.run(
        [sys.executable, "-m", "splunk_diag_analyzer", str(MOCK_DIAG), "-o", str(output)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"Analyzer failed: {result.stderr}"
    assert output.exists()
    content = output.read_text()
    assert "# Splunk Diag Analysis Report" in content
    assert "## Summary" in content or "## 📋 Summary" in content


def test_analyze_json_output(tmp_path):
    """Test that JSON report is generated and parseable."""
    output = tmp_path / "report.json"
    result = subprocess.run(
        [sys.executable, "-m", "splunk_diag_analyzer", str(MOCK_DIAG), "--json", "-o", str(output)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"Analyzer failed: {result.stderr}"
    assert output.exists()
    data = json.loads(output.read_text())
    assert "findings" in data
    assert "diag_info" in data


def test_analyze_detects_critical_findings(tmp_path):
    """Test that critical config issues are detected."""
    output = tmp_path / "report.md"
    subprocess.run(
        [sys.executable, "-m", "splunk_diag_analyzer", str(MOCK_DIAG), "-o", str(output)],
        capture_output=True,
        text=True,
        check=True,
    )
    content = output.read_text()
    # Mock diag has pass4SymmKey=changeme, disk at 95%, license errors
    assert "pass4SymmKey" in content or "weak" in content.lower()
    assert "95%" in content or "Disk usage critical" in content


def test_analyze_detects_topology(tmp_path):
    """Test that deployment topology is detected."""
    output = tmp_path / "report.md"
    subprocess.run(
        [sys.executable, "-m", "splunk_diag_analyzer", str(MOCK_DIAG), "-o", str(output)],
        capture_output=True,
        text=True,
        check=True,
    )
    content = output.read_text()
    assert "Cluster Peer" in content or "cluster peer" in content.lower()


def test_no_network_calls():
    """Verify the analyzer module has no network imports."""
    main_file = Path(__file__).parent.parent / "src" / "splunk_diag_analyzer" / "__main__.py"
    content = main_file.read_text()
    forbidden = ["import urllib", "import http", "import requests", "import socket", "subprocess"]
    for forbidden_import in forbidden:
        assert forbidden_import not in content, f"Found forbidden import: {forebidden_import}"
