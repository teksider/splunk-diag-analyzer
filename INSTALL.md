# Installation & Setup Guide

> **TL;DR:** This tool is a single Python script with **zero dependencies**. If you can run `python3`, you can run this tool.

## Requirements

- **Python 3.8 or newer** (uses only the standard library)
- A Splunk diagnostic archive (`.tar.gz` or `.tgz`)

**No pip packages, no npm, no Docker, no system packages required.**

---

## Installation Methods

Choose the method that works best for your environment.

### Method 1: Direct Execution (Simplest)

No installation at all. Just run the script directly.

```bash
# Clone or download the repo
git clone https://github.com/YOUR_USERNAME/splunk-diag-analyzer.git
cd splunk-diag-analyzer

# Run directly
python3 src/splunk_diag_analyzer/__main__.py /path/to/diag-file.tar.gz -o report.md

# Or just the single file — copy it anywhere and run
cp src/splunk_diag_analyzer/__main__.py ~/bin/analyze_diag.py
python3 ~/bin/analyze_diag.py /path/to/diag-file.tar.gz
```

### Method 2: pip install (Adds `splunk-diag-analyzer` to your PATH)

```bash
cd splunk-diag-analyzer

# Standard install
pip install .

# Or editable install (for development)
pip install -e .

# Usage after install — works from any directory
splunk-diag-analyzer /path/to/diag-file.tar.gz -o report.md
```

**If you get `externally-managed-environment` error** (common on Arch, Debian, Ubuntu 23.04+):

```bash
# Option A: Use a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
splunk-diag-analyzer /path/to/diag-file.tar.gz -o report.md

# Option B: Use --break-system-packages (if you understand the implications)
pip install --break-system-packages -e .

# Option C: Use the Makefile (auto-handles venv)
make install-venv
source .venv/bin/activate
splunk-diag-analyzer /path/to/diag-file.tar.gz -o report.md
```

### Method 3: Virtual Environment (Isolated, No System Changes)

```bash
cd splunk-diag-analyzer
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# Now use the tool
splunk-diag-analyzer /path/to/diag-file.tar.gz -o report.md

# Deactivate when done
deactivate
```

### Method 4: As a Shell Alias (Quick Access)

Add to your `~/.bashrc` or `~/.zshrc`:

```bash
alias splunk-diag='python3 /path/to/splunk-diag-analyzer/src/splunk_diag_analyzer/__main__.py'
```

Then:
```bash
source ~/.bashrc
splunk-diag /path/to/diag-file.tar.gz -o report.md
```

---

## Verifying the Installation

### Step 1: Check Python Version

```bash
python3 --version
# Must be 3.8 or higher
```

### Step 2: Run the Built-in Help

```bash
python3 src/splunk_diag_analyzer/__main__.py --help
```

You should see:
```
usage: splunk_diag_analyzer [-h] [-o OUTPUT] [--json] [--verbose] [--keep] diag_file

Deep analysis of Splunk diagnostic (diag) archives.

positional arguments:
  diag_file             Path to the Splunk diag .tar.gz file

options:
  -h, --help            Show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output file path for the markdown report
  --json                Output findings as JSON instead of markdown
  --verbose             Show detailed progress during analysis
  --keep                Keep extracted files after analysis (for inspection)
```

### Step 3: Run a Test (Optional)

If you have a real Splunk diag file:

```bash
python3 src/splunk_diag_analyzer/__main__.py diag.tar.gz -o test-report.md
cat test-report.md
```

If you don't have a diag file, the tool will still work — it just needs a valid `.tar.gz` archive. It will analyze whatever files are inside and report what it finds (or report that no Splunk-specific files were detected).

---

## Troubleshooting

### "No module named splunk_diag_analyzer"

You're running `python3 -m splunk_diag_analyzer` without the package installed. Fix:

```bash
# Either install it:
pip install -e .

# Or run the script directly instead:
python3 src/splunk_diag_analyzer/__main__.py diag.tar.gz
```

### "externally-managed-environment"

Your OS restricts system-wide pip installs. Use a venv:

```bash
python3 -m venv .venv && source .venv/bin/activate && pip install -e .
```

### "Permission denied" on the output file

Make sure you have write access to the output directory:

```bash
# Write to your home directory instead
python3 src/splunk_diag_analyzer/__main__.py diag.tar.gz -o ~/report.md
```

### "tarfile.ReadError" or "not a gzip file"

The file may not be a valid `.tar.gz` archive. Verify:

```bash
file diag.tar.gz
# Should say: gzip compressed data
```

If Splunk gave you a `.diag` file that's actually a tarball:

```bash
# Rename it
mv diag-file.diag diag-file.tar.gz
# Then analyze
python3 src/splunk_diag_analyzer/__main__.py diag-file.tar.gz -o report.md
```

### "No Splunk-specific files found"

The archive doesn't contain recognizable Splunk diag structure. This could mean:
- It's not a Splunk diag file
- The diag was generated with a non-standard tool
- The archive is corrupted

You can still inspect the contents manually:

```bash
# Use --keep to leave extracted files for inspection
python3 src/splunk_diag_analyzer/__main__.py diag.tar.gz --keep
# Then browse the extracted directory (path shown in output)
```

### Slow Analysis on Large Diags

Large diags (500MB+) take time because the tool must:
1. Extract the entire archive
2. Parse every log and config file
3. Cross-reference findings

Use `--verbose` to see progress:

```bash
python3 src/splunk_diag_analyzer/__main__.py diag.tar.gz -o report.md --verbose
```

---

## Security Notes

- **No network access:** The tool runs 100% offline. No telemetry, no phone home.
- **No data exfiltration:** Your Splunk data stays on your machine.
- **Safe extraction:** Uses `filter="data"` (Python 3.12+) to prevent path traversal attacks in malicious archives.
- **Auto-cleanup:** Extracted files are deleted after analysis unless `--keep` is specified.
- **Read-only:** The tool never modifies the diag archive or any Splunk configuration.

---

## Uninstall

```bash
# If installed via pip
pip uninstall splunk-diag-analyzer

# If installed in a venv, just delete the venv
rm -rf .venv

# If running directly, just delete the directory
rm -rf splunk-diag-analyzer/
```
