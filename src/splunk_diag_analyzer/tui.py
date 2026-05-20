#!/usr/bin/env python3
"""
Splunk Diag TUI — Terminal UI for browsing Splunk diagnostic archives.

A ncurses-based interface for navigating extracted diag files, viewing
logs with syntax highlighting, searching, and filtering.

Zero dependencies — Python stdlib only (curses, tarfile, pathlib, re).

Usage:
    python3 src/splunk_diag_analyzer/tui.py diag-file.tar.gz

Keybindings:
    Arrow keys / j,k  — Navigate file tree
    Enter             — Open selected file in viewer
    Esc / q           — Quit (or go back from viewer)
    /                 — Search within current file
    n / N             — Next / previous search result
    f                 — Toggle filter: show only ERROR/WARN lines
    F                 — Toggle filter: show only CRITICAL lines
    r                 — Reset filters
    Tab               — Switch between tree and viewer pane
    g                 — Go to top
    G                 — Go to bottom
    Ctrl+L            — Refresh screen
"""

import curses
import os
import re
import shutil
import sys
import tarfile
import tempfile
from pathlib import Path


# ─── Color Pairs ─────────────────────────────────────────────────────────────

COLOR_DIR = 1
CONFIG_COLOR = 2
LOG_COLOR = 3
ERROR_COLOR = 4
WARN_COLOR = 5
INFO_COLOR = 6
HIGHLIGHT_COLOR = 7
SELECTED_COLOR = 8
HEADER_COLOR = 9
STATUS_COLOR = 10


# ─── Diag Archive Browser ────────────────────────────────────────────────────

class DiagArchive:
    """Manages extraction and file tree of a Splunk diag archive."""

    def __init__(self, archive_path: str):
        self.archive_path = Path(archive_path).resolve()
        self.extract_dir: Path | None = None
        self.tree: list[tuple[str, Path]] = []  # (display_name, full_path)
        self._extract()

    def _extract(self):
        """Extract archive to a temp directory and build file tree."""
        self.extract_dir = Path(tempfile.mkdtemp(prefix="splunk_diag_tui_"))

        with tarfile.open(self.archive_path, "r:gz") as tar:
            # Safe extraction
            try:
                tar.extractall(path=self.extract_dir, filter="data")
            except TypeError:
                tar.extractall(path=self.extract_dir)

        self._build_tree()

    def _build_tree(self):
        """Walk extracted directory and build sorted file tree."""
        if not self.extract_dir:
            return

        # Find the root (usually a single top-level directory)
        entries = list(self.extract_dir.iterdir())
        if len(entries) == 1 and entries[0].is_dir():
            root = entries[0]
        else:
            root = self.extract_dir

        for path in sorted(root.rglob("*")):
            rel = path.relative_to(self.extract_dir)
            display = str(rel)
            if path.is_dir():
                display = f"📁 {display}/"
                self.tree.append((display, path))
            else:
                self.tree.append((f"   {display}", path))

    def get_content(self, file_path: Path) -> str:
        """Read file content, handling binary files gracefully."""
        try:
            with open(file_path, "r", errors="replace") as f:
                return f.read()
        except (PermissionError, IsADirectoryError):
            return f"[Cannot read: {file_path}]"

    def cleanup(self):
        """Remove extracted temp directory."""
        if self.extract_dir and self.extract_dir.exists():
            shutil.rmtree(self.extract_dir, ignore_errors=True)

    def __del__(self):
        self.cleanup()


# ─── Syntax Highlighting ─────────────────────────────────────────────────────

# Patterns for log line classification
ERROR_PATTERNS = re.compile(
    r"(ERROR|CRITICAL|FATAL|SEVERE|EMERGENCY|PANIC|ASSERT|SEGFAULT|CoreDumped)",
    re.IGNORECASE,
)
WARN_PATTERNS = re.compile(
    r"(WARN|WARNING|DEPRECATE|deprecated)",
    re.IGNORECASE,
)
INFO_PATTERNS = re.compile(
    r"(INFO|NOTICE|DEBUG|VERBOSE)",
    re.IGNORECASE,
)


def classify_line(line: str) -> str:
    """Classify a log line by severity."""
    if ERROR_PATTERNS.search(line):
        return "error"
    if WARN_PATTERNS.search(line):
        return "warn"
    if INFO_PATTERNS.search(line):
        return "info"
    return "normal"


# ─── TUI Application ─────────────────────────────────────────────────────────

class DiagTUI:
    """Main TUI application."""

    def __init__(self, archive_path: str):
        self.archive = DiagArchive(archive_path)
        self.tree_items = self.archive.tree
        self.tree_start = 0      # Visible window start in tree
        self.tree_cursor = 0     # Current selection in tree
        self.viewer_lines: list[str] = []
        self.viewer_start = 0    # Visible window start in viewer
        self.viewer_cursor = 0   # Cursor position in viewer
        self.current_file: Path | None = None
        self.current_file_name = ""
        self.search_query = ""
        self.search_results: list[int] = []
        self.search_index = -1
        self.filter_mode = "all"  # "all", "errors", "critical"
        self.active_pane = "tree"  # "tree" or "viewer"
        self.status_msg = ""
        self.status_time = 0

    def run(self):
        """Start the curses application."""
        curses.wrapper(self._main_loop)

    def _main_loop(self, stdscr):
        """Main event loop."""
        self.stdscr = stdscr
        self._setup_colors()
        curses.curs_set(0)  # Hide cursor
        self.stdscr.nodelay(False)
        self.stdscr.keypad(True)

        self._set_status(f"Loaded: {self.archive.archive_path.name} ({len(self.tree_items)} entries)")

        while True:
            self._draw()
            key = self.stdscr.getch()

            if self.active_pane == "tree":
                handled = self._handle_tree_key(key)
            else:
                handled = self._handle_viewer_key(key)

            if not handled:
                if key == ord("q") or key == 27:  # q or Esc
                    break
                elif key == curses.KEY_RESIZE:
                    self.stdscr.clear()

    def _setup_colors(self):
        """Initialize color pairs."""
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(COLOR_DIR, curses.COLOR_BLUE, -1)
        curses.init_pair(CONFIG_COLOR, curses.COLOR_YELLOW, -1)
        curses.init_pair(LOG_COLOR, curses.COLOR_GREEN, -1)
        curses.init_pair(ERROR_COLOR, curses.COLOR_RED, -1)
        curses.init_pair(WARN_COLOR, curses.COLOR_YELLOW, -1)
        curses.init_pair(INFO_COLOR, curses.COLOR_CYAN, -1)
        curses.init_pair(HIGHLIGHT_COLOR, curses.COLOR_BLACK, curses.COLOR_YELLOW)
        curses.init_pair(SELECTED_COLOR, curses.COLOR_BLACK, curses.COLOR_WHITE)
        curses.init_pair(HEADER_COLOR, curses.COLOR_WHITE, curses.COLOR_BLUE)
        curses.init_pair(STATUS_COLOR, curses.COLOR_BLACK, curses.COLOR_GREEN)

    def _draw(self):
        """Draw the full interface."""
        self.stdscr.erase()
        height, width = self.stdscr.getmaxyx()

        if height < 10 or width < 40:
            self.stdscr.addstr(0, 0, "Terminal too small. Resize and press any key.")
            self.stdscr.refresh()
            return

        # Split: tree pane (35%), viewer pane (65%)
        tree_width = max(20, int(width * 0.35))
        viewer_x = tree_width + 1

        # Header bar
        header = f" Splunk Diag TUI — {self.archive.archive_path.name} "
        header = header.ljust(width - 1)
        try:
            self.stdscr.addstr(0, 0, header[:width-1], curses.color_pair(HEADER_COLOR) | curses.A_BOLD)
        except curses.error:
            pass

        # Pane labels
        tree_label = " Files (↑↓ navigate, Enter open) "
        viewer_label = f" Viewer: {self.current_file_name or '(no file open)'} "
        try:
            self.stdscr.addstr(1, 0, tree_label.ljust(tree_width), curses.A_BOLD | curses.A_UNDERLINE)
            self.stdscr.addstr(1, viewer_x, viewer_label.ljust(width - viewer_x - 1), curses.A_BOLD | curses.A_UNDERLINE)
        except curses.error:
            pass

        # Vertical divider
        for y in range(2, height - 2):
            try:
                self.stdscr.addstr(y, tree_width, "│")
            except curses.error:
                pass

        # Draw tree pane
        self._draw_tree(2, 0, height - 3, tree_width)

        # Draw viewer pane
        self._draw_viewer(2, viewer_x, height - 3, width - viewer_x - 1)

        # Status bar
        status = self._get_status_text()
        try:
            self.stdscr.addstr(height - 2, 0, status.ljust(width - 1)[:width-1], curses.color_pair(STATUS_COLOR))
        except curses.error:
            pass

        # Key hints
        hints = " q:Quit  Tab:Switch  /:Search  f:Filter  F:Critical  r:Reset  g:Top  G:Bottom "
        try:
            self.stdscr.addstr(height - 1, 0, hints.center(width - 1)[:width-1], curses.A_DIM)
        except curses.error:
            pass

        self.stdscr.refresh()

    def _draw_tree(self, start_y, start_x, max_lines, width):
        """Draw the file tree pane."""
        available = max_lines - start_y
        visible = self.tree_items[self.tree_start:self.tree_start + available]

        for i, (display, path) in enumerate(visible):
            y = start_y + i
            if y >= max_lines:
                break

            idx = self.tree_start + i
            is_selected = (idx == self.tree_cursor) and (self.active_pane == "tree")

            # Truncate display to fit width
            truncated = display[:width-2]

            # Determine color
            if is_selected:
                attr = curses.color_pair(SELECTED_COLOR) | curses.A_BOLD
            elif path.is_dir():
                attr = curses.color_pair(COLOR_DIR)
            elif self._is_config_file(path):
                attr = curses.color_pair(CONFIG_COLOR)
            elif self._is_log_file(path):
                attr = curses.color_pair(LOG_COLOR)
            else:
                attr = curses.A_NORMAL

            try:
                self.stdscr.addstr(y, start_x + 1, truncated, attr)
            except curses.error:
                pass

    def _draw_viewer(self, start_y, start_x, max_lines, width):
        """Draw the file viewer pane."""
        if not self.viewer_lines:
            try:
                self.stdscr.addstr(start_y, start_x + 1, "(No file selected — use Enter to open a file)", curses.A_DIM)
            except curses.error:
                return

        available = max_lines - start_y
        visible = self.viewer_lines[self.viewer_start:self.viewer_start + available]

        for i, line in enumerate(visible):
            y = start_y + i
            if y >= max_lines:
                break

            line_idx = self.viewer_start + i
            is_cursor = (line_idx == self.viewer_cursor) and (self.active_pane == "viewer")
            is_search_result = line_idx in self.search_results

            # Truncate to fit
            truncated = line[:width-2]

            # Determine color based on content
            if is_search_result:
                attr = curses.color_pair(HIGHLIGHT_COLOR) | curses.A_BOLD
            elif is_cursor:
                attr = curses.color_pair(SELECTED_COLOR)
            else:
                classification = classify_line(line)
                if classification == "error":
                    attr = curses.color_pair(ERROR_COLOR) | curses.A_BOLD
                elif classification == "warn":
                    attr = curses.color_pair(WARN_COLOR)
                elif classification == "info":
                    attr = curses.color_pair(INFO_COLOR) | curses.A_DIM
                else:
                    attr = curses.A_NORMAL

            try:
                self.stdscr.addstr(y, start_x + 1, truncated, attr)
            except curses.error:
                pass

    def _handle_tree_key(self, key: int) -> bool:
        """Handle keypresses in tree pane. Returns True if handled."""
        if key == curses.KEY_UP or key == ord("k"):
            if self.tree_cursor > 0:
                self.tree_cursor -= 1
                self._ensure_tree_visible()
            return True
        elif key == curses.KEY_DOWN or key == ord("j"):
            if self.tree_cursor < len(self.tree_items) - 1:
                self.tree_cursor += 1
                self._ensure_tree_visible()
            return True
        elif key == curses.KEY_PPAGE:  # Page Up
            self.tree_cursor = max(0, self.tree_cursor - 10)
            self._ensure_tree_visible()
            return True
        elif key == curses.KEY_NPAGE:  # Page Down
            self.tree_cursor = min(len(self.tree_items) - 1, self.tree_cursor + 10)
            self._ensure_tree_visible()
            return True
        elif key == ord("g"):
            self.tree_cursor = 0
            self._ensure_tree_visible()
            return True
        elif key == ord("G"):
            self.tree_cursor = len(self.tree_items) - 1
            self._ensure_tree_visible()
            return True
        elif key in (curses.KEY_ENTER, 10, 13):
            self._open_selected_file()
            return True
        elif key == curses.KEY_LEFT:
            self.active_pane = "viewer"
            return True
        elif key == curses.KEY_RIGHT:
            self.active_pane = "viewer"
            return True
        elif key == ord("\t"):
            self.active_pane = "viewer"
            return True
        elif key == ord("/"):
            # Search mode — switch to viewer if file open
            if self.viewer_lines:
                self._start_search()
            else:
                self._set_status("Open a file first to search")
            return True
        elif key == ord("f"):
            self._toggle_filter()
            return True
        elif key == ord("F"):
            self._toggle_critical_filter()
            return True
        elif key == ord("r"):
            self._reset_filter()
            return True
        return False

    def _handle_viewer_key(self, key: int) -> bool:
        """Handle keypresses in viewer pane. Returns True if handled."""
        if key == curses.KEY_UP or key == ord("k"):
            if self.viewer_cursor > 0:
                self.viewer_cursor -= 1
                self._ensure_viewer_visible()
            return True
        elif key == curses.KEY_DOWN or key == ord("j"):
            if self.viewer_cursor < len(self.viewer_lines) - 1:
                self.viewer_cursor += 1
                self._ensure_viewer_visible()
            return True
        elif key == curses.KEY_PPAGE:
            self.viewer_cursor = max(0, self.viewer_cursor - 20)
            self._ensure_viewer_visible()
            return True
        elif key == curses.KEY_NPAGE:
            self.viewer_cursor = min(len(self.viewer_lines) - 1, self.viewer_cursor + 20)
            return True
        elif key == ord("g"):
            self.viewer_cursor = 0
            self.viewer_start = 0
            return True
        elif key == ord("G"):
            self.viewer_cursor = len(self.viewer_lines) - 1
            return True
        elif key == curses.KEY_LEFT:
            self.active_pane = "tree"
            return True
        elif key == ord("\t"):
            self.active_pane = "tree"
            return True
        elif key == ord("/"):
            self._start_search()
            return True
        elif key == ord("n"):
            self._next_search_result()
            return True
        elif key == ord("N"):
            self._prev_search_result()
            return True
        elif key == ord("f"):
            self._toggle_filter()
            return True
        elif key == ord("F"):
            self._toggle_critical_filter()
            return True
        elif key == ord("r"):
            self._reset_filter()
            return True
        elif key == ord("q") or key == 27:
            return False  # Let main loop handle quit
        return False

    def _open_selected_file(self):
        """Open the currently selected tree item in the viewer."""
        if not self.tree_items:
            return

        _, path = self.tree_items[self.tree_cursor]

        if path.is_dir():
            # Find first file entry after this directory
            for i in range(self.tree_cursor + 1, len(self.tree_items)):
                _, next_path = self.tree_items[i]
                if next_path.is_file():
                    self.tree_cursor = i
                    self._open_selected_file()
                    return
            self._set_status(f"Directory: {path.name} (no files below)")
            return

        self.current_file = path
        self.current_file_name = str(path.relative_to(self.archive.extract_dir))
        content = self.archive.get_content(path)
        self.viewer_lines = content.splitlines()
        self.viewer_start = 0
        self.viewer_cursor = 0
        self.search_results = []
        self.search_index = -1
        self.search_query = ""
        self.filter_mode = "all"
        self._set_status(f"Opened: {self.current_file_name} ({len(self.viewer_lines)} lines)")

    def _start_search(self):
        """Start interactive search."""
        height, width = self.stdscr.getmaxyx()
        curses.echo()
        curses.curs_set(1)

        try:
            self.stdscr.addstr(height - 2, 0, " / Search: ".ljust(width - 1)[:width-1], curses.color_pair(STATUS_COLOR) | curses.A_BOLD)
            self.stdscr.refresh()

            self.stdscr.nodelay(True)
            query = ""
            while True:
                key = self.stdscr.getch()
                if key in (10, 13, 27):  # Enter or Esc
                    break
                elif key in (curses.KEY_BACKSPACE, 127, 8):
                    query = query[:-1]
                elif 32 <= key <= 126:
                    query += chr(key)

                # Show query in status bar
                prompt = f" / Search: {query}"
                try:
                    self.stdscr.addstr(height - 2, 0, prompt.ljust(width - 1)[:width-1], curses.color_pair(STATUS_COLOR) | curses.A_BOLD)
                    self.stdscr.refresh()
                except curses.error:
                    pass

            curses.noecho()
            curses.curs_set(0)
            self.stdscr.nodelay(False)

            if query:
                self.search_query = query
                self._perform_search()
        except curses.error:
            curses.noecho()
            curses.curs_set(0)
            self.stdscr.nodelay(False)

    def _perform_search(self):
        """Search current file for the query string."""
        if not self.search_query or not self.viewer_lines:
            return

        self.search_results = []
        for i, line in enumerate(self.viewer_lines):
            if self.search_query.lower() in line.lower():
                self.search_results.append(i)

        if self.search_results:
            self.search_index = 0
            self.viewer_cursor = self.search_results[0]
            self._ensure_viewer_visible()
            self._set_status(f"Search: '{self.search_query}' — {len(self.search_results)} matches")
        else:
            self._set_status(f"Search: '{self.search_query}' — No matches")

    def _next_search_result(self):
        """Jump to next search result."""
        if not self.search_results:
            return
        self.search_index = (self.search_index + 1) % len(self.search_results)
        self.viewer_cursor = self.search_results[self.search_index]
        self._ensure_viewer_visible()
        self._set_status(f"Match {self.search_index + 1}/{len(self.search_results)}: '{self.search_query}'")

    def _prev_search_result(self):
        """Jump to previous search result."""
        if not self.search_results:
            return
        self.search_index = (self.search_index - 1) % len(self.search_results)
        self.viewer_cursor = self.search_results[self.search_index]
        self._ensure_viewer_visible()
        self._set_status(f"Match {self.search_index + 1}/{len(self.search_results)}: '{self.search_query}'")

    def _toggle_filter(self):
        """Toggle error/warning filter."""
        if not self.current_file:
            return

        if self.filter_mode == "errors":
            self._reset_filter()
            return

        self.filter_mode = "errors"
        original_content = self.archive.get_content(self.current_file)
        self.viewer_lines = [
            line for line in original_content.splitlines()
            if classify_line(line) in ("error", "warn")
        ]
        self.viewer_start = 0
        self.viewer_cursor = 0
        self.search_results = []
        self._set_status(f"Filter: errors/warnings only ({len(self.viewer_lines)} lines)")

    def _toggle_critical_filter(self):
        """Toggle critical-only filter."""
        if not self.current_file:
            return

        if self.filter_mode == "critical":
            self._reset_filter()
            return

        self.filter_mode = "critical"
        original_content = self.archive.get_content(self.current_file)
        self.viewer_lines = [
            line for line in original_content.splitlines()
            if classify_line(line) == "error"
        ]
        self.viewer_start = 0
        self.viewer_cursor = 0
        self.search_results = []
        self._set_status(f"Filter: critical only ({len(self.viewer_lines)} lines)")

    def _reset_filter(self):
        """Reset to show all lines."""
        if not self.current_file:
            return

        self.filter_mode = "all"
        content = self.archive.get_content(self.current_file)
        self.viewer_lines = content.splitlines()
        self.viewer_start = 0
        self.viewer_cursor = 0
        self._set_status(f"Filter reset: showing all {len(self.viewer_lines)} lines")

    def _ensure_tree_visible(self):
        """Scroll tree pane to keep cursor visible."""
        height, _ = self.stdscr.getmaxyx()
        available = height - 5  # Account for header, labels, status

        if self.tree_cursor < self.tree_start:
            self.tree_start = self.tree_cursor
        elif self.tree_cursor >= self.tree_start + available:
            self.tree_start = self.tree_cursor - available + 1

    def _ensure_viewer_visible(self):
        """Scroll viewer pane to keep cursor visible."""
        height, _ = self.stdscr.getmaxyx()
        available = height - 5

        if self.viewer_cursor < self.viewer_start:
            self.viewer_start = self.viewer_cursor
        elif self.viewer_cursor >= self.viewer_start + available:
            self.viewer_start = self.viewer_cursor - available + 1

    def _set_status(self, msg: str):
        """Set status bar message."""
        self.status_msg = msg
        self.status_time = os.times().elapsed

    def _get_status_text(self) -> str:
        """Get current status bar text with filter indicator."""
        filter_indicator = ""
        if self.filter_mode == "errors":
            filter_indicator = " [FILTER: errors/warns] "
        elif self.filter_mode == "critical":
            filter_indicator = " [FILTER: critical] "

        pane = "TREE" if self.active_pane == "tree" else "VIEWER"
        return f" {pane}{filter_indicator}│ {self.status_msg} "

    @staticmethod
    def _is_config_file(path: Path) -> bool:
        """Check if file is a Splunk config file."""
        suffix = path.suffix.lower()
        name = path.name.lower()
        return suffix in (".conf", ".cfg", ".ini", ".xml", ".json", ".yaml", ".yml") \
            or name in ("inputs.conf", "outputs.conf", "server.conf", "web.conf",
                        "indexes.conf", "props.conf", "transforms.conf", "limits.conf",
                        "authentication.conf", "authorize.conf", "deploymentclient.conf")

    @staticmethod
    def _is_log_file(path: Path) -> bool:
        """Check if file is a log file."""
        suffix = path.suffix.lower()
        name = path.name.lower()
        return suffix in (".log",) \
            or "log" in name \
            or name in ("splunkd.log", "splunkd_stderr.log", "splunkd_stdout.log",
                        "web_service.log", "mongod.log", "audit.log")


# ─── Entry Point ─────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <splunk-diag.tar.gz>")
        print("\nTerminal UI for browsing Splunk diagnostic archives.")
        print("Navigate files, view logs with syntax highlighting, search and filter.")
        sys.exit(1)

    archive_path = sys.argv[1]
    if not os.path.isfile(archive_path):
        print(f"Error: File not found: {archive_path}")
        sys.exit(1)

    print(f"Loading {archive_path}...")
    tui = DiagTUI(archive_path)
    print(f"Loaded {len(tui.tree_items)} entries. Starting TUI...")
    try:
        tui.run()
    except KeyboardInterrupt:
        pass
    finally:
        tui.archive.cleanup()
    print("Bye!")


if __name__ == "__main__":
    main()
