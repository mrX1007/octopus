#!/usr/bin/env python3
"""
Unified ANSI color constants and formatting helpers for OCTOPUS CLI.

Usage:
    from core.colors import C, style, severity_color

    print(f"{C.GREEN}[+] Success{C.RESET}")
    print(style("Warning message", C.YELLOW))
    print(f"{severity_color('CRITICAL')}VULN{C.RESET}")
"""


class C:
    """ANSI color and style constants."""

    # Styles
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    INVERSE = "\033[7m"
    STRIKETHROUGH = "\033[9m"

    # Foreground colors
    BLACK = "\033[30m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"

    # Background colors
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"
    BG_WHITE = "\033[47m"

    # Semantic aliases
    SUCCESS = GREEN
    ERROR = RED
    WARNING = YELLOW
    INFO = CYAN
    MUTED = GRAY
    ACCENT = MAGENTA
    HIGHLIGHT = BOLD + CYAN


_SEVERITY_COLORS = {
    "critical": C.BOLD + C.RED,
    "high": C.RED,
    "medium": C.YELLOW,
    "low": C.GREEN,
    "info": C.CYAN,
    "unknown": C.GRAY,
}


def severity_color(level: str) -> str:
    """Return ANSI escape for a severity level string."""
    return _SEVERITY_COLORS.get(level.lower().strip(), C.GRAY)


def style(text: str, color: str) -> str:
    """Wrap text in color codes with auto-reset."""
    return f"{color}{text}{C.RESET}"


def success(msg: str) -> str:
    """Format a success message."""
    return f"{C.GREEN}[+] {msg}{C.RESET}"


def warn(msg: str) -> str:
    """Format a warning message."""
    return f"{C.YELLOW}[!] {msg}{C.RESET}"


def error(msg: str) -> str:
    """Format an error message."""
    return f"{C.RED}[✗] {msg}{C.RESET}"


def info(msg: str) -> str:
    """Format an info message."""
    return f"{C.CYAN}[*] {msg}{C.RESET}"


def divider(title: str = "", width: int = 60, char: str = "─") -> str:
    """Create a section divider with optional centered title."""
    if title:
        pad = (width - len(title) - 2) // 2
        return f"{C.CYAN}{char * pad} {title} {char * pad}{C.RESET}"
    return f"{C.CYAN}{char * width}{C.RESET}"


def table_header(*columns: tuple[str, int]) -> str:
    """Format a table header row with column widths.

    Args:
        columns: Tuples of (header_text, width).

    Returns:
        Formatted header string with separator line.
    """
    header = "  " + "".join(f"{col:<{w}}" for col, w in columns)
    sep = "  " + "─" * sum(w for _, w in columns)
    return f"{C.CYAN}{header}\n{sep}{C.RESET}"
