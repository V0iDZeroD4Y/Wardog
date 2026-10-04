"""
banner.py - The WarDog ASCII logo and terminal color helpers.

Terminal colors work through ANSI escape codes: special character sequences
like "\033[31m" that the terminal interprets as "switch to red" instead of
printing. "\033[0m" resets back to normal.
"""

import os
import re
import sys

# r"""...""" is a "raw string": backslashes are kept as-is, which matters
# because ASCII art is full of them.
DOG = r"""
                                 __
          ,                    ,"  `-.
          |`-.__..--------.._.'  o  ,`--.
           `.                       ___ )  . : .
             \    ,_______.    .--'   ~   sniff
              \  /         \  /
               ||           ||
               ''           ''"""

TITLE = r"""
__        __     _     ____   ____    ___    ____ 
\ \      / /    / \   |  _ \ |  _ \  / _ \  / ___|
 \ \ /\ / /    / _ \  | |_) || | | || | | || |  _ 
  \ V  V /    / ___ \ |  _ < | |_| || |_| || |_| |
   \_/\_/    /_/   \_\|_| \_\|____/  \___/  \____|"""

TAGLINE = "       a loyal hound on patrol in your logs"

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------

CODES = {
    "reset": "0", "bold": "1", "dim": "2",
    "red": "31", "green": "32", "yellow": "33", "blue": "34",
    "magenta": "35", "cyan": "36", "white": "37",
    "amber": "38;5;214",   # 256-color mode orange
}

ANSI_PATTERN = re.compile(r"\033\[[0-9;]*m")


def colors_enabled():
    """Only use color when writing to a real terminal.

    If output is piped to a file or another program, escape codes would show
    up as junk. NO_COLOR is a common convention for opting out (no-color.org).
    """
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ


USE_COLOR = colors_enabled()


def c(text, *styles):
    """Wrap text in color codes, e.g. c("ALERT", "red", "bold")."""
    if not USE_COLOR or not styles:
        return str(text)
    codes = ";".join(CODES[s] for s in styles)
    return f"\033[{codes}m{text}\033[0m"


def visible_len(text):
    """Length of text as it appears on screen (escape codes take no space)."""
    return len(ANSI_PATTERN.sub("", text))


def logo():
    """Return the full colored logo as one string."""
    return "\n".join([
        c(DOG.strip("\n"), "amber"),
        c(TITLE.strip("\n"), "cyan", "bold"),
        c(TAGLINE, "dim"),
    ])


if __name__ == "__main__":
    print(logo())
