"""
dashboard.py - Draws the terminal dashboard.

Everything here builds plain lists of strings ("lines") and then glues them
together. Keeping the drawing separate from the database code means you
could swap this for a web dashboard later without touching anything else.
"""

import shutil
from datetime import datetime

from banner import c, logo, visible_len

BLOCKS = " ▏▎▍▌▋▊▉█"  # partial blocks give bars 8x finer resolution


# ---------------------------------------------------------------------------
# Small drawing helpers
# ---------------------------------------------------------------------------

def pad(text, width):
    """Pad text with spaces to an exact on-screen width (color-safe)."""
    return text + " " * max(0, width - visible_len(text))


def clip(text, width):
    """Cut plain (uncolored) text down to a width, adding … if it was cut."""
    text = str(text)
    return text if len(text) <= width else text[: max(0, width - 1)] + "…"


def bar(value, maximum, width):
    """A horizontal bar like ██████▍ scaled so `maximum` fills `width`."""
    if maximum <= 0 or width <= 0:
        return ""
    eighths = round(value / maximum * width * 8)
    full, part = divmod(eighths, 8)
    return "█" * full + (BLOCKS[part] if part else "")


def box(title, lines, width):
    """Draw a rounded box with a title around a list of lines."""
    inner = width - 4  # 2 border chars + 1 space padding each side
    title = clip(title, width - 6)  # never let a title break the border
    top = "╭─ " + c(title, "bold") + " " + "─" * max(0, width - visible_len(title) - 5) + "╮"
    body = [f"│ {pad(line, inner)} │" for line in lines] or [f"│ {pad(c('no data', 'dim'), inner)} │"]
    bottom = "╰" + "─" * (width - 2) + "╯"
    return [top, *body, bottom]


def side_by_side(left, right, gap=2):
    """Place two blocks of lines next to each other."""
    left_w = max((visible_len(l) for l in left), default=0)
    right_w = max((visible_len(r) for r in right), default=0)
    height = max(len(left), len(right))
    left = left + [" " * left_w] * (height - len(left))
    right = right + [" " * right_w] * (height - len(right))
    return [pad(l, left_w) + " " * gap + r for l, r in zip(left, right)]


# ---------------------------------------------------------------------------
# Panels
# ---------------------------------------------------------------------------

def stat_cards(summary, width):
    """The row of big-number cards across the top."""
    failed = summary["failed_logins"] or 0
    errs4 = summary["client_errors"] or 0
    errs5 = summary["server_errors"] or 0

    cards = [
        ("Events", summary["total"], "cyan"),
        ("Unique IPs", summary["unique_ips"], "cyan"),
        ("Failed logins", failed, "red" if failed else "green"),
        ("HTTP 4xx", errs4, "yellow" if errs4 else "green"),
        ("HTTP 5xx", errs5, "red" if errs5 else "green"),
    ]

    # Each card needs ~18 columns to fit its title, so wrap to fewer per row on narrow screens.
    per_row = 5 if width >= 94 else 3 if width >= 58 else 2
    card_w = (width - (per_row - 1)) // per_row
    lines = []
    for i in range(0, len(cards), per_row):
        row = [
            box(label, [c(f"{value:,}", color, "bold")], card_w)
            for label, value, color in cards[i:i + per_row]
        ]
        merged = row[0]
        for card in row[1:]:
            merged = side_by_side(merged, card, gap=1)
        lines += merged
    return lines


def top_ips_panel(rows, width):
    inner = width - 4
    if not rows:
        return box("Top IPs", [], width)
    biggest = rows[0]["n"]
    ip_w, num_w = 15, len(str(biggest))
    bar_w = inner - ip_w - num_w - 2
    lines = [
        f"{clip(r['ip'], ip_w):<{ip_w}} {c(bar(r['n'], biggest, bar_w).ljust(bar_w), 'amber')} "
        f"{r['n']:>{num_w}}"
        for r in rows
    ]
    return box("Top IPs", lines, width)


def status_panel(rows, width):
    inner = width - 4
    if not rows:
        return box("HTTP status codes", [], width)
    biggest = max(r["n"] for r in rows)
    num_w = len(str(biggest))
    bar_w = inner - 3 - num_w - 2   # '404' + 2 spaces + count
    lines = []
    for r in rows:
        color = _status_color(r["status"])
        lines.append(f"{c(r['status'], color, 'bold')} {c(bar(r['n'], biggest, bar_w).ljust(bar_w), color)} {r['n']:>{num_w}}")
    return box("HTTP status codes", lines, width)


def hourly_panel(rows, width):
    inner = width - 4
    if not rows:
        return box("Activity by hour", [], width)
    biggest = max(r["n"] for r in rows)
    num_w = len(str(biggest))
    bar_w = inner - 16 - num_w - 2  # 'YYYY-MM-DD HH:00' + 2 spaces + count
    lines = []
    for r in rows:
        label = r["hour"].replace("T", " ") + ":00"  # '2026-10-04 09:00'
        lines.append(f"{label} {c(bar(r['n'], biggest, bar_w).ljust(bar_w), 'cyan')} {r['n']:>{num_w}}")
    return box("Activity by hour", lines, width)


def recent_panel(rows, width):
    inner = width - 4
    msg_w = max(10, inner - 8 - 2 - 6 - 2 - 15 - 2)
    lines = []
    for r in rows:
        time = (r["timestamp"] or "")[11:19] or "--:--:--"
        msg = clip((r["message"] or "").strip(), msg_w)
        color = _event_color(r)
        line = f"{c(time, 'dim')}  {r['source']:<6}  {clip(r['ip'] or '-', 15):<15}  {c(msg, color) if color else msg}"
        lines.append(line)
    return box("Recent events", lines, width)


def _severity_color(severity):
    return {
        "critical": "red", "high": "red", "medium": "yellow",
        "low": "blue", "info": "dim",
    }.get(severity, "white")


def threat_panel(findings, width):
    """The most important panel: active security findings, worst first."""
    inner = width - 4
    if not findings:
        return box("Threats", [c("✓ No active threats detected", "green")], width)

    lines = []
    for f in findings:
        color = _severity_color(f["severity"])
        badge = c(f"[{f['severity'].upper()}]", color, "bold")
        ip = c(clip(f["ip"] or "-", 15), "white")
        # Reserve room for the badge + ip, then clip the title to what's left.
        used = visible_len(badge) + 1 + 15 + 1
        title = clip(f["title"], max(10, inner - used))
        lines.append(f"{badge} {ip:<15} {title}")
    return box(f"⚠ Threats ({len(findings)} open)", lines, width)


# ---------------------------------------------------------------------------
# Color rules
# ---------------------------------------------------------------------------

def _status_color(status):
    if status >= 500:
        return "red"
    if status >= 400:
        return "yellow"
    if status >= 300:
        return "blue"
    return "green"


def _event_color(row):
    """Pick a color for an event line based on simple keywords and status.

    This is just visual - real threat detection comes in the next stage.
    """
    msg = (row["message"] or "").lower()
    status = row["status"]
    if (status and status >= 500) or "failed" in msg or "invalid user" in msg:
        return "red"
    if status and status >= 400:
        return "yellow"
    if "accepted" in msg:
        return "green"
    return None


# ---------------------------------------------------------------------------
# Putting it together
# ---------------------------------------------------------------------------

def terminal_width():
    """Current terminal width, kept between 60 and 120 columns."""
    return max(60, min(120, shutil.get_terminal_size((100, 30)).columns))


def render(data, db_path, footer=None, width=None):
    """Build the whole dashboard and return it as one string."""
    width = width or terminal_width()
    s = data["summary"]
    out = []

    out.append(logo() if width >= 56 else c("WARDOG", "cyan", "bold"))
    out.append("")
    out.append(
        f"{c('db', 'dim')} {db_path}   "
        f"{c('range', 'dim')} {s['first_seen'] or '-'} → {s['last_seen'] or '-'}"
    )
    out.append("")

    if not s["total"]:
        out.append(c("Database is empty. Run 'ingest' first, e.g.:", "yellow"))
        out.append("  python3 wardog.py ingest sample_logs/access.log sample_logs/auth.log")
        return "\n".join(out)

    out += stat_cards(s, width)
    out += threat_panel(data.get("findings", []), width)

    # Two columns on wide terminals, stacked on narrow ones.
    if width >= 90:
        left_w = (width - 2) // 2
        right_w = width - 2 - left_w
        out += side_by_side(top_ips_panel(data["top_ips"], left_w),
                            status_panel(data["status_codes"], right_w))
    else:
        out += top_ips_panel(data["top_ips"], width)
        out += status_panel(data["status_codes"], width)

    out += hourly_panel(data["by_hour"], width)
    out += recent_panel(data["recent"], width)

    stamp = datetime.now().strftime("%H:%M:%S")
    out.append(c(footer or f"updated {stamp}", "dim"))
    return "\n".join(out)
