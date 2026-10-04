#!/usr/bin/env python3
"""
wardog.py - Command-line entry point.

Usage:
  python3 wardog.py ingest sample_logs/access.log sample_logs/auth.log
  python3 wardog.py stats
  python3 wardog.py search --ip 198.51.100.7
  python3 wardog.py dashboard
  python3 wardog.py dashboard --watch 5 --ingest /var/log/auth.log
  cat /var/log/auth.log | python3 wardog.py ingest -
"""

import argparse
import os
import sys
import time

import banner
import dashboard
import database
import detection
from parsers import parse_line, PARSERS

DEFAULT_DB = "wardog.db"
BATCH_SIZE = 1000  # insert in chunks so huge files don't eat all your memory

# ANSI codes for full-screen refreshing in watch mode
CLEAR_SCREEN = "\033[H\033[2J"
HIDE_CURSOR = "\033[?25l"
SHOW_CURSOR = "\033[?25h"


# ---------------------------------------------------------------------------
# Core ingest logic (reused by the 'ingest' and 'dashboard' commands)
# ---------------------------------------------------------------------------

def ingest_source(conn, path, fmt="auto", verbose=False):
    """Parse one file (or '-' for stdin) into the database.

    Returns a dict of counts, or None if the file doesn't exist.
    """
    if path == "-":
        handle, label = sys.stdin, "<stdin>"
    else:
        if not os.path.isfile(path):
            return None
        handle = open(path, "r", encoding="utf-8", errors="replace")
        label = os.path.abspath(path)

    counts = {"label": label, "parsed": 0, "new": 0, "unparsed": 0}
    batch = []

    with handle:
        for line_number, line in enumerate(handle, start=1):
            record = parse_line(line, fmt)
            if record is None:
                if line.strip():
                    counts["unparsed"] += 1
                    if verbose:
                        print(f"    skipped line {line_number}: {line.strip()[:80]}")
                continue

            raw = line.rstrip("\n")
            record["raw"] = raw
            record["source_file"] = label
            record["line_hash"] = database.make_line_hash(label, line_number, raw)
            batch.append(record)
            counts["parsed"] += 1

            if len(batch) >= BATCH_SIZE:
                counts["new"] += database.insert_events(conn, batch)
                batch.clear()

    if batch:
        counts["new"] += database.insert_events(conn, batch)
    return counts


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_ingest(args):
    conn = database.connect(args.db)
    for path in args.files:
        counts = ingest_source(conn, path, args.format, args.verbose)
        if counts is None:
            print(banner.c(f"[!] File not found: {path}", "red"), file=sys.stderr)
            continue
        dupes = counts["parsed"] - counts["new"]
        print(banner.c(f"[+] {counts['label']}", "green"))
        print(f"    parsed: {counts['parsed']}  new: {counts['new']}  "
              f"duplicates: {dupes}  unparsed: {counts['unparsed']}")
    conn.close()


def cmd_stats(args):
    conn = database.connect(args.db)
    s = database.get_stats(conn, top=args.top)
    conn.close()

    if s["total"] == 0:
        print("Database is empty. Run 'ingest' first.")
        return

    start, end = s["time_range"]
    print(f"\nTotal events: {s['total']}")
    print(f"Time range:   {start}  ->  {end}")

    print_table("Events by source", ["source", "count"], s["by_source"])
    print_table(f"Top {args.top} IPs", ["ip", "count"], s["top_ips"])
    print_table("HTTP status codes", ["status", "count"], s["status_codes"])
    print_table(f"Top {args.top} processes", ["process", "count"], s["top_processes"])


def cmd_search(args):
    conn = database.connect(args.db)
    rows = database.search_events(
        conn, ip=args.ip, source=args.source, status=args.status,
        text=args.text, limit=args.limit,
    )
    conn.close()

    if not rows:
        print("No matching events.")
        return

    print_table(
        f"{len(rows)} event(s)",
        ["timestamp", "source", "ip", "message"],
        [(r["timestamp"], r["source"], r["ip"] or "-", (r["message"] or "")[:70]) for r in rows],
    )


def cmd_dashboard(args):
    conn = database.connect(args.db)

    def draw(footer=None):
        # Re-ingest watched files first. Thanks to the line_hash dedup,
        # only lines added since last time actually get inserted.
        for path in args.ingest or []:
            ingest_source(conn, path)
        # Re-run detection each refresh so the threat panel stays current.
        database.save_findings(conn, detection.run_rules(conn))
        data = database.get_dashboard_data(conn, top=args.top, recent=args.recent)
        return dashboard.render(data, os.path.abspath(args.db), footer=footer)

    if not args.watch:
        print(draw())
        conn.close()
        return

    # Watch mode: redraw every N seconds until Ctrl+C.
    interactive = sys.stdout.isatty()
    try:
        if interactive:
            sys.stdout.write(HIDE_CURSOR)
        while True:
            footer = (f"refreshing every {args.watch}s · "
                      f"{time.strftime('%H:%M:%S')} · Ctrl+C to quit")
            frame = draw(footer)
            sys.stdout.write((CLEAR_SCREEN if interactive else "") + frame + "\n")
            sys.stdout.flush()
            time.sleep(args.watch)
    except KeyboardInterrupt:
        pass
    finally:
        if interactive:
            sys.stdout.write(SHOW_CURSOR + "\n")
        conn.close()


def cmd_detect(args):
    conn = database.connect(args.db)
    findings = detection.run_rules(conn)
    new = database.save_findings(conn, findings)
    conn.close()

    if not findings:
        print(banner.c("No findings. Either all clear, or no logs ingested yet.", "green"))
        return

    print(banner.c(f"\n{len(findings)} finding(s), {len(new)} new:\n", "bold"))
    for f in findings:
        color = dashboard._severity_color(f["severity"])
        print("  " + banner.c(detection.format_finding_line(f), color))
    print(banner.c("\nReview them anytime with:  python3 wardog.py threats", "dim"))


def cmd_threats(args):
    conn = database.connect(args.db)
    status = None if args.all else "open"
    rows = database.get_findings(conn, status=status, limit=args.limit)
    conn.close()

    if not rows:
        print(banner.c("No findings stored. Run 'detect' first.", "yellow"))
        return

    for r in rows:
        color = dashboard._severity_color(r["severity"])
        tag = "" if r["status"] == "open" else banner.c(" (acknowledged)", "dim")
        print(banner.c(f"#{r['id']:<3} [{r['severity'].upper():<8}]", color, "bold")
              + f" {r['title']}{tag}")
        print(f"      {r['detail']}")
        print(banner.c(f"      {r['event_count']} event(s) · {r['first_seen']} → {r['last_seen']}", "dim"))
    print(banner.c(f"\nAcknowledge one with:  python3 wardog.py ack <id>", "dim"))


def cmd_ack(args):
    conn = database.connect(args.db)
    changed = database.acknowledge_finding(conn, args.id)
    conn.close()
    if changed:
        print(banner.c(f"Finding #{args.id} acknowledged.", "green"))
    else:
        print(banner.c(f"No open finding with id #{args.id}.", "yellow"))


def cmd_monitor(args):
    """Continuous ingestion: tail files, detect, repeat. Good under cron/systemd
    too, but this loop is the simplest 'always-on' form."""
    conn = database.connect(args.db)
    print(banner.logo())
    print(banner.c(f"\nMonitoring {len(args.files)} file(s) every {args.interval}s. "
                   f"Ctrl+C to stop.\n", "cyan"))
    try:
        while True:
            new_events = 0
            for path in args.files:
                counts = ingest_source(conn, path)
                if counts is None:
                    print(banner.c(f"[!] missing: {path}", "red"), file=sys.stderr)
                else:
                    new_events += counts["new"]

            new_findings = database.save_findings(conn, detection.run_rules(conn))
            stamp = time.strftime("%H:%M:%S")

            if new_events or new_findings:
                line = f"[{stamp}] +{new_events} new event(s)"
                if new_findings:
                    line += banner.c(f"  ⚠ {len(new_findings)} NEW finding(s)", "red", "bold")
                print(line)
                for f in new_findings:
                    color = dashboard._severity_color(f["severity"])
                    print("    " + banner.c(detection.format_finding_line(f), color))
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print(banner.c("\nStopped.", "dim"))
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Output helper
# ---------------------------------------------------------------------------

def print_table(title, headers, rows):
    """Print rows as a simple aligned text table."""
    rows = [tuple("" if v is None else str(v) for v in row) for row in rows]
    if not rows:
        return
    widths = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(headers)]

    print("\n" + banner.c(f"== {title} ==", "cyan", "bold"))
    print("  ".join(h.ljust(w) for h, w in zip(headers, widths)))
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print("  ".join(v.ljust(w) for v, w in zip(row, widths)))


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="wardog",
        description="Parse log files into a searchable SQLite database.",
    )
    parser.add_argument("--db", default=DEFAULT_DB, help=f"database file (default: {DEFAULT_DB})")
    sub = parser.add_subparsers(dest="command")

    p_ingest = sub.add_parser("ingest", help="parse log files into the database")
    p_ingest.add_argument("files", nargs="+", help="log file(s) to read, or '-' for stdin")
    p_ingest.add_argument("-f", "--format", default="auto",
                          choices=["auto", *PARSERS.keys()], help="log format (default: auto)")
    p_ingest.add_argument("-v", "--verbose", action="store_true", help="show lines that failed to parse")
    p_ingest.set_defaults(func=cmd_ingest)

    p_stats = sub.add_parser("stats", help="show a summary of what's in the database")
    p_stats.add_argument("--top", type=int, default=10, help="how many top IPs/processes to show")
    p_stats.set_defaults(func=cmd_stats)

    p_search = sub.add_parser("search", help="search stored events")
    p_search.add_argument("--ip", help="exact IP address")
    p_search.add_argument("--source", choices=list(PARSERS.keys()), help="log type")
    p_search.add_argument("--status", type=int, help="HTTP status code, e.g. 404")
    p_search.add_argument("--text", help="text to look for anywhere in the raw line")
    p_search.add_argument("--limit", type=int, default=50, help="max results (default: 50)")
    p_search.set_defaults(func=cmd_search)

    p_dash = sub.add_parser("dashboard", help="visual overview in the terminal")
    p_dash.add_argument("-w", "--watch", type=int, metavar="SECONDS",
                        help="keep refreshing every N seconds (live mode)")
    p_dash.add_argument("-i", "--ingest", nargs="+", metavar="FILE",
                        help="re-ingest these files before each refresh")
    p_dash.add_argument("--top", type=int, default=8, help="how many top IPs to show")
    p_dash.add_argument("--recent", type=int, default=10, help="how many recent events to show")
    p_dash.set_defaults(func=cmd_dashboard)

    p_detect = sub.add_parser("detect", help="run detection rules and store findings")
    p_detect.set_defaults(func=cmd_detect)

    p_threats = sub.add_parser("threats", help="list stored security findings")
    p_threats.add_argument("--all", action="store_true", help="include acknowledged findings")
    p_threats.add_argument("--limit", type=int, default=200, help="max findings to show")
    p_threats.set_defaults(func=cmd_threats)

    p_ack = sub.add_parser("ack", help="acknowledge (dismiss) a finding by id")
    p_ack.add_argument("id", type=int, help="finding id from 'threats'")
    p_ack.set_defaults(func=cmd_ack)

    p_monitor = sub.add_parser("monitor", help="continuously ingest files and detect")
    p_monitor.add_argument("files", nargs="+", help="log file(s) to keep watching")
    p_monitor.add_argument("-n", "--interval", type=int, default=10,
                           help="seconds between checks (default: 10)")
    p_monitor.set_defaults(func=cmd_monitor)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # No command given: show the logo and the help text.
    if args.command is None:
        print(banner.logo() + "\n")
        parser.print_help()
        return

    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
    except BrokenPipeError:
        # Happens when output is piped into something like `head` that exits
        # early. Silence Python's own warning and exit cleanly.
        try:
            sys.stdout.close()
        except Exception:
            pass
        os._exit(0)


if __name__ == "__main__":
    main()
