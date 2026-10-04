# wardog 🐕

```
                                 __
          ,                    ,"  `-.
          |`-.__..--------.._.'  o  ,`--.
           `.                       ___ )  . : .
             \    ,_______.    .--'   ~   sniff
              \  /         \  /
               ||           ||
               ''           ''
__        __     _     ____   ____    ___    ____ 
\ \      / /    / \   |  _ \ |  _ \  / _ \  / ___|
 \ \ /\ / /    / _ \  | |_) || | | || | | || |  _ 
  \ V  V /    / ___ \ |  _ < | |_| || |_| || |_| |
   \_/\_/    /_/   \_\|_| \_\|____/  \___/  \____|
```

A lightweight command-line tool that parses log files into a searchable SQLite database. Built as the first stage of a personal security monitoring pipeline.

Pure Python standard library, so there's nothing to `pip install`.

## Features

- Parses **web server access logs** (Apache / Nginx combined & common formats)
- Parses **syslog / auth.log** lines (sshd, sudo, cron, etc.)
- Auto-detects the format of each line
- Stores everything in a single SQLite file with indexes for fast searching
- Skips duplicates, so you can safely re-run it on a log that keeps growing
- Reads from files or from a pipe (`-` for stdin)
- `stats` summary and `search` filtering by IP, status code, log type, or text
- **Live terminal dashboard** with stat cards, bar charts, hourly activity, and color-coded recent events
- Watch mode that auto-ingests growing log files and refreshes on a timer
- **Rule-based detection**: SSH brute force, web path scanning, SQL injection / path traversal, and known attack tools (sqlmap, nikto, nmap, …)
- **Threat view**: findings stored, deduplicated, severity-ranked, and shown both on the dashboard and via a `threats` command; acknowledge handled ones
- **Continuous monitoring**: a `monitor` loop that ingests + detects on an interval and prints new findings as they happen

## Requirements

Python 3.8+ (check with `python3 --version`).

## Usage

```bash
# Load logs into the database (creates wardog.db)
python3 wardog.py ingest sample_logs/access.log sample_logs/auth.log

# Summary: top IPs, status codes, processes
python3 wardog.py stats

# Search
python3 wardog.py search --ip 198.51.100.7
python3 wardog.py search --status 404
python3 wardog.py search --text "Failed password"
python3 wardog.py search --source syslog --limit 20

# Dashboard (one-time snapshot)
python3 wardog.py dashboard

# Live dashboard: refresh every 5 seconds, pulling in new lines from a log
python3 wardog.py dashboard --watch 5 --ingest /var/log/auth.log

# Pipe logs in from another command
cat /var/log/auth.log | python3 wardog.py ingest -

# Use a different database file
python3 wardog.py --db mylogs.db stats

# Show lines that couldn't be parsed
python3 wardog.py ingest -v some.log
```

Run `python3 wardog.py <command> --help` for every option.

## Project structure

```
wardog/
├── wardog.py      # CLI entry point: commands and argument parsing
├── parsers.py       # Regex parsers that turn raw lines into structured records
├── database.py      # SQLite schema, inserts, dedup, and queries
├── dashboard.py     # Terminal dashboard rendering (boxes, bars, colors)
├── banner.py        # ASCII logo and ANSI color helpers
├── detection.py     # Rule engine: brute force, scanning, injection, tools
├── sample_logs/     # Example logs (uses reserved documentation IP ranges)
└── README.md
```

## Roadmap

- [x] Log parsing + database storage
- [x] Rule-based detection: flag brute force, scanners, injection attempts
- [x] Terminal dashboard
- [x] Threat view: highlight high-severity events, hide the noise
- [x] Scheduled / continuous ingestion

Colors turn off automatically when output is piped, or set `NO_COLOR=1`.

## Running it on a schedule

The `monitor` command is the simplest always-on form - leave it running in a
terminal (or under `tmux`). To run it as a background service or on a timer:

**macOS (launchd), every 5 minutes:** create
`~/Library/LaunchAgents/com.wardog.plist` pointing at a small script that runs
`ingest` then `detect`, and load it with `launchctl load`.

**Linux/macOS (cron), every 5 minutes:**

```cron
*/5 * * * * cd /path/to/wardog && /usr/bin/python3 wardog.py ingest /var/log/auth.log && /usr/bin/python3 wardog.py detect >> ~/wardog-cron.log 2>&1
```

Because ingest deduplicates by line, running it repeatedly only picks up new
lines - so a frequent cron job is cheap and safe.

## Detection rules

| Rule | Severity | What triggers it |
|------|----------|------------------|
| SSH brute force | high | 5+ failed SSH passwords from one IP |
| Web path scanning | medium | 4+ distinct 404s from one IP |
| SQL injection / path traversal | critical | attack patterns in the request path |
| Attack tool user-agent | high | sqlmap, nikto, nmap, gobuster, etc. |

Thresholds live at the top of `detection.py` - tune them to your environment.

## Disclaimer

Intended for analyzing logs from systems you own or are authorized to monitor.
