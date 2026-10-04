"""
detection.py - The rules engine that turns raw events into security findings.

Each rule is a plain function: it takes a database connection and returns a
list of "findings" (dicts). A finding is one security concern worth a human's
attention - a brute-force source, a scanner, an injection attempt.

The rules are deliberately simple and readable. You can look at any one of
them and know exactly why it fired. When you're learning - and when you need
to trust an alert at 2am - that transparency beats cleverness every time.

Adding a rule later is the same pattern as adding a parser: write a function,
add it to the RULES list at the bottom.
"""

import re
from urllib.parse import unquote

# Severity levels, most urgent first. The rank is used for sorting findings
# and for choosing a color in the dashboard.
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# --- Thresholds: lower = stricter (fires more easily). Tune to taste. ---
BRUTE_FORCE_MIN_FAILS = 5   # failed SSH logins from one IP before we care
SCAN_MIN_404 = 4            # distinct 404s from one IP = probing for files

# Request-path patterns that strongly indicate an attack. We test the
# URL-decoded path, so "%27%20OR" is checked as "' OR".
INJECTION_PATTERNS = [
    (re.compile(r"union\s+select", re.I),            "critical", "SQL injection (UNION SELECT)"),
    (re.compile(r"\bor\s+1\s*=\s*1", re.I),          "critical", "SQL injection (OR 1=1)"),
    (re.compile(r"(?:\.\./){2,}|/etc/passwd|/etc/shadow", re.I), "critical", "Path traversal"),
    (re.compile(r"<script|javascript:", re.I),       "high",     "Cross-site scripting (XSS)"),
    (re.compile(r";\s*(?:cat|wget|curl|bash|nc)\s", re.I),       "high", "Command injection"),
]

# Offensive-security tools that announce themselves in the User-Agent header.
# (python-requests / curl are intentionally NOT here - plenty of legitimate
#  scripts use them, so flagging them would drown you in false positives.)
SCANNER_AGENTS = re.compile(
    r"sqlmap|nikto|nmap|masscan|dirbuster|gobuster|hydra|wpscan|acunetix|"
    r"havij|zgrab|feroxbuster",
    re.I,
)


# ---------------------------------------------------------------------------
# Finding helper
# ---------------------------------------------------------------------------

def make_finding(rule, severity, ip, title, detail, count, first, last, key_extra=""):
    """Build one finding dict.

    'signature' is the stable identity of a finding - the thing we dedupe on.
    Two detection runs that find the same problem produce the same signature,
    so the database updates the existing row instead of piling up duplicates.
    """
    signature = f"{rule}|{ip}|{key_extra}" if key_extra else f"{rule}|{ip}"
    return {
        "signature": signature,
        "rule": rule,
        "severity": severity,
        "ip": ip,
        "title": title,
        "detail": detail,
        "event_count": count,
        "first_seen": first,
        "last_seen": last,
    }


# ---------------------------------------------------------------------------
# The rules
# ---------------------------------------------------------------------------

def rule_ssh_brute_force(conn):
    """Many failed SSH logins from one IP = someone guessing passwords.

    Technique: SQL aggregation. GROUP BY ip collapses all of an IP's failures
    into one row, and HAVING filters to only the noisy ones.
    """
    rows = conn.execute(
        """
        SELECT ip, COUNT(*) AS n, MIN(timestamp) AS first, MAX(timestamp) AS last
        FROM events
        WHERE source = 'syslog'
          AND message LIKE 'Failed password%'
          AND ip IS NOT NULL
        GROUP BY ip
        HAVING n >= ?
        """,
        (BRUTE_FORCE_MIN_FAILS,),
    ).fetchall()

    return [
        make_finding(
            "ssh_brute_force", "high", r["ip"],
            title=f"SSH brute force from {r['ip']}",
            detail=f"{r['n']} failed password attempts",
            count=r["n"], first=r["first"], last=r["last"],
        )
        for r in rows
    ]


def rule_web_scanning(conn):
    """One IP generating lots of 404s is walking a wordlist, hunting for files.

    Technique: SQL aggregation again, but we also COUNT(DISTINCT path) so a
    single page refreshed 50 times doesn't look like a scan.
    """
    rows = conn.execute(
        """
        SELECT ip,
               COUNT(*) AS n,
               COUNT(DISTINCT path) AS distinct_paths,
               MIN(timestamp) AS first, MAX(timestamp) AS last
        FROM events
        WHERE source = 'access' AND status = 404 AND ip IS NOT NULL
        GROUP BY ip
        HAVING distinct_paths >= ?
        """,
        (SCAN_MIN_404,),
    ).fetchall()

    return [
        make_finding(
            "web_scanning", "medium", r["ip"],
            title=f"Web path scanning from {r['ip']}",
            detail=f"{r['distinct_paths']} distinct 404s ({r['n']} requests total)",
            count=r["n"], first=r["first"], last=r["last"],
        )
        for r in rows
    ]


def rule_web_injection(conn):
    """Requests whose path matches a known attack pattern.

    Technique: signature matching with regex. SQL can't easily URL-decode or
    run regex, so we pull the candidate rows and test them in Python.
    """
    rows = conn.execute(
        "SELECT ip, path, timestamp FROM events "
        "WHERE source = 'access' AND path IS NOT NULL"
    ).fetchall()

    # Group hits by (ip, attack type) so five injection tries become one finding.
    hits = {}
    for r in rows:
        decoded = unquote(r["path"]).replace("+", " ")
        for pattern, severity, label in INJECTION_PATTERNS:
            if pattern.search(decoded):
                key = (r["ip"], label, severity)
                h = hits.setdefault(
                    key, {"count": 0, "first": r["timestamp"],
                          "last": r["timestamp"], "sample": r["path"]}
                )
                h["count"] += 1
                if r["timestamp"]:
                    h["first"] = min(h["first"] or r["timestamp"], r["timestamp"])
                    h["last"] = max(h["last"] or r["timestamp"], r["timestamp"])

    findings = []
    for (ip, label, severity), h in hits.items():
        findings.append(make_finding(
            "web_injection", severity, ip,
            title=f"{label} from {ip}",
            detail=f"{h['count']} request(s); e.g. {h['sample'][:90]}",
            count=h["count"], first=h["first"], last=h["last"],
            key_extra=label,   # keeps SQLi and traversal from the same IP separate
        ))
    return findings


def rule_scanner_user_agent(conn):
    """A request whose User-Agent is a known attack tool.

    Technique: signature matching on the user_agent field.
    """
    rows = conn.execute(
        """
        SELECT ip, user_agent, COUNT(*) AS n,
               MIN(timestamp) AS first, MAX(timestamp) AS last
        FROM events
        WHERE source = 'access' AND user_agent IS NOT NULL AND ip IS NOT NULL
        GROUP BY ip, user_agent
        """
    ).fetchall()

    findings = []
    for r in rows:
        match = SCANNER_AGENTS.search(r["user_agent"])
        if match:
            tool = match.group(0).lower()
            findings.append(make_finding(
                "scanner_user_agent", "high", r["ip"],
                title=f"Attack tool '{tool}' from {r['ip']}",
                detail=f"User-Agent: {r['user_agent'][:70]} ({r['n']} requests)",
                count=r["n"], first=r["first"], last=r["last"],
                key_extra=tool,
            ))
    return findings


# The registry. Order doesn't matter - findings are sorted by severity after.
RULES = [
    rule_ssh_brute_force,
    rule_web_scanning,
    rule_web_injection,
    rule_scanner_user_agent,
]


def run_rules(conn):
    """Run every rule and return all findings, most severe first."""
    findings = []
    for rule in RULES:
        findings.extend(rule(conn))
    findings.sort(
        key=lambda f: (SEVERITY_RANK[f["severity"]], f["last_seen"] or ""),
        reverse=True,
    )
    return findings


def format_finding_line(finding):
    """One-line plain-text summary, used by the CLI and monitor mode."""
    return f"[{finding['severity'].upper():<8}] {finding['title']}  —  {finding['detail']}"
