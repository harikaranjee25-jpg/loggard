"""LogGuard analyzer: detects common attacks in web access logs and SSH auth logs."""
import re
from collections import Counter, defaultdict

ACCESS_RE = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" (?P<status>\d{3}) \S+ "[^"]*" "(?P<ua>[^"]*)"'
)
AUTH_FAIL_RE = re.compile(
    r'^(?P<time>\w{3}\s+\d+\s[\d:]+).*sshd.*Failed password for (?:invalid user )?'
    r'(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
)

SQLI_RE = re.compile(r"(union(\s|%20|\+)+select|or(\s|%20|\+)+1=1|sleep\(|information_schema|--(\s|$)|'\s*or\s*')", re.I)
XSS_RE = re.compile(r"(<script|%3cscript|onerror=|javascript:)", re.I)
TRAVERSAL_RE = re.compile(r"(\.\./|%2e%2e%2f|/etc/passwd)", re.I)
BAD_UA = ("sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster", "hydra")

BRUTE_THRESHOLD = 5      # failed logins from one IP
SCAN_THRESHOLD = 10      # 404 responses from one IP

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}


def _add(findings, ip, attack, severity, detail, time=""):
    findings.append({"ip": ip, "attack": attack, "severity": severity,
                     "detail": detail[:150], "time": time})


def analyze(text):
    findings = []
    requests_per_ip = Counter()
    login_fails = defaultdict(int)
    not_found = defaultdict(int)
    ssh_fails = defaultdict(int)
    total_lines = parsed = 0

    for line in text.splitlines():
        if not line.strip():
            continue
        total_lines += 1

        m = ACCESS_RE.search(line)
        if m:
            parsed += 1
            ip, path, status = m["ip"], m["path"], m["status"]
            ua, t = m["ua"].lower(), m["time"]
            requests_per_ip[ip] += 1
            if SQLI_RE.search(path):
                _add(findings, ip, "SQL Injection", "High", path, t)
            if XSS_RE.search(path):
                _add(findings, ip, "Cross-Site Scripting (XSS)", "Medium", path, t)
            if TRAVERSAL_RE.search(path):
                _add(findings, ip, "Path Traversal", "High", path, t)
            if any(b in ua for b in BAD_UA):
                _add(findings, ip, "Scanner / Attack Tool", "High", m["ua"], t)
            if status in ("401", "403") and "login" in path.lower():
                login_fails[ip] += 1
            if status == "404":
                not_found[ip] += 1
            continue

        a = AUTH_FAIL_RE.search(line)
        if a:
            parsed += 1
            requests_per_ip[a["ip"]] += 1
            ssh_fails[a["ip"]] += 1

    for ip, c in login_fails.items():
        if c >= BRUTE_THRESHOLD:
            _add(findings, ip, "Web Login Brute Force", "High", f"{c} failed login attempts")
    for ip, c in ssh_fails.items():
        if c >= BRUTE_THRESHOLD:
            _add(findings, ip, "SSH Brute Force", "High", f"{c} failed SSH passwords")
    for ip, c in not_found.items():
        if c >= SCAN_THRESHOLD:
            _add(findings, ip, "Directory Scanning", "Medium", f"{c} x HTTP 404")

    findings.sort(key=lambda f: SEVERITY_ORDER[f["severity"]])
    return {
        "total_lines": total_lines,
        "parsed_lines": parsed,
        "findings": findings,
        "top_ips": requests_per_ip.most_common(5),
        "by_type": dict(Counter(f["attack"] for f in findings)),
        "by_severity": dict(Counter(f["severity"] for f in findings)),
    }
