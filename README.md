# 🛡️ LogGuard – Log Analyzer & Threat Dashboard

Cybersecurity Capstone Project (Module 06)

LogGuard is a web-based **defensive security tool**. Upload a web server access log or an SSH auth log and it detects common attack patterns and shows them on a dashboard.

**Live demo:** `https://loggard.onrender.com`
**Demo video:** `<add link>`

## Features
| Detection | Severity | How |
|---|---|---|
| SQL Injection | High | Regex on request path (`UNION SELECT`, `OR 1=1`, `sleep(`, ...) |
| Path Traversal | High | `../`, `%2e%2e%2f`, `/etc/passwd` |
| Scanner / attack tools | High | User-Agent: sqlmap, nikto, nmap, gobuster, hydra... |
| Web login brute force | High | 5+ failed (401/403) `/login` requests from one IP |
| SSH brute force | High | 5+ `Failed password` entries from one IP |
| XSS | Medium | `<script`, `onerror=`, `javascript:` |
| Directory scanning | Medium | 10+ HTTP 404 from one IP |

Dashboard: summary stats, attack-type chart, top IPs, findings table, CSV export.

## Run locally
```bash
git clone https://github.com/harikaranjee25-jpg/loggard.git
cd loggard
python -m venv venv && venv\Scripts\activate     # Windows
pip install -r requirements.txt
python app.py        # open http://127.0.0.1:5000
pytest               # run tests
```

## Deploy (Render)
Build: `pip install -r requirements.txt` · Start: `gunicorn app:app`

## Security design
- Only `.log` / `.txt` accepted, max 2 MB
- Uploads processed in memory, **never saved to disk**
- Jinja2 auto-escaping (log content cannot inject HTML/JS)
- Security headers: CSP, X-Frame-Options, nosniff, Referrer-Policy
- Demo logs selected via allow-list (no user-supplied file paths)
- Runs with `debug=False`

See [docs/architecture.md](docs/architecture.md) and [docs/testing_report.md](docs/testing_report.md).

## Ethics & scope
LogGuard is passive: it only reads logs. All sample logs are self-generated. Only analyze logs from systems you own or are authorized to review.

## Tech stack
Python, Flask, Gunicorn, Chart.js, Pytest, Render
