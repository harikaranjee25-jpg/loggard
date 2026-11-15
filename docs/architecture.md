# Security Architecture – LogGuard

## Data flow
```
User (browser)
   │  HTTPS (Render TLS)
   ▼
Flask app (app.py)
   ├─ Validate: extension (.log/.txt), size ≤ 2 MB
   ├─ Read file in memory (no disk write)
   ▼
Analyzer (analyzer.py)
   ├─ Parse lines (access log / sshd auth log)
   ├─ Apply detection rules + thresholds
   ▼
Result dict → Jinja2 template (auto-escaped) → Dashboard (Chart.js, CSV export)
```

## Trust boundaries
| Boundary | Threat | Control |
|---|---|---|
| Browser → Server | Malicious/oversized upload | Extension allow-list, 2 MB limit (HTTP 413) |
| Log content → HTML | Stored/reflected XSS via log lines | Jinja2 auto-escape, CSP header |
| Demo selector → filesystem | Path traversal | Fixed allow-list dict, no user paths |
| Server → Internet | Clickjacking, MIME sniffing | X-Frame-Options DENY, nosniff |
| Processing | Regex DoS / crashes | Simple linear regexes, malformed lines skipped, tested |
| Data at rest | Leakage of uploaded logs | Nothing stored |

## Detection logic
Rule-based (signature + threshold). Limitations: signatures can be evaded by encoding tricks, thresholds are per-file not time-windowed, IPs behind NAT/proxies may be grouped together. Future work: time-window analysis, GeoIP, IP blocklist export, ML anomaly detection.

## Diagram
Draw the data-flow above in draw.io / Excalidraw and save as `docs/architecture.png`.
