# Testing Report – LogGuard

**Tester:** HARIKARAN M · **Date:** 15 Nov 2026 · **Tool:** pytest · **Result:** 18 / 18 passed

## 1. Functional tests
| # | Test | Input | Expected | Result |
|---|---|---|---|---|
| 1 | Clean traffic | 20 normal requests | 0 findings | Pass |
| 2 | SQLi UNION | `?id=1 UNION SELECT` | SQL Injection | Pass |
| 3 | SQLi OR 1=1 | `?id=1 OR 1=1--` | SQL Injection | Pass |
| 4 | XSS | `<script>alert(1)</script>` | XSS | Pass |
| 5 | Path traversal | `../../etc/passwd` | Path Traversal | Pass |
| 6 | Scanner UA | `sqlmap/1.7` | Scanner tool | Pass |
| 7 | Web brute force boundary | 4 fails → no alert; 5 → alert | Threshold works | Pass |
| 8 | Dir scanning | 10 × 404 | Directory Scanning | Pass |
| 9 | SSH brute force | 6 failed passwords | SSH Brute Force | Pass |
| 10 | Sample access log | provided file | All 6 web attack types | Pass |
| 11 | Sample auth log | provided file | SSH Brute Force | Pass |

## 2. Robustness tests
| # | Test | Expected | Result |
|---|---|---|---|
| 12 | Garbage text | No crash, 0 findings | Pass |
| 13 | Empty file | 0 lines | Pass |

## 3. Security tests (application)
| # | Test | Expected | Result |
|---|---|---|---|
| 14 | Upload `evil.exe` | Rejected with message | Pass |
| 15 | Log containing `<script>` | Escaped in HTML output | Pass |
| 16 | Security headers | CSP, X-Frame-Options present | Pass |
| 17 | Home page | HTTP 200 | Pass |
| 18 | Demo log button | Findings shown | Pass |

## 4. Manual tests (add your own screenshots)
- Upload a >2 MB file → "File too large"
- Test on the live Render URL
- Run in Chrome and mobile view

## 5. Known limitations
Signature-based detection can be bypassed with obfuscation; legitimate users who mistype passwords 5+ times can raise false positives.
