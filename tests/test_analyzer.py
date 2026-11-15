import os, sys
from io import BytesIO
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from analyzer import analyze
from app import app

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def line(ip="10.0.0.1", path="/", status="200", ua="Mozilla/5.0", m="GET"):
    return f'{ip} - - [15/Nov/2026:10:00:00 +0530] "{m} {path} HTTP/1.1" {status} 100 "-" "{ua}"'

def types(r): return {f["attack"] for f in r["findings"]}

def test_clean_traffic_has_no_findings():
    assert analyze("\n".join(line() for _ in range(20)))["findings"] == []

def test_sql_injection_union():
    assert "SQL Injection" in types(analyze(line(path="/p?id=1%20UNION%20SELECT%20a,b")))

def test_sql_injection_or_1_equals_1():
    assert "SQL Injection" in types(analyze(line(path="/p?id=1%20OR%201=1--")))

def test_xss_detected():
    assert "Cross-Site Scripting (XSS)" in types(analyze(line(path="/s?q=<script>alert(1)</script>")))

def test_path_traversal_detected():
    assert "Path Traversal" in types(analyze(line(path="/f?x=../../etc/passwd")))

def test_scanner_user_agent_detected():
    assert "Scanner / Attack Tool" in types(analyze(line(ua="sqlmap/1.7")))

def test_web_brute_force_threshold():
    four = "\n".join(line(path="/login", status="401", m="POST") for _ in range(4))
    five = "\n".join(line(path="/login", status="401", m="POST") for _ in range(5))
    assert "Web Login Brute Force" not in types(analyze(four))
    assert "Web Login Brute Force" in types(analyze(five))

def test_directory_scanning_threshold():
    log = "\n".join(line(path=f"/x{i}", status="404") for i in range(10))
    assert "Directory Scanning" in types(analyze(log))

def test_ssh_brute_force():
    log = "\n".join(f"Nov 15 11:00:0{i} srv sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2" for i in range(6))
    assert "SSH Brute Force" in types(analyze(log))

def test_garbage_input_does_not_crash():
    assert analyze("random text\n\n%%%%\n")["findings"] == []

def test_empty_input():
    assert analyze("")["total_lines"] == 0

def test_sample_access_log_detects_all_attack_types():
    t = types(analyze(open(os.path.join(ROOT, "sample_logs", "access.log")).read()))
    assert {"SQL Injection", "Cross-Site Scripting (XSS)", "Path Traversal",
            "Web Login Brute Force", "Directory Scanning", "Scanner / Attack Tool"} <= t

def test_sample_auth_log_detects_ssh_brute_force():
    assert "SSH Brute Force" in types(analyze(open(os.path.join(ROOT, "sample_logs", "auth.log")).read()))

def test_home_page_loads():
    assert app.test_client().get("/").status_code == 200

def test_rejects_wrong_file_type():
    r = app.test_client().post("/", data={"logfile": (BytesIO(b"x"), "evil.exe")},
                               content_type="multipart/form-data")
    assert b"Only .log or .txt" in r.data

def test_script_in_log_is_escaped_in_page():
    payload = line(path="/s?q=<script>alert(1)</script>").encode()
    r = app.test_client().post("/", data={"logfile": (BytesIO(payload), "a.log")},
                               content_type="multipart/form-data")
    assert b"q=<script>alert(1)</script>" not in r.data

def test_demo_sample_works():
    r = app.test_client().post("/", data={"sample": "access"})
    assert b"SQL Injection" in r.data

def test_security_headers_present():
    r = app.test_client().get("/")
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in r.headers
