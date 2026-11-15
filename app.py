import os
from flask import Flask, render_template, request
from analyzer import analyze

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB upload limit
ALLOWED_EXT = (".log", ".txt")
SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "sample_logs")
SAMPLES = {"access": "access.log", "auth": "auth.log"}


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'"
    )
    return resp


@app.route("/", methods=["GET", "POST"])
def index():
    result, error, source = None, None, None
    if request.method == "POST":
        sample = request.form.get("sample")
        if sample in SAMPLES:  # built-in demo logs (allow-list, no user path used)
            with open(os.path.join(SAMPLE_DIR, SAMPLES[sample]), encoding="utf-8") as fh:
                result = analyze(fh.read())
            source = SAMPLES[sample]
        else:
            f = request.files.get("logfile")
            if not f or not f.filename:
                error = "Please choose a log file."
            elif not f.filename.lower().endswith(ALLOWED_EXT):
                error = "Only .log or .txt files are allowed."
            else:
                result = analyze(f.read().decode("utf-8", errors="ignore"))  # never saved to disk
                source = "uploaded file"
    return render_template("index.html", result=result, error=error, source=source)


@app.errorhandler(413)
def too_large(_):
    return render_template("index.html", result=None, error="File too large (max 2 MB).", source=None), 413


if __name__ == "__main__":
    app.run(debug=False)
