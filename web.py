#!/usr/bin/env python3
# web.py — Web UI check pass Kiro (Microsoft / IAM Identity Center).
# Flask + auth + 1 worker thread giu 1 browser Playwright; tai dung logic batch.py.
#
# Bao mat (web global): mat khau truy cap bat buoc (CHECKPASS_PASSWORD), rate-limit
# login, so sanh constant-time, CSRF token, cookie Secure/HttpOnly/SameSite, anti-
# clickjacking, gioi han body + so account + so job.
#
# Local:  $env:CHECKPASS_PASSWORD="..."; $env:COOKIES_SECURE="0"; python web.py
#         (COOKIES_SECURE=0 vi local la http; cloud HTTPS de mac dinh '1')
import os, time, hmac, threading, queue, uuid, secrets, collections
from functools import wraps
from flask import (Flask, request, session, redirect, url_for,
                   render_template, jsonify, abort)

import batch as B   # tai dung logic check pass

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

PASSWORD = os.environ.get("CHECKPASS_PASSWORD", "")   # KHONG strip (cho phep pass co space)
ALLOW_NOAUTH = os.environ.get("ALLOW_NOAUTH", "0") == "1"
PORT = int(os.environ.get("PORT", "5000"))

# Fail-closed: bat buoc co mat khau khi serve (tranh deploy global quen set -> mo toang).
# Chi bo qua khi ALLOW_NOAUTH=1 (local dev).
if not PASSWORD and not ALLOW_NOAUTH:
    raise SystemExit("CHECKPASS_PASSWORD la bat buuoc (hoac set ALLOW_NOAUTH=1 khi local).")
if PASSWORD and len(PASSWORD) < 8:
    print("CANH BAO: CHECKPASS_PASSWORD ngan (<8) — dung mat khau manh hon.")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIES_SECURE", "1") == "1",
    PERMANENT_SESSION_LIFETIME=3600 * 12,
    MAX_CONTENT_LENGTH=256 * 1024,          # 256KB / request
)
MAX_ACCOUNTS = 500
MAX_ACTIVE_JOBS = 3
LOGIN_MAX_FAIL = 8          # so lan sai / phut / IP
JOB_TTL = 600               # don job done cu (giay)


# ---- Anti-clickjacking + nosniff ----
@app.after_request
def _harden(resp):
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


# ---- Login rate-limit (IP, in-memory) ----
_attempts = collections.defaultdict(list)
_attempts_lock = threading.Lock()


def _client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "?"


def _login_locked(ip):
    now = time.time()
    with _attempts_lock:
        rec = [t for t in _attempts[ip] if now - t < 60]
        _attempts[ip] = rec
        return len(rec) >= LOGIN_MAX_FAIL


def _login_record(ip):
    with _attempts_lock:
        _attempts[ip].append(time.time())


# ---- Job queue + worker (1 browser; restart loop) ----
_jobs = {}
_lock = threading.Lock()
_q = queue.Queue()


def parse_accounts(text):
    rows = []
    for ln in (text or "").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        parts = ln.split("|", 1) if "|" in ln else ln.split(",", 1)
        user = parts[0].strip()
        if not user or user.lower() in ("email", "user", "username"):
            continue
        pw = parts[1].strip() if len(parts) > 1 else ""
        rows.append({"email": user, "password": pw})
    return rows


def _count_active():
    return sum(1 for j in _jobs.values() if j["status"] in ("queued", "running"))


def _sweep():
    now = time.time()
    for jid in [k for k, v in _jobs.items()
                if v["status"] == "done" and now - v.get("finished_at", now) > JOB_TTL]:
        _jobs.pop(jid, None)


def _worker():
    from playwright.sync_api import sync_playwright
    # Restart loop: browser launch loi transient -> khoi lai worker, khong chet hoan toan.
    while True:
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
                while True:
                    job_id = _q.get()
                    with _lock:
                        job = _jobs.get(job_id)
                        if job:
                            job["status"] = "running"
                    if not job:
                        continue
                    try:
                        for i, acct in enumerate(job["accounts"]):
                            if job.get("cancel"):
                                break
                            try:
                                is_iam = job["type"] == "iam"
                                mode = job.get("mode") or ("full" if job.get("full") else "checkpass")
                                if mode in ("full", "keys", "delete"):
                                    # Full/keys/delete tra ve DICT day du thay vi tuple
                                    # (status, detail) — co y, xu ly rieng. IAM lay start URL.
                                    if is_iam:
                                        acct = dict(acct, url=job["url"])
                                        if mode == "full":
                                            res = B.process_full_iam(acct, browser)
                                        elif mode == "keys":
                                            res = B.process_check_keys(acct, browser, True, job["url"])
                                        else:
                                            res = B.process_delete_keys(
                                                acct, browser, True, job["url"],
                                                job.get("keys_to_delete"), job.get("delete_all"))
                                    else:
                                        if mode == "full":
                                            res = B.process_full_microsoft(acct, browser)
                                        elif mode == "keys":
                                            res = B.process_check_keys(acct, browser, False)
                                        else:
                                            res = B.process_delete_keys(
                                                acct, browser, False, None,
                                                job.get("keys_to_delete"), job.get("delete_all"))
                                else:
                                    if not is_iam:
                                        status, detail = B._checkpass_microsoft(acct, browser)
                                    else:
                                        status, detail = B._checkpass_iam(
                                            browser, acct["email"], acct["password"], job["url"])
                                    verdict = {"OK": "Right", "WRONG": "Wrong"}.get(status, "Error")
                                    res = {"user": acct["email"], "password": acct["password"],
                                           "result": verdict, "detail": detail}
                            except Exception as exc:
                                res = {"user": acct["email"], "password": acct["password"],
                                       "result": "Error",
                                       "detail": (str(exc) or exc.__class__.__name__)}
                            with _lock:
                                job["results"].append(res)
                                job["done"] = i + 1
                    except Exception as exc:
                        with _lock:
                            job["results"].append({
                                "user": "(job)", "password": "", "result": "Error",
                                "detail": "worker: %s" % (str(exc) or type(exc).__name__),
                            })
                    finally:
                        with _lock:
                            job["status"] = "done"
                            job["done"] = job["total"]      # day du tren terminal path
                            job["finished_at"] = time.time()
        except Exception as exc:
            print("WORKER crash (khoi lai sau 5s):", exc, flush=True)
            time.sleep(5)


threading.Thread(target=_worker, daemon=True).start()


# ---- Auth ----
def login_required(f):
    @wraps(f)
    def wrap(*a, **kw):
        if not session.get("ok"):
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrap


def _csrf_ok():
    tok = request.headers.get("X-CSRF", "")
    return bool(tok) and hmac.compare_digest(tok, session.get("csrf", ""))


@app.route("/healthz")
def healthz():
    return "ok", 200


@app.route("/login", methods=["GET", "POST"])
def login():
    ip = _client_ip()
    if _login_locked(ip):
        time.sleep(1)
        return render_template("login.html", err="Qua nhieu lan sai. Thu lai sau 1 phut."), 429
    if not PASSWORD:                       # ALLOW_NOAUTH (local)
        session.clear()
        session["ok"] = True
        session["csrf"] = secrets.token_hex(16)
        return redirect(url_for("index"))
    err = ""
    if request.method == "POST":
        _login_record(ip)
        if hmac.compare_digest(request.form.get("password", "").encode(), PASSWORD.encode()):
            session.clear()                # chong session fixation
            session["ok"] = True
            session["csrf"] = secrets.token_hex(16)
            return redirect(url_for("index"))
        time.sleep(0.3)
        err = "Sai mat khau."
    return render_template("login.html", err=err)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    return render_template("index.html", csrf=session.get("csrf", ""))


@app.route("/run", methods=["POST"])
@login_required
def run():
    if not _csrf_ok():
        return jsonify({"error": "CSRF"}), 400
    data = request.get_json(silent=True) or {}
    atype = "iam" if data.get("type") == "iam" else "microsoft"
    # mode: "checkpass" | "full" (pass+credit+keys) | "keys" (chi cao key)
    #       | "delete" (xoa key chon loc theo ten / hoac xoa het).
    mode = data.get("mode") or ("full" if data.get("full") else "checkpass")
    if mode not in ("checkpass", "full", "keys", "delete"):
        mode = "checkpass"
    full = mode in ("full", "keys", "delete")   # hien cot mo rong o UI
    url = (data.get("url") or "").strip()
    needs_url = (atype == "iam") and (mode in ("checkpass", "full", "keys", "delete"))
    if needs_url and not url:
        return jsonify({"error": "IAM can start URL"}), 400
    # delete mode: danh sach ten key can xoa + co xoa het khong.
    keys_to_delete = [s.strip() for s in (data.get("keys") or "").splitlines() if s.strip()]
    delete_all = bool(data.get("delete_all"))
    if mode == "delete" and not delete_all and not keys_to_delete:
        return jsonify({"error": "Nhap ten key can xoa hoac bat 'Xoa tat ca key'"}), 400
    accounts = parse_accounts(data.get("accounts", ""))
    if not accounts:
        return jsonify({"error": "Khong co account (dang user,password hoac user|password)"}), 400
    if len(accounts) > MAX_ACCOUNTS:
        return jsonify({"error": "Qua nhieu account (max %d)" % MAX_ACCOUNTS}), 400
    with _lock:
        _sweep()
        if _count_active() >= MAX_ACTIVE_JOBS:
            return jsonify({"error": "Server dang ban (qua nhieu job). Thu lai sau."}), 429
        job_id = uuid.uuid4().hex
        _jobs[job_id] = {"type": atype, "url": url, "accounts": accounts,
                         "mode": mode, "full": full,
                         "keys_to_delete": keys_to_delete, "delete_all": delete_all,
                         "results": [], "done": 0, "total": len(accounts), "status": "queued"}
    _q.put(job_id)
    return jsonify({"job_id": job_id, "total": len(accounts), "full": full, "mode": mode})


@app.route("/status/<job_id>")
@login_required
def status(job_id):
    with _lock:
        job = _jobs.get(job_id)
        if not job:
            abort(404)
        return jsonify({"status": job["status"], "done": job["done"],
                        "total": job["total"], "results": list(job["results"])})


@app.route("/cancel/<job_id>", methods=["POST"])
@login_required
def cancel(job_id):
    if not _csrf_ok():
        return jsonify({"error": "CSRF"}), 400
    with _lock:
        job = _jobs.get(job_id)
        if job and job["status"] in ("queued", "running"):
            job["cancel"] = True       # worker dung sau acc hien tai
            return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "not found or finished"}), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, threaded=True)
