#!/usr/bin/env python3
# Batch: doc accounts.csv (email,password) -> tu dong login qua Playwright ->
# xuat CLIProxyAPI_<user>.json + report.csv. Tai dung logic tu kiro_helper.py
import csv, html, json, os, queue, secrets, sys, time, urllib.parse, traceback
from datetime import datetime, timezone
import kiro_helper as K
import kiro_usage as U
from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

CSV_PATH = r"h:\Tải\json\accounts.csv"
OUT_DIR  = os.environ.get("OUT_DIR") or r"h:\Tải\json\out"
HEADLESS = os.environ.get("HEADED", "") == ""   # set HEADED=1 de hien trinh duyet
ACCOUNT_TIMEOUT = 90  # giay cho moi account
FULL_ACCOUNT_TIMEOUT = 120  # full-check ton them buoc doi pass + credit + cao portal
RETRIES = 2  # so lan thu lai khi check pass bi flaky (kẹt org-page / timeout transient)
DEBUG = os.environ.get("DEBUG", "") != ""        # set DEBUG=1 de bat log chi tiet
REGION = os.environ.get("REGION", "").strip() or K.DEFAULT_REGION  # set REGION=eu-west-1 cho tenant EU


def dbg(*args):
    if DEBUG:
        print("   [debug]", *args, flush=True)


def preview(tok, head=12, tail=6):
    # rut gon token de log an toan (khong lo nguyen token)
    tok = tok or ""
    if len(tok) <= head + tail:
        return tok
    return "%s...%s (len=%d)" % (tok[:head], tok[-tail:], len(tok))


def generate_ms_password(length=16):
    # Sinh password ngau nhien dat Microsoft/Entra complexity: ep du ca 4 nhom
    # (upper/lower/digit/symbol). Bo ky tu de nham (l/1/I/O/0) va space/quote de
    # con nguoi doc lai tu report de dang. Tranh 3 ky tu lien tiep giong nhau
    # (mot so policy AD cham lich su/lap ky tu).
    upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    lower = "abcdefghijkmnpqrstuvwxyz"
    digit = "23456789"
    symbol = "!@#$%^&*-_+="
    pool = upper + lower + digit + symbol
    rng = secrets.SystemRandom()
    for _ in range(1000):  # tran an toan: gan nhu luon thoat ngay vong dau
        chars = [secrets.choice(upper), secrets.choice(lower),
                 secrets.choice(digit), secrets.choice(symbol)]
        chars += [secrets.choice(pool) for _ in range(max(0, length - 4))]
        rng.shuffle(chars)
        candidate = "".join(chars)
        if not any(candidate[i] == candidate[i + 1] == candidate[i + 2]
                   for i in range(len(candidate) - 2)):
            return candidate
    return candidate  # cuc hiem: tra ung vien cuoi neu khong dat dieu kien lap


# Cac mau host endpoint de thu (CodeWhisperer da doi ten thanh Amazon Q).
# codewhisperer.<region> chi ton tai o us-east-1; tenant EU dung q.<region>.
ENDPOINT_TEMPLATES = [
    "https://codewhisperer.%s.amazonaws.com/",
    "https://q.%s.amazonaws.com/",
]

# Cac region se thu lan luot khi auto-detect. REGION (env) duoc uu tien dau tien.
DEFAULT_REGION_CANDIDATES = ["us-east-1", "eu-central-1"]


def region_candidates():
    out = []
    if os.environ.get("REGION", "").strip():
        out.append(os.environ["REGION"].strip())
    for r in DEFAULT_REGION_CANDIDATES:
        if r not in out:
            out.append(r)
    return out


def _call_list_profiles(access_token, region, url, external_idp=True):
    machine_id = K.build_machine_id(access_token)
    headers = {
        "Content-Type": "application/x-amz-json-1.0",
        "Accept": "application/x-amz-json-1.0",
        "Authorization": "Bearer " + access_token,
        "X-Amz-Target": K.LIST_PROFILES_TARGET,
        "amz-sdk-invocation-id": K.build_machine_id(access_token, region, "list-profiles"),
        "amz-sdk-request": "attempt=1; max=1",
        "x-amzn-kiro-agent-mode": "vibe",
        "x-amzn-codewhisperer-optout": "true",
        "User-Agent": K.build_user_agent(machine_id),
        "x-amz-user-agent": K.build_x_amz_user_agent(machine_id),
    }
    # external_idp (Microsoft) can TokenType; awsidc/social gui bearer tran.
    if external_idp:
        headers["TokenType"] = "EXTERNAL_IDP"
    req = urllib.request.Request(url, data=b"{}", method="POST", headers=headers)
    return K._do_request(req, None, timeout=30)


def _list_profiles_over(access_token, regions, external_idp):
    """Do region + endpoint: thu lan luot regions x ENDPOINT_TEMPLATES.
    Tra (arn, region, used_url). Dung chung cho ca external_idp va awsidc."""
    import socket as _socket
    last_err = None
    denied = False
    for region in regions:
        for tmpl in ENDPOINT_TEMPLATES:
            url = tmpl % region
            host = urllib.parse.urlparse(url).hostname
            try:
                _socket.getaddrinfo(host, 443)
            except OSError:
                dbg("skip (DNS fail):", url)
                continue
            status, parsed, text = _call_list_profiles(access_token, region, url, external_idp)
            dbg("POST", url, "-> status", status)
            if 200 <= status < 300:
                for prof in (parsed or {}).get("profiles", []) or []:
                    arn = (prof.get("arn") or "").strip()
                    if arn:
                        arn_region = K.region_from_profile_arn(arn) or region
                        return arn, arn_region, url
                last_err = RuntimeError("no profiles available at %s" % url)
            else:
                if status == 403:
                    denied = True  # token den dung region nhung chua co quyen
                last_err = RuntimeError(
                    "list-profiles failed (status %d) at %s: %s" % (status, url, text))
    if denied and last_err is None:
        raise RuntimeError("access denied o moi region da thu")
    if last_err:
        raise last_err
    raise RuntimeError("khong co endpoint CodeWhisperer/Q nao truy cap duoc")


def list_profiles_multi(access_token):
    # Microsoft/external_idp: thu cac region ung vien, gui TokenType EXTERNAL_IDP.
    return _list_profiles_over(access_token, region_candidates(), external_idp=True)


def list_profiles_multi_idc(access_token, region):
    # awsidc: uu tien region cua directory (da suy tu start page), khong TokenType.
    regions = [region] + [r for r in region_candidates() if r != region]
    return _list_profiles_over(access_token, regions, external_idp=False)


def signin_url():
    verifier = K.random_url_safe(96)
    state = K.random_url_safe(32)
    url = K.SOCIAL_SIGNIN_BASE_URL + "?" + urllib.parse.urlencode({
        "state": state,
        "code_challenge": K.pkce_challenge(verifier),
        "code_challenge_method": "S256",
        "redirect_uri": K.SOCIAL_REDIRECT_URI,
        "redirect_from": K.SOCIAL_REDIRECT_FROM,
    })
    return url, state, verifier

def safe_click(page, selector, timeout=8000):
    page.click(selector, timeout=timeout)

def _submit_login(page, email, password):
    # Phan nhap chung cho ca 2 mode (json + checkpass): cookie banner -> organization
    # -> email -> Microsoft login (loginfmt/passwd) -> submit password.
    try: page.get_by_role("button", name="Accept").click(timeout=4000)
    except Exception: pass
    # organization
    page.get_by_role("button", name="Your organization Sign in").click(timeout=15000)
    page.fill("#idp-email-input", email, timeout=15000)
    # Dien email -> cho sang trang Microsoft (loginfmt/passwd). Click Continue co
    # luc KHONG chuyen trang (org-discovery cham / click khong submit), nen thu 3
    # lan: click Continue; neu sau 12s van chua sang thi dien lai email + bam Enter
    # de submit form truc tiep.
    for _try in range(3):
        try:
            page.get_by_role("button", name="Continue").click(timeout=8000)
        except Exception:
            pass
        try:
            page.wait_for_selector('input[name="loginfmt"], input[name="passwd"]', timeout=12000)
            break
        except PWTimeout:
            dbg("org->Microsoft chua sang, thu lai (%d/3) ..." % (_try + 1))
            try:
                el = page.locator("#idp-email-input").first
                el.fill(email, timeout=5000)
                el.press("Enter")
            except Exception:
                pass

    # --- Microsoft login --- cho trang email HOAC password
    page.wait_for_selector('input[name="loginfmt"], input[name="passwd"]', timeout=25000)

    # neu dang o trang nhap email (login_hint trong) -> dien & next
    el = page.query_selector('input[name="loginfmt"]')
    if el and el.is_visible():
        try:
            if not el.input_value():
                el.fill(email)
        except Exception:
            pass
        page.click('input[type="submit"]', timeout=8000)   # de click propagate -> fail fast

    # trang password
    page.wait_for_selector('input[name="passwd"]', timeout=20000)
    page.fill('input[name="passwd"]', password, timeout=10000)
    page.click('input[type="submit"]', timeout=8000)


def drive_login(page, email, password, flow):
    _submit_login(page, email, password)
    # xu ly hau dang nhap: loi sai pass / MFA / proof-up skip / KMSI / redirect xong
    deadline = time.time() + 60
    while time.time() < deadline:
        if not flow.result_queue.empty():
            return  # da bat duoc code -> thanh cong
        try:
            if page.url.lower().startswith("http://localhost:3128"):
                return
            # sai mat khau
            e = page.query_selector('#passwordError, #usernameError')
            if e:
                t = (e.inner_text() or "").strip()
                if t:
                    raise RuntimeError("Microsoft: " + t[:140])
            # man hinh nhap OTP/MFA that su -> khong qua duoc
            if page.query_selector('#idTxtBx_SAOTCC_OTC, #idDiv_SAOTCS_Title'):
                raise RuntimeError("Account yeu cau nhap ma OTP/MFA - khong tu dong duoc")
            # "Let's keep your account secure" -> bam Next
            n = page.query_selector('#idSubmit_ProofUp_Redirect')
            if n and n.is_visible():
                n.click(); page.wait_for_timeout(2500); continue
            # trang dang ky security info -> Skip setup
            sk = page.query_selector('button:has-text("Skip setup"), button:has-text("Skip for now")')
            if sk and sk.is_visible():
                sk.click(); page.wait_for_timeout(2500); continue
            # "Stay signed in?" (KMSI)
            if page.query_selector('#KmsiCheckboxField'):
                page.click('input[type="submit"]', timeout=4000); continue
        except RuntimeError:
            raise
        except Exception:
            # navigation dang dien ra -> bo qua, vong sau kiem tra lai queue
            pass
        page.wait_for_timeout(700)


def is_change_password_page(page):
    # Nhan dien trang Microsoft "Update your password" (account bi ep doi pass lan
    # dau / "must change at next logon"). Day la tin hieu password DUNG. Selectors
    # can verify bang HEADED=1 neu Microsoft doi DOM.
    # (1) Tin hieu manh nhat: input mat khau moi cua Microsoft.
    for sel in ('input[name="newPassword"]',
                'input[name="reenterPassword"]',
                'input[name="confirmNewPassword"]'):
        el = page.query_selector(sel)
        if el:
            try:
                vis = el.is_visible()
            except Exception:
                vis = True
            if vis:
                return True
    # (2) Tin hieu phu: heading trang doi pass.
    for hsel in ("h1", "#ChangePasswordDescription", '[aria-level="1"]'):
        try:
            txt = (page.inner_text(hsel, timeout=1000) or "").lower()
        except Exception:
            txt = ""
        if "update your password" in txt or "change your password" in txt:
            return True
    return False


def fill_change_password(page, new_password):
    # Dien man hinh Microsoft "Update your password" (account bi ep doi lan dau /
    # het han). CANH BAO: selector cho 2 o (new + confirm) la SUY DOAN tu ten
    # field Microsoft hay dung; tuy tenant/phien ban co the la 'newPassword'/
    # 'reenterPassword' hoac 'confirmNewPassword' hoac ban hoa dau. PHAI verify
    # bang HEADED=1 tren 1 account thuc bi ep doi pass truoc khi tin ket qua
    # hang loat. Khong dien duoc -> raise de caller bao ERROR ro rang (khong am
    # tham coi la thanh cong).
    new_sel = ('input[name="newPassword"]', 'input[name="NewPassword"]',
               '#newPassword', 'input[name="Password"][autocomplete="new-password"]')
    confirm_sel = ('input[name="reenterPassword"]', 'input[name="confirmNewPassword"]',
                   'input[name="ConfirmNewPassword"]', '#confirmNewPassword')
    if not _fill_first(page, new_password, *new_sel):
        raise RuntimeError("khong tim thay o 'new password' (selector can verify HEADED=1)")
    if not _fill_first(page, new_password, *confirm_sel):
        raise RuntimeError("khong tim thay o 'confirm password' (selector can verify HEADED=1)")
    # Nut submit trang doi pass MS thuong la #idSIButton9 hoac input[type=submit].
    for sel in ('#idSIButton9', 'input[type="submit"]', 'button[type="submit"]'):
        try:
            page.click(sel, timeout=6000)
            return
        except Exception:
            pass
    raise RuntimeError("khong bam duoc nut submit trang doi pass")


def drive_login_full(page, email, password, flow, new_password):
    # Nhu drive_login (login day du, cho toi khi listener bat OAuth code), nhung
    # khi gap trang doi pass bat buoc thi TU DIEN new_password roi tiep tuc. Tra
    # ve True neu da phai doi pass (bao cho caller biet new_password la pass THAT
    # dang dung), False neu khong can doi. Raise khi sai pass / MFA / timeout.
    _submit_login(page, email, password)
    changed = False
    deadline = time.time() + 90  # doi pass ton them buoc so drive_login thuong
    while time.time() < deadline:
        if not flow.result_queue.empty():
            return changed
        try:
            if page.url.lower().startswith("http://localhost:3128"):
                return changed
            # sai mat khau
            e = page.query_selector('#passwordError, #usernameError')
            if e:
                t = (e.inner_text() or "").strip()
                if t:
                    raise RuntimeError("Microsoft: " + t[:140])
            # trang doi pass bat buoc -> dien pass moi (chi lan dau, guard changed)
            if is_change_password_page(page):
                if not changed:
                    fill_change_password(page, new_password)
                    changed = True
                    page.wait_for_timeout(2500)
                continue
            # man hinh nhap OTP/MFA that su -> khong qua duoc
            if page.query_selector('#idTxtBx_SAOTCC_OTC, #idDiv_SAOTCS_Title'):
                raise RuntimeError("Account yeu cau nhap ma OTP/MFA - khong tu dong duoc")
            # "Let's keep your account secure" -> bam Next
            n = page.query_selector('#idSubmit_ProofUp_Redirect')
            if n and n.is_visible():
                n.click(); page.wait_for_timeout(2500); continue
            # trang dang ky security info -> Skip setup
            sk = page.query_selector('button:has-text("Skip setup"), button:has-text("Skip for now")')
            if sk and sk.is_visible():
                sk.click(); page.wait_for_timeout(2500); continue
            # "Stay signed in?" (KMSI)
            if page.query_selector('#KmsiCheckboxField'):
                page.click('input[type="submit"]', timeout=4000); continue
        except RuntimeError:
            raise
        except Exception:
            # navigation dang dien ra -> bo qua, vong sau kiem tra lai
            pass
        page.wait_for_timeout(700)
    raise RuntimeError("timeout, khong dang nhap xong duoc (co the ket sau doi pass)")


def drive_login_checkpass(page, email, password, flow):
    # Cung _submit_login nhu mode json, nhung thay vi doi OAuth code thi chi nhan
    # dien password DUNG hay SAI roi dung lai: KHONG exchange token, KHONG xuat
    # JSON, KHONG dien pass moi.
    _submit_login(page, email, password)
    deadline = time.time() + 60
    while time.time() < deadline:
        # login thanh cong hẳn (redirect ve loopback / listener da bat code) -> DUNG
        try:
            cur = (page.url or "").lower()
        except Exception:
            cur = ""
        if cur.startswith("http://localhost:3128") or not flow.result_queue.empty():
            return "DUNG"
        try:
            # sai mat khau
            e = page.query_selector('#passwordError, #usernameError')
            if e:
                try:
                    vis = e.is_visible()
                except Exception:
                    vis = True
                if vis:
                    t = (e.inner_text() or "").strip()
                    raise RuntimeError("SAI PASS" + ((": " + t[:120]) if t else ""))
            # trang doi pass xuat hien -> DUNG (dung lai, KHONG dien pass moi)
            if is_change_password_page(page):
                return "DUNG"
            # man hinh OTP/MFA that su -> khong xac dinh duoc
            if page.query_selector('#idTxtBx_SAOTCC_OTC, #idDiv_SAOTCS_Title'):
                raise RuntimeError("Account yeu cau MFA/OTP - khong xac dinh duoc pass")
            # "Let's keep your account secure" -> bam Next
            n = page.query_selector('#idSubmit_ProofUp_Redirect')
            if n and n.is_visible():
                n.click(); page.wait_for_timeout(2500); continue
            # trang dang ky security info -> Skip setup
            sk = page.query_selector('button:has-text("Skip setup"), button:has-text("Skip for now")')
            if sk and sk.is_visible():
                sk.click(); page.wait_for_timeout(2500); continue
            # "Stay signed in?" (KMSI)
            if page.query_selector('#KmsiCheckboxField'):
                page.click('input[type="submit"]', timeout=4000); continue
        except RuntimeError:
            raise
        except Exception:
            # navigation dang dien ra -> bo qua, vong sau kiem tra lai
            pass
        page.wait_for_timeout(700)
    raise RuntimeError("timeout, khong xac dinh duoc ket qua pass")

def process(account, browser):
    email = account["email"].strip()
    password = account.get("password", "")
    url, state, _verifier = signin_url()
    servers, flow = K.start_listener(state, None)
    ctx = browser.new_context()
    page = ctx.new_page()
    try:
        page.goto(url, wait_until="domcontentloaded", timeout=60000)
        drive_login(page, email, password, flow)
        # cho listener nhan code
        result = flow.result_queue.get(timeout=ACCOUNT_TIMEOUT)
        if isinstance(result, Exception):
            raise result
        if result.get("kind") != "external_idp":
            raise RuntimeError("luong khong phai external_idp: " + str(result.get("kind")))
        # doi code -> token
        access, refresh, expires_in, _ = K.exchange_external_idp_code(
            result["token_endpoint"], result["client_id"], result["code"],
            result["verifier"], result["redirect_uri"], result["scopes"], None)
        dbg("token_endpoint =", result["token_endpoint"])
        dbg("issuer_url     =", result["issuer_url"])
        dbg("client_id      =", result["client_id"])
        dbg("scopes         =", result["scopes"])
        dbg("access_token   =", preview(access))
        dbg("refresh_token  =", preview(refresh), "| expires_in =", expires_in)
        claims = K.decode_jwt_claims(access)
        if DEBUG:
            keys = ("preferred_username", "email", "upn", "unique_name",
                    "name", "oid", "sub", "tid", "iss", "aud", "appid", "scp", "roles")
            for k in keys:
                if k in claims:
                    dbg("jwt.%s =" % k, claims.get(k))
            dbg("jwt all keys =", sorted(claims.keys()))
        region = REGION
        dbg("auto-detect endpoint/region, thu:", ", ".join(region_candidates()))
        try:
            arn, region, used_url = list_profiles_multi(access)
        except Exception as exc:
            dbg("list_available_profiles FAILED:", str(exc))
            raise
        dbg("profile_arn    =", arn, "| region:", region, "| endpoint:", used_url)
        token = {
            "auth_method": "external_idp", "access_token": access,
            "refresh_token": refresh, "expires_in": expires_in, "profile_arn": arn,
            "client_id": result["client_id"], "token_endpoint": result["token_endpoint"],
            "issuer_url": result["issuer_url"], "scopes": result["scopes"],
        }
        obj = K.build_auth_json(token, region)
        uname = K.derive_username(access) or email
        safe = K.sanitize_file_component(uname) or ("kiro-%d" % int(time.time()*1000))
        out = os.path.join(OUT_DIR, "CLIProxyAPI_%s.json" % safe)
        dbg("username       =", uname, "-> file:", os.path.basename(out))
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=2, sort_keys=True); fh.write("\n")
        return ("OK", arn)
    finally:
        try: ctx.close()
        except Exception: pass
        for s in servers:
            try: s.shutdown()
            except Exception: pass
            try: s.server_close()   # giai phong cong 3128 cho account sau
            except Exception: pass
        time.sleep(1.0)             # cho OS nha cong truoc khi account ke tiep bind

def _dump_portal(page, tag):
    # Luu HTML + screenshot trang portal de do DOM API keys (chay voi DEBUG=1).
    if not DEBUG:
        return
    try:
        with open(os.path.join(OUT_DIR, "_portal_%s.html" % tag), "w", encoding="utf-8") as fh:
            fh.write(page.content())
        page.screenshot(path=os.path.join(OUT_DIR, "_portal_%s.png" % tag), full_page=True)
        dbg("portal dump [%s] url=%s" % (tag, (page.url or "")[:110]))
    except Exception as exc:
        dbg("portal dump fail [%s]: %s" % (tag, exc))


def _extract_api_keys(page):
    # Tra None neu trang KHONG phai trang API keys (de caller thu URL khac); tra []
    # neu dung trang nhung khong co key; tra list[{name, created}] neu tim duoc.
    # SELECTOR SUY DOAN — DOM portal chua verify, phai chinh bang HEADED=1 + xem
    # _portal_*.html dump (xem _dump_portal). Fail-soft o cap tren.
    try:
        body_txt = page.inner_text("body", timeout=3000) or ""
    except Exception:
        body_txt = ""
    low = body_txt.lower()
    if "ksk_" not in body_txt and "api key" not in low and "api keys" not in low:
        return None  # khong nhan ra trang key -> thu URL khac
    rows = []
    # Uu tien row chua masked key ksk_ (chac chan hon 'tbody tr'); danh sach key
    # cua Kiro la <table> moi row <tr> gom: ten | <code>ksk_xxx...</code> | ngay | actions.
    row_selectors = ('tr:has-text("ksk_")', 'tr:has(code)',
                     '[data-testid*="api-key-row"]', '[data-testid*="apikey"]',
                     'tr[class*="key"]', 'li[class*="key"]',
                     '[class*="ApiKeyRow"]', '[class*="api-key-item"]', 'tbody tr')
    for rsel in row_selectors:
        try:
            els = page.query_selector_all(rsel)
        except Exception:
            els = []
        if not els:
            continue
        for el in els:
            try:
                txt = el.inner_text() or ""
            except Exception:
                continue
            lines = [ln.strip() for ln in txt.splitlines() if ln.strip()]
            if not lines:
                continue
            # ten = dong dau tien KHONG phai masked key (ksk_) va KHONG phai ngay.
            name = ""
            for ln in lines:
                low = ln.lower()
                if ln.startswith("ksk_"):
                    continue
                if low.startswith(("jan", "feb", "mar", "apr", "may", "jun", "jul",
                                   "aug", "sep", "oct", "nov", "dec")):
                    continue
                name = ln
                break
            if not name:
                name = lines[0]
            created = ""
            for ln in lines:
                low_ln = ln.lower()
                if "creat" in low_ln or "20" in ln:  # "Created", "Created on", ngay co "20xx"
                    created = ln
                    break
            rows.append({"name": name, "created": created})
        if rows:
            return rows
    return []


def portal_web_login(page, kind, email=None, password=None, start_url=None):
    # Dang nhap app.kiro.dev tren WEB (khong qua loopback) de co session cookie
    # portal -> moi doc duoc trang /account/api-keys. Sau login dau tien, context
    # da co session AWS SSO / Microsoft nen buoc nay thuong tu dong qua (SSO im
    # lang). BEST-EFFORT: nuot loi, tra True/False (co ve da vao portal hay chua).
    try:
        page.goto("https://app.kiro.dev/signin?redirect_to_after_auth=%2Faccount",
                  wait_until="domcontentloaded", timeout=20000)
    except Exception as exc:
        dbg("portal_web_login goto signin loi:", exc); return False
    try: page.get_by_role("button", name="Accept").click(timeout=3000)
    except Exception: pass
    deadline = time.time() + 45
    while time.time() < deadline:
        cur = (page.url or "").lower()
        # da vao duoc portal (khong con o /signin)
        if "app.kiro.dev" in cur and "/signin" not in cur:
            return True
        try:
            if kind == "awsidc":
                # lai lai luong org -> IAM Identity Center -> start URL -> (SSO tu qua)
                for sel in ('button:has-text("Your organization")', 'text=Your organization'):
                    try: page.locator(sel).first.click(timeout=3000); break
                    except Exception: pass
                for sel in ('button:has-text("IAM Identity Center")', 'text=IAM Identity Center'):
                    try: page.locator(sel).first.click(timeout=3000); break
                    except Exception: pass
                if start_url and _fill_first(page, start_url, '#enterprise-sign-in-url',
                                             'input[name="url"]', 'input[placeholder*="awsapps"]'):
                    _iam_click_submit(page, ('button:has-text("Continue")',
                                             'button:has-text("Next")', 'button[type="submit"]'))
            else:
                # Microsoft: bam "Your organization Sign in" -> SSO tu qua neu con session
                for sel in ('button:has-text("Your organization")',
                            'button:has-text("Your organization Sign in")'):
                    try: page.locator(sel).first.click(timeout=3000); break
                    except Exception: pass
        except Exception:
            pass
        page.wait_for_timeout(1000)
    dbg("portal_web_login: khong vao duoc portal sau 45s (van o %s)" % (page.url or "")[:80])
    return False


def scrape_portal_api_keys(page, timeout_ms=15000, kind=None, email=None,
                           password=None, start_url=None):
    # Dieu huong context toi trang Account/API Keys cua app.kiro.dev, doc list API
    # key (name + created). Truoc tien login portal tren web (session cookie), vi
    # code OAuth di ve loopback nen context CHUA co session portal. BEST-EFFORT:
    # nuot loi, tra [] de KHONG lam FAIL account.
    if kind is not None:
        portal_web_login(page, kind, email, password, start_url)
    candidate_urls = (
        "https://app.kiro.dev/settings/api-keys",
        "https://app.kiro.dev/account/api-keys",
        "https://app.kiro.dev/account",
        "https://app.kiro.dev/settings",
    )
    for url in candidate_urls:
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        except Exception as exc:
            dbg("scrape_portal: goto %s loi: %s" % (url, exc))
            continue
        # Cookie banner chan React render -> Accept truoc.
        for sel in ('button:has-text("Accept")', '[data-testid="ccba-footer"] button',
                    'button:has-text("Accept all")'):
            try: page.click(sel, timeout=2000); break
            except Exception: pass
        # SPA Kiro load cham: cho NOI DUNG THAT render (ksk_ / nut Create key / empty
        # state), khong tinh <title>. Toi da ~30s; bam Retry neu "failed to load".
        ready = False
        for _ in range(30):
            try:
                body = page.inner_text("body", timeout=2000) or ""
            except Exception:
                body = ""
            low = body.lower()
            # dau hieu trang key da render that su:
            if ("ksk_" in body or "create key" in low or "create api key" in low
                    or "generate" in low and "key" in low
                    or "no api keys" in low or "last used" in low):
                ready = True
                break
            if "failed to load" in low:
                try: page.click('button:has-text("Retry")', timeout=1500)
                except Exception: pass
            page.wait_for_timeout(1000)
        _dump_portal(page, urllib.parse.urlparse(url).path.strip("/").replace("/", "_") or "root")
        if not ready:
            continue
        keys = _extract_api_keys(page)
        if keys is not None:
            return keys
    dbg("scrape_portal: khong tim duoc trang API keys nao")
    return []


def process_full_microsoft(account, browser):
    # Pipeline full cho 1 account Microsoft:
    #   1) login day du (drive_login_full — tu dien pass moi neu bi ep doi)
    #   2) sai/error -> tra ngay (giong checkpass)
    #   3) dung -> exchange code -> token -> list_profiles_multi
    #   4) U.get_usage_limits (power credit)
    #   5) scrape_portal_api_keys tren cung context
    # Tra ve DICT day du (khac tuple cua process/_checkpass_* — co y, vi nhieu field
    # hon; web.py xu ly rieng path nay).
    email = account["email"].strip()
    password = account.get("password", "")
    url, state, _verifier = signin_url()
    servers, flow = K.start_listener(state, None)
    ctx = browser.new_context()
    page = ctx.new_page()
    result = {
        "user": email, "password": password, "result": "Error", "detail": "",
        "new_password": "", "credit_used": None, "credit_total": None,
        "credit_remaining": None, "credit_reset": "", "api_keys": [],
    }
    try:
        new_password = generate_ms_password()
        page.goto(url, wait_until="domcontentloaded", timeout=60000)
        try:
            changed = drive_login_full(page, email, password, flow, new_password)
        except RuntimeError as exc:
            msg = str(exc)
            if msg.startswith("SAI PASS") or "passwordError" in msg or msg.startswith("Microsoft:"):
                result["result"] = "Wrong"; result["detail"] = msg
            else:
                result["result"] = "Error"; result["detail"] = msg
            return result
        cb = flow.result_queue.get(timeout=FULL_ACCOUNT_TIMEOUT)
        if isinstance(cb, Exception):
            raise cb
        if cb.get("kind") != "external_idp":
            raise RuntimeError("luong khong phai external_idp: %s" % cb.get("kind"))
        access, refresh, expires_in, _ = K.exchange_external_idp_code(
            cb["token_endpoint"], cb["client_id"], cb["code"],
            cb["verifier"], cb["redirect_uri"], cb["scopes"], None)
        arn, region, used_url = list_profiles_multi(access)
        result["result"] = "Right"
        result["detail"] = "pass DUNG" + (" (da doi pass moi)" if changed else "")
        if changed:
            result["new_password"] = new_password
        # (4) power credit
        usage, usage_host, usage_err = U.get_usage_limits(access, arn, region, external_idp=True)
        if usage:
            result["credit_used"] = usage["used"]
            result["credit_total"] = usage["total"]
            result["credit_remaining"] = usage["remaining"]
            if usage.get("reset_epoch"):
                try:
                    result["credit_reset"] = datetime.fromtimestamp(
                        int(usage["reset_epoch"]), tz=timezone.utc).strftime("%Y-%m-%d")
                except Exception:
                    result["credit_reset"] = str(usage["reset_epoch"])
            dbg("credit:", result["credit_used"], "/", result["credit_total"],
                "| host:", usage_host)
        else:
            dbg("GetUsageLimits khong lay duoc:", usage_err)
            result["detail"] += " | credit: %s" % (usage_err or "khong lay duoc")[:120]
        # (5) cao portal API keys (best-effort). Pass m:i (neu doi) de login portal.
        try:
            eff_pw = result["new_password"] or password
            result["api_keys"] = scrape_portal_api_keys(
                page, kind="external_idp", email=email, password=eff_pw)
        except Exception as exc:  # noqa: BLE001 - khong lam FAIL account
            dbg("scrape_portal_api_keys loi:", exc)
        return result
    except Exception as exc:  # noqa: BLE001 - bao ERROR ro rang
        result["result"] = "Error"
        result["detail"] = (result["detail"] + " | " if result["detail"] else "") + \
            (str(exc) or exc.__class__.__name__)
        return result
    finally:
        try: ctx.close()
        except Exception: pass
        for s in servers:
            try: s.shutdown()
            except Exception: pass
            try: s.server_close()   # giai phong cong 3128 cho account sau
            except Exception: pass
        time.sleep(1.0)             # cho OS nha cong truoc khi account ke tiep bind


def _checkpass_microsoft(account, browser):
    # Mode check pass (Microsoft): cung login flow, chi tra ve DUNG/SAI/ERROR. KHONG
    # exchange token, KHONG list_profiles, KHONG ghi JSON. Listener van chay de bat
    # truong hop login thanh cong hẳn (account khong bi ep doi pass).
    email = account["email"].strip()
    password = account.get("password", "")
    url, state, _verifier = signin_url()
    servers, flow = K.start_listener(state, None)
    ctx = browser.new_context()
    page = ctx.new_page()
    try:
        # Retry buoc login khi flaky (org-page transition / timeout transient): pass
        # SAI thi tra ve ngay; con khong xac dinh duoc thi tai lai trang va thu lai
        # toi RETRIES+1 lan; het lan moi bao ERROR (kem screenshot).
        last_detail = ""
        for attempt in range(1, RETRIES + 2):
            try:
                if attempt > 1:
                    dbg("checkpass thu lai lan %d/%d ..." % (attempt, RETRIES + 1))
                page.goto(url, wait_until="domcontentloaded", timeout=60000)
                outcome = drive_login_checkpass(page, email, password, flow)
                return ("OK", "pass DUNG (%s)" % outcome)
            except RuntimeError as exc:
                msg = str(exc)
                if msg.startswith("SAI PASS"):
                    return ("WRONG", msg)   # pass sai ro rang -> khong retry
                last_detail = msg
            except Exception as exc:
                last_detail = str(exc) or exc.__class__.__name__
            # chua xac dinh duoc -> chup anh debug o lan cuoi, roi retry (neu con lan)
            if attempt > RETRIES:
                shot = ""
                try:
                    shot = os.path.join(OUT_DIR, "_err_%s.png" % int(time.time()*1000))
                    page.screenshot(path=shot, full_page=True)
                except Exception:
                    shot = ""
                try:
                    cur_url = page.url
                except Exception:
                    cur_url = ""
                detail = "khong xac dinh duoc sau %d lan: %s" % (attempt, last_detail)
                if cur_url:
                    detail += "  [url=%s]" % cur_url[:120]
                if shot:
                    detail += "  [screenshot=%s]" % os.path.basename(shot)
                dbg("checkpass ERROR:", detail)
                return ("ERROR", detail)
    finally:
        try: ctx.close()
        except Exception: pass
        for s in servers:
            try: s.shutdown()
            except Exception: pass
            try: s.server_close()   # giai phong cong 3128 cho account sau
            except Exception: pass
        time.sleep(1.0)             # cho OS nha cong truoc khi account ke tiep bind

def process_checkpass(account, browser):
    # Dispatcher check pass theo kieu account:
    #   - email co "@"  -> Microsoft SSO (Kiro -> Microsoft, flow cu)
    #   - email KHONG co "@" -> IAM Identity Center (can start URL)
    email = account["email"].strip()
    password = account.get("password", "")
    if "@" in email:
        return _checkpass_microsoft(account, browser)
    # IAM: start URL lay tu cot "url" cua CSV, hoac bien IAM_URL.
    start_url = (account.get("url") or "").strip() or os.environ.get("IAM_URL", "").strip()
    if not start_url:
        return ("ERROR", "IAM account thieu start URL (them cot url hoac set IAM_URL)")
    return _checkpass_iam(browser, email, password, start_url)


def _iam_dump(page, tag):
    # Luu HTML + screenshot cua trang de debug DOM AWS (chay voi DEBUG=1).
    if not DEBUG:
        return
    try:
        with open(os.path.join(OUT_DIR, "_iam_dump_%s.html" % tag), "w", encoding="utf-8") as fh:
            fh.write(page.content())
        page.screenshot(path=os.path.join(OUT_DIR, "_iam_dump_%s.png" % tag), full_page=True)
        dbg("IAM dump [%s] url=%s" % (tag, (page.url or "")[:110]))
    except Exception as exc:
        dbg("IAM dump fail [%s]: %s" % (tag, exc))


def _fill_first(page, value, *selectors):
    for sel in selectors:
        el = page.query_selector(sel)
        if el:
            try:
                el.fill(value)
                return True
            except Exception:
                pass
    return False


def _iam_click_submit(page, selectors):
    for sel in selectors:
        try:
            page.click(sel, timeout=4000)
            return True
        except Exception:
            pass
    try: page.keyboard.press("Enter")
    except Exception: pass
    return False


def _iam_page_text(page):
    # Doc noi dung trang (body) de match ca keyword SAI (alert loi) lan DUNG (chu
    # "New password" cua trang doi pass). Timeout cao + loop retry o ngoai chiu
    # re-render. Tra "" neu khong doc duoc.
    try:
        return page.inner_text("body", timeout=3000) or ""
    except Exception:
        return ""


def drive_login_iam(page, username, password, start_url):
    # IAM Identity Center check pass: mo start URL TRUC TIEP -> trang login AWS
    # (signin.aws, 2 buoc: username -> password) -> detect DUNG / SAI. KHONG qua Kiro.
    page.goto(start_url, wait_until="domcontentloaded", timeout=60000)
    try: page.wait_for_load_state("networkidle", timeout=15000)   # cho SPA render
    except Exception: pass
    _iam_dump(page, "login")
    # --- BUOC 1: trang username --- (input that la .awsui-input / #awsui-input-0;
    # #username-input chi la container, fill se loi)
    page.wait_for_selector('input.awsui-input, #awsui-input-0, [data-testid="test-input"]',
                           timeout=30000)
    if not _fill_first(page, username,
            'input.awsui-input', '#awsui-input-0', '[data-testid="test-input"]',
            'input[type="text"]'):
        raise RuntimeError("IAM: khong thay o username")
    _iam_click_submit(page, ('#username-submit-button', '[data-testid="test-primary-button"]',
                             'button[type="submit"]', 'button:has-text("Next")',
                             'button:has-text("Continue")'))
    # --- BUOC 2: trang password ---
    try:
        page.wait_for_selector('input[type="password"], input.awsui-input[type="password"]',
                               timeout=20000)
    except PWTimeout:
        # khong sang duoc trang password -> thuong la username sai
        _iam_dump(page, "nouser")
        raise RuntimeError("SAI PASS: khong sang trang password (sai username?)")
    _iam_dump(page, "pwdpage")
    if not _fill_first(page, password,
            'input[type="password"]', 'input.awsui-input'):
        raise RuntimeError("IAM: khong thay o password")
    _iam_click_submit(page, ('#password-submit-button', '[data-testid="test-primary-button"]',
                             'button[type="submit"]', 'button:has-text("Sign in")',
                             'button:has-text("Next")'))
    # --- detect DUNG / SAI ---
    # SAI: AWS bao loi chung thuc ("We couldn't verify..."/"Something doesn't compute").
    # DUNG (pass duoc chap nhan) khi bat ky: (1) url roi route /login, (2) password
    # input bien mat (portal/MFA), (3) den trang "Set/New password" (account bi ep
    # doi pass sau khi login dung). KHONG dung pwd_gone don le vi trang doi pass
    # cung co input password.
    SAI_KW = ("couldn't verify your sign-in credentials", "couldn't verify",
              "doesn't compute", "does not compute",
              "incorrect username or password", "incorrect username",
              "your username or password")
    DUNG_KW = ("set new password", "new password", "create a new password")
    deadline = time.time() + 45
    while time.time() < deadline:
        txt_low = _iam_page_text(page).lower()
        for kw in SAI_KW:
            if kw in txt_low:
                _iam_dump(page, "error")
                raise RuntimeError("SAI PASS: " + kw)
        try:
            cur = (page.url or "").lower()
        except Exception:
            cur = ""
        try:
            pwd_gone = page.query_selector('#password-input, input[type="password"]') is None
        except Exception:
            pwd_gone = False
        left_login = "/login" not in cur
        if pwd_gone or left_login or any(kw in txt_low for kw in DUNG_KW):
            _iam_dump(page, "after")
            return "DUNG"
        page.wait_for_timeout(700)
    _iam_dump(page, "timeout")
    raise RuntimeError("timeout, khong xac dinh duoc IAM (login hay chua qua?)")


def _iam_attempt(page, username, password, start_url, label):
    # 1 lan thu login IAM voi 1 password (co retry transient). Tra OK/WRONG/ERROR.
    last = ""
    for attempt in range(1, RETRIES + 2):
        try:
            if attempt > 1:
                dbg("IAM thu lai lan %d/%d ..." % (attempt, RETRIES + 1))
            drive_login_iam(page, username, password, start_url)
            return ("OK", "pass DUNG (IAM, %s)" % label)
        except RuntimeError as exc:
            msg = str(exc)
            if msg.startswith("SAI PASS"):
                return ("WRONG", "SAI PASS (IAM, %s): %s" % (label, msg))
            last = msg
        except Exception as exc:
            last = str(exc) or exc.__class__.__name__
        if attempt > RETRIES:
            shot = ""
            try:
                shot = os.path.join(OUT_DIR, "_err_iam_%s.png" % int(time.time()*1000))
                page.screenshot(path=shot, full_page=True)
            except Exception:
                shot = ""
            detail = "IAM loi sau %d lan (%s): %s" % (attempt, label, last)
            if shot:
                detail += "  [screenshot=%s]" % os.path.basename(shot)
            return ("ERROR", detail)
    return ("ERROR", "IAM loi khong xac dinh (%s): %s" % (label, last))


def _checkpass_iam(browser, username, password, start_url):
    # Thu ca 2 bien ban password: raw (nhu trong CSV) + decoded (html.unescape,
    # de xu ly &gt;/&lt;). Cai nao login duoc = DUNG, bao luon bien ban do.
    variants = []
    for v in (password, html.unescape(password)):
        if v not in variants:
            variants.append(v)
    ctx = browser.new_context()
    page = ctx.new_page()
    try:
        for idx, pw in enumerate(variants):
            label = "raw" if idx == 0 and len(variants) > 1 else ("decoded" if idx > 0 else "raw")
            status, detail = _iam_attempt(page, username, pw, start_url, label)
            if status == "OK":
                return ("OK", detail)
            if status == "ERROR":
                return ("ERROR", detail)   # transient -> bao luon, khong thu variant khac
            # status == WRONG -> thu variant ke; neu het variant -> WRONG
            if idx == len(variants) - 1:
                return ("WRONG", detail)
            dbg("IAM SAI voi pass %s -> thu bien ban con lai" % label)
        return ("WRONG", "SAI PASS (IAM): ca %d bien ban pass deu sai" % len(variants))
    finally:
        try: ctx.close()
        except Exception: pass
        time.sleep(1.0)


def _fill_aws_login(page, username, password):
    # Login AWS signin.aws (2 buoc: username -> password). Input that = .awsui-input.
    # Tai dung selector da kiem chung o drive_login_iam.
    page.wait_for_selector('input.awsui-input, #awsui-input-0, [data-testid="test-input"]',
                           timeout=30000)
    if not _fill_first(page, username, 'input.awsui-input', '#awsui-input-0',
                       '[data-testid="test-input"]', 'input[type="text"]'):
        raise RuntimeError("IAM: khong thay o username")
    _iam_click_submit(page, ('#username-submit-button', '[data-testid="test-primary-button"]',
                             'button[type="submit"]', 'button:has-text("Next")',
                             'button:has-text("Continue")'))
    try:
        page.wait_for_selector('input[type="password"], input.awsui-input[type="password"]',
                               timeout=20000)
    except PWTimeout:
        raise RuntimeError("SAI PASS: khong sang trang password (sai username?)")
    if not _fill_first(page, password, 'input[type="password"]', 'input.awsui-input'):
        raise RuntimeError("IAM: khong thay o password")
    _iam_click_submit(page, ('#password-submit-button', '[data-testid="test-primary-button"]',
                             'button[type="submit"]', 'button:has-text("Sign in")',
                             'button:has-text("Next")'))


def is_iam_set_password_page(page):
    # Trang AWS "Set new password" (account IAM bi ep doi pass lan dau / het han).
    txt = _iam_page_text(page).lower()
    if "set new password" in txt or "confirm new password" in txt:
        return True
    # phu: 2 o password xuat hien cung luc (new + confirm)
    try:
        return len(page.query_selector_all('input[type="password"]')) >= 2
    except Exception:
        return False


def fill_iam_set_password(page, new_password):
    # Dien 2 o password cua trang AWS "Set new password" roi submit. AWS dung awsui
    # inputs (type=password): o[0]=new, o[1]=confirm. Cho 2 o render truoc khi dien.
    pw_inputs = []
    for _ in range(20):  # ~10s cho ca 2 o xuat hien
        pw_inputs = page.query_selector_all('input[type="password"]')
        if len(pw_inputs) >= 2:
            break
        page.wait_for_timeout(500)
    if len(pw_inputs) < 2:
        raise RuntimeError("khong thay du 2 o password tren trang Set new password")
    try:
        pw_inputs[0].fill(new_password)
        pw_inputs[1].fill(new_password)
    except Exception as exc:
        raise RuntimeError("khong dien duoc pass moi IAM: %s" % exc)
    _iam_click_submit(page, ('button:has-text("Set new password")', '#password-submit-button',
                             '[data-testid="test-primary-button"]', 'button[type="submit"]',
                             'button:has-text("Confirm")'))


def drive_login_iam_full(page, username, password, start_url, flow, new_password=None):
    # Full IAM Identity Center: di QUA Kiro signin (de callback awsidc kich hoat
    # RegisterClient + 302 sang AWS authorize) -> chon "IAM Identity Center" ->
    # dien start URL -> AWS login -> listener bat OAuth code. Khac drive_login_iam
    # (chi check pass, mo start URL truc tiep, khong lay token).
    # cookie banner
    try: page.get_by_role("button", name="Accept").click(timeout=4000)
    except Exception: pass
    # buoc 1: click "Your organization" de hien cac lua chon SSO (giong explore.py)
    for sel in ('button:has-text("Your organization")', 'button:has-text("Your organization Sign in")',
                'text=Your organization'):
        try:
            page.locator(sel).first.click(timeout=8000); break
        except Exception:
            pass
    page.wait_for_timeout(1500)
    # buoc 2: click "Sign in via IAM Identity Center instead"
    clicked = False
    for sel in ('button:has-text("IAM Identity Center")', 'a:has-text("IAM Identity Center")',
                'text=IAM Identity Center'):
        try:
            page.locator(sel).first.click(timeout=6000); clicked = True; break
        except Exception:
            pass
    if not clicked:
        raise RuntimeError("khong thay nut 'IAM Identity Center' tren trang Kiro signin")
    page.wait_for_timeout(1500)
    # dien start URL (#enterprise-sign-in-url)
    if not _fill_first(page, start_url, '#enterprise-sign-in-url', 'input[name="url"]',
                       'input[placeholder*="awsapps"]'):
        raise RuntimeError("khong thay o nhap Start URL (#enterprise-sign-in-url)")
    page.wait_for_timeout(400)
    _iam_click_submit(page, ('button:has-text("Continue")', 'button:has-text("Next")',
                             'button[type="submit"]'))
    # Luc nay listener nhan callback awsidc -> RegisterClient -> 302 sang AWS authorize.
    # Cho trang AWS login hien (co the mat vai giay do RegisterClient).
    try:
        _fill_aws_login(page, username, password)
    except Exception as exc:  # noqa: BLE001 - PWTimeout hoac RuntimeError
        if isinstance(exc, RuntimeError) and str(exc).startswith("SAI PASS"):
            raise
        # Trang AWS login khong hien -> thuong do listener da tra LOI (RegisterClient/
        # derive_region fail) va gui _html(False). Uu tien surface loi that do.
        if not flow.result_queue.empty():
            r = flow.result_queue.get_nowait()
            if isinstance(r, Exception):
                raise r
        raise
    # cho listener bat OAuth code (hoac loi). Xu ly them: trang "Allow access" cua
    # AWS SSO OIDC (consent) + trang "Set new password" (account bi ep doi pass).
    changed = False
    deadline = time.time() + 60
    while time.time() < deadline:
        if not flow.result_queue.empty():
            return changed
        try:
            cur = (page.url or "").lower()
            if cur.startswith("http://127.0.0.1:3128/oauth/callback") or \
               cur.startswith("http://localhost:3128/oauth/callback"):
                return changed
            # account bi ep doi pass -> dien pass moi (chi lan dau, guard changed)
            if new_password and not changed and is_iam_set_password_page(page):
                fill_iam_set_password(page, new_password)
                changed = True
                page.wait_for_timeout(2500)
                continue
            # trang consent "Allow access" / "Authorize request"
            for sel in ('button:has-text("Allow access")', 'button:has-text("Allow")',
                        'button:has-text("Authorize")', 'button:has-text("Confirm")',
                        '[data-testid="allow-access-button"]', '#cli_verification_btn'):
                try:
                    el = page.query_selector(sel)
                    if el and el.is_visible():
                        el.click(timeout=4000); page.wait_for_timeout(1500); break
                except Exception:
                    pass
            # KMSI / stay signed in
            if page.query_selector('#KmsiCheckboxField'):
                try: page.click('input[type="submit"]', timeout=3000)
                except Exception: pass
            # sai pass o buoc AWS (hien sau khi submit)
            txt = _iam_page_text(page).lower()
            for kw in ("couldn't verify", "incorrect username or password", "does not compute"):
                if kw in txt:
                    raise RuntimeError("SAI PASS (IAM): " + kw)
        except RuntimeError:
            raise
        except Exception:
            pass
        page.wait_for_timeout(700)
    _dump_portal(page, "iam_timeout")
    raise RuntimeError("timeout, khong bat duoc callback awsidc (xem _portal_iam_timeout dump)")


# (drive_login_iam_full tra ve `changed`: True neu da dat pass moi cho account IAM.)


def process_full_iam(account, browser):
    # Pipeline full cho 1 account IAM Identity Center: login qua awsidc -> token ->
    # list_profiles (external_idp=False, KHONG TokenType) -> credit -> scrape portal.
    # Tra ve DICT day du giong process_full_microsoft.
    email = account["email"].strip()
    password = account.get("password", "")
    start_url = (account.get("url") or "").strip() or os.environ.get("IAM_URL", "").strip()
    url, state, _verifier = signin_url()
    servers, flow = K.start_listener(state, None)
    ctx = browser.new_context()
    page = ctx.new_page()
    result = {
        "user": email, "password": password, "result": "Error", "detail": "",
        "new_password": "", "credit_used": None, "credit_total": None,
        "credit_remaining": None, "credit_reset": "", "api_keys": [],
    }
    if not start_url:
        result["detail"] = "IAM account thieu start URL (them cot url hoac set IAM_URL)"
        try: ctx.close()
        except Exception: pass
        for s in servers:
            try: s.shutdown(); s.server_close()
            except Exception: pass
        return result
    try:
        page.goto(url, wait_until="domcontentloaded", timeout=60000)
        try: page.wait_for_load_state("networkidle", timeout=15000)
        except Exception: pass
        new_password = generate_ms_password()
        try:
            changed = drive_login_iam_full(page, email, password, start_url, flow, new_password)
        except RuntimeError as exc:
            msg = str(exc)
            result["result"] = "Wrong" if msg.startswith("SAI PASS") else "Error"
            result["detail"] = msg
            return result
        cb = flow.result_queue.get(timeout=FULL_ACCOUNT_TIMEOUT)
        if isinstance(cb, Exception):
            raise cb
        if cb.get("kind") != "awsidc":
            raise RuntimeError("luong khong phai awsidc: %s" % cb.get("kind"))
        access, refresh, expires_in = K.exchange_awsidc_code(
            cb["token_endpoint"], cb["client_id"], cb["client_secret"], cb["code"],
            cb["verifier"], cb["redirect_uri"], None)
        region = cb.get("region", REGION)
        # IAM Identity Center token: KHONG gui TokenType -> external_idp=False.
        arn, region2, used_url = list_profiles_multi_idc(access, region)
        region = region2 or region
        result["result"] = "Right"
        result["detail"] = "pass DUNG (IAM awsidc)" + (" (da doi pass moi)" if changed else "")
        if changed:
            result["new_password"] = new_password
        # power credit — IAM token khong dung TokenType
        usage, usage_host, usage_err = U.get_usage_limits(access, arn, region, external_idp=False)
        if usage:
            result["credit_used"] = usage["used"]
            result["credit_total"] = usage["total"]
            result["credit_remaining"] = usage["remaining"]
            if usage.get("reset_epoch"):
                try:
                    result["credit_reset"] = datetime.fromtimestamp(
                        int(usage["reset_epoch"]), tz=timezone.utc).strftime("%Y-%m-%d")
                except Exception:
                    result["credit_reset"] = str(usage["reset_epoch"])
            dbg("credit:", result["credit_used"], "/", result["credit_total"], "| host:", usage_host)
        else:
            dbg("GetUsageLimits khong lay duoc:", usage_err)
            result["detail"] += " | credit: %s" % (usage_err or "khong lay duoc")[:120]
        try:
            eff_pw = result["new_password"] or password
            result["api_keys"] = scrape_portal_api_keys(
                page, kind="awsidc", email=email, password=eff_pw, start_url=start_url)
        except Exception as exc:  # noqa: BLE001
            dbg("scrape_portal_api_keys loi:", exc)
        return result
    except Exception as exc:  # noqa: BLE001
        result["result"] = "Error"
        result["detail"] = (result["detail"] + " | " if result["detail"] else "") + \
            (str(exc) or exc.__class__.__name__)
        return result
    finally:
        try: ctx.close()
        except Exception: pass
        for s in servers:
            try: s.shutdown()
            except Exception: pass
            try: s.server_close()
            except Exception: pass
        time.sleep(1.0)


def process_check_keys(account, browser, is_iam, start_url=None):
    # Keys-only: login (de co portal session) -> portal_web_login -> cao API keys.
    # BO QUA exchange token / list_profiles / credit (chi can session portal). Xu ly
    # ca microsoft (external_idp) va iam (awsidc). Tra dict chuan giong process_full_*.
    email = account["email"].strip()
    password = account.get("password", "")
    url, state, _verifier = signin_url()
    servers, flow = K.start_listener(state, None)
    ctx = browser.new_context()
    page = ctx.new_page()
    result = {
        "user": email, "password": password, "result": "Error", "detail": "",
        "new_password": "", "credit_used": None, "credit_total": None,
        "credit_remaining": None, "credit_reset": "", "api_keys": [],
    }
    try:
        new_password = generate_ms_password()
        page.goto(url, wait_until="domcontentloaded", timeout=60000)
        try:
            page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        try:
            if is_iam:
                if not start_url:
                    raise RuntimeError("IAM account thieu start URL")
                changed = drive_login_iam_full(page, email, password, start_url, flow, new_password)
                kind = "awsidc"
            else:
                changed = drive_login_full(page, email, password, flow, new_password)
                kind = "external_idp"
        except RuntimeError as exc:
            msg = str(exc)
            result["result"] = "Wrong" if msg.startswith("SAI PASS") else "Error"
            result["detail"] = msg
            return result
        # drain OAuth callback (khong can token — chi can portal session da thiet lap).
        try:
            cb = flow.result_queue.get(timeout=FULL_ACCOUNT_TIMEOUT)
            if isinstance(cb, Exception):
                raise cb
        except Exception:
            pass  # portal session co the da co roi; khong chan viec cao key
        result["result"] = "Right"
        result["detail"] = "pass DUNG" + (" (da doi pass moi)" if changed else "")
        if changed:
            result["new_password"] = new_password
        try:
            eff_pw = result["new_password"] or password
            result["api_keys"] = scrape_portal_api_keys(
                page, kind=kind, email=email, password=eff_pw,
                start_url=start_url if is_iam else None)
        except Exception as exc:  # noqa: BLE001
            dbg("scrape_portal_api_keys loi:", exc)
        return result
    except Exception as exc:  # noqa: BLE001
        result["result"] = "Error"
        result["detail"] = (result["detail"] + " | " if result["detail"] else "") + \
            (str(exc) or exc.__class__.__name__)
        return result
    finally:
        try: ctx.close()
        except Exception: pass
        for s in servers:
            try: s.shutdown()
            except Exception: pass
            try: s.server_close()
            except Exception: pass
        time.sleep(1.0)


def _goto_apikeys_ready(page, kind, email, password, start_url):
    # Login portal (session) roi vao trang /settings/api-keys, accept cookie, cho
    # noi dung that render. Tra True neu trang key da san sang (co ksk_ hoac nut
    # "Create key"/empty-state). Dung chung cho check_keys va delete_keys.
    portal_web_login(page, kind, email, password, start_url)
    page.goto("https://app.kiro.dev/settings/api-keys", wait_until="domcontentloaded", timeout=20000)
    for sel in ('button:has-text("Accept")', '[data-testid="ccba-footer"] button',
                'button:has-text("Accept all")'):
        try: page.click(sel, timeout=2000); break
        except Exception: pass
    for _ in range(30):
        try:
            body = page.inner_text("body", timeout=2000) or ""
        except Exception:
            body = ""
        low = body.lower()
        if ("ksk_" in body or "create key" in low or "no api keys" in low):
            return True
        if "failed to load" in low:
            try: page.click('button:has-text("Retry")', timeout=1500)
            except Exception: pass
        page.wait_for_timeout(1000)
    return False


def _revoke_first_matching_key(page, want_names):
    # Tim row key (chua ksk_) co ten nam trong want_names (case-insensitive exact),
    # bam nut revoke (danger) trong row do, xac nhan. Tra ve ten key da xoa hoac "".
    # want_names = set lowercased names; {} rong + delete_all phai xu ly ngoai.
    try:
        rows = page.query_selector_all('tr:has-text("ksk_")')
    except Exception:
        rows = []
    for row in rows:
        try:
            txt = row.inner_text() or ""
        except Exception:
            continue
        lines = [ln.strip() for ln in txt.splitlines() if ln.strip()]
        if not lines:
            continue
        name = ""
        for ln in lines:
            low = ln.lower()
            if ln.startswith("ksk_"):
                continue
            if low.startswith(("jan", "feb", "mar", "apr", "may", "jun", "jul",
                               "aug", "sep", "oct", "nov", "dec")):
                continue
            name = ln; break
        if not name:
            name = lines[0]
        if name.lower() not in want_names:
            continue
        # bam nut revoke (danger action icon) trong row
        btn = None
        for sel in ('button[class*="danger"]', 'button[aria-label*="elete"]',
                    'button[aria-label*="evok"]', 'button[aria-label*="emove"]',
                    'button[data-variant="danger"]'):
            try:
                b = row.query_selector(sel)
                if b:
                    btn = b; break
            except Exception:
                pass
        if btn is None:
            btns = row.query_selector_all('button')
            if btns:
                btn = btns[-1]
        if btn is None:
            continue
        try:
            btn.click(timeout=4000)
        except Exception:
            continue
        # xac nhan dialog (cho nut xac nhan danger xuat hien)
        confirmed = False
        for _ in range(10):
            for csel in ('button:has-text("Delete")', 'button:has-text("Revoke")',
                         'button:has-text("Remove")', 'button:has-text("Confirm")',
                         'button:has-text("Yes")', 'button[data-variant="danger"]'):
                try:
                    el = page.query_selector(csel)
                    if el and el.is_visible():
                        el.click(timeout=3000); confirmed = True; break
                except Exception:
                    pass
            if confirmed:
                break
            page.wait_for_timeout(600)
        page.wait_for_timeout(1200)  # cho row bien mat
        return name
    return ""


def process_delete_keys(account, browser, is_iam, start_url=None,
                        names=None, delete_all=False):
    # Xoa key chon loc: login -> portal -> trang API keys -> revoke tung key co ten
    # nam trong `names` (exact, case-insensitive); neu delete_all thi xoa het. Tra
    # dict chuan + deleted_keys (list ten da xoa) + api_keys (con lai).
    email = account["email"].strip()
    password = account.get("password", "")
    want = {n.strip().lower() for n in (names or []) if n.strip()}
    url, state, _v = signin_url()
    servers, flow = K.start_listener(state, None)
    ctx = browser.new_context()
    page = ctx.new_page()
    result = {
        "user": email, "password": password, "result": "Error", "detail": "",
        "new_password": "", "deleted_keys": [], "api_keys": [],
    }
    try:
        new_password = generate_ms_password()
        page.goto(url, wait_until="domcontentloaded", timeout=60000)
        try: page.wait_for_load_state("networkidle", timeout=15000)
        except Exception: pass
        try:
            if is_iam:
                if not start_url:
                    raise RuntimeError("IAM account thieu start URL")
                changed = drive_login_iam_full(page, email, password, start_url, flow, new_password)
                kind = "awsidc"
            else:
                changed = drive_login_full(page, email, password, flow, new_password)
                kind = "external_idp"
        except RuntimeError as exc:
            msg = str(exc)
            result["result"] = "Wrong" if msg.startswith("SAI PASS") else "Error"
            result["detail"] = msg
            return result
        try:
            cb = flow.result_queue.get(timeout=FULL_ACCOUNT_TIMEOUT)
            if isinstance(cb, Exception):
                raise cb
        except Exception:
            pass
        result["result"] = "Right"
        result["detail"] = "pass DUNG" + (" (da doi pass moi)" if changed else "")
        if changed:
            result["new_password"] = new_password
        eff_pw = result["new_password"] or password
        ready = _goto_apikeys_ready(page, kind, email, eff_pw,
                                    start_url if is_iam else None)
        if not ready:
            result["detail"] += " | khong vao duoc trang API keys"
            return result
        # danh sach key truoc khi xoa
        before = _extract_api_keys(page)
        target = {k["name"].lower() for k in before if k.get("name")} if delete_all else want
        if not target and not delete_all:
            result["detail"] += " | khong chi dinh ten key nao de xoa"
            result["api_keys"] = before
            return result
        # xoa tung key (lap den khi khong con match)
        deleted = []
        for _ in range(50):  # gioi han chong lap vo han
            gone = _revoke_first_matching_key(page, target)
            if not gone:
                break
            deleted.append(gone)
            target.discard(gone.lower())  # tranh trung lap
        result["deleted_keys"] = deleted
        result["api_keys"] = _extract_api_keys(page)
        result["detail"] += " | da xoa %d key" % len(deleted)
        return result
    except Exception as exc:  # noqa: BLE001
        result["result"] = "Error"
        result["detail"] = (result["detail"] + " | " if result["detail"] else "") + \
            (str(exc) or exc.__class__.__name__)
        return result
    finally:
        try: ctx.close()
        except Exception: pass
        for s in servers:
            try: s.shutdown()
            except Exception: pass
            try: s.server_close()
            except Exception: pass
        time.sleep(1.0)


def write_report(report, mode="json"):
    # checkpass: cot [user, password, result(Right/Wrong/Error)].
    # json: cot [email, status, detail].
    fieldnames = ["user", "password", "result"] if mode == "checkpass" else ["email", "status", "detail"]
    with open(os.path.join(OUT_DIR, "_report.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader(); w.writerows(report)

def choose_mode():
    # Cho phep truyen doi so: `python batch.py json` / `python batch.py checkpass`.
    # Khong co doi so thi hoi tuong tac khi khoi dong.
    if len(sys.argv) > 1:
        arg = sys.argv[1].strip().lower()
        if arg in ("checkpass", "check-pass", "pass", "2"):
            return "checkpass"
        if arg in ("json", "export", "1"):
            return "json"
    while True:
        try:
            ans = input("Chon che do:  1) Xuat JSON   2) Check pass   [1/2]: ").strip()
        except EOFError:
            ans = "1"
        if ans in ("1", ""):
            return "json"
        if ans == "2":
            return "checkpass"
        print("   (nhap 1 hoac 2)")


def load_accounts(path):
    # Doc danh sach account tu CSV. Tu dong phat hien delimiter ('|' hoac ',') va
    # bo dong header -> ho tro ca "email,password[,url]" va "user|password[|url]".
    # Gia su password KHONG chua delimiter (neu chua thi phai quote trong CSV).
    # utf-8-sig tu bo BOM (Excel/Notepad hay them BOM -> header bi thanh account).
    with open(path, encoding="utf-8-sig") as fh:
        lines = [ln.rstrip("\r\n") for ln in fh]
    data = [ln for ln in lines if ln.strip()]
    sample = "".join(data[1:5]) if len(data) > 1 else ""
    delim = "|" if sample.count("|") > sample.count(",") else ","
    rows = []
    for ln in data:
        parts = ln.split(delim, 2)   # user, password, [url]
        user = parts[0].strip()
        if not user or user.lower() in ("email", "user", "username"):
            continue   # bo header / dong trong
        if len(parts) < 2:
            continue   # chi co user, khong co password
        rows.append({
            "email": user,
            "password": parts[1].strip(),
            "url": parts[2].strip() if len(parts) > 2 else "",
        })
    return rows


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    rows = load_accounts(CSV_PATH)
    mode = choose_mode()
    print("Mode:", "CHECK PASS" if mode == "checkpass" else "XUAT JSON", flush=True)
    report = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=HEADLESS)
        for i, row in enumerate(rows, 1):
            email = row["email"].strip()
            print("[%d/%d] %s" % (i, len(rows), email), flush=True)
            if mode == "checkpass":
                try:
                    status, detail = process_checkpass(row, browser)
                except Exception as exc:
                    status, detail = "ERROR", (str(exc) or exc.__class__.__name__)
                verdict = {"OK": "Right", "WRONG": "Wrong"}.get(status, "Error")
                report.append({"user": email, "password": row.get("password", ""),
                               "result": verdict, "status": status, "detail": detail})
                print("   %s (%s) -> %s" % (status, verdict, detail), flush=True)
            else:
                try:
                    status, detail = process(row, browser)
                except Exception as exc:
                    status, detail = "FAIL", (str(exc) or exc.__class__.__name__)
                report.append({"email": email, "status": status, "detail": detail})
                print("   %s -> %s" % (status, detail), flush=True)
            write_report(report, mode)   # ghi sau moi account
        browser.close()
    print("="*40)
    if mode == "checkpass":
        right = sum(1 for r in report if r.get("result") == "Right")
        wrong = sum(1 for r in report if r.get("result") == "Wrong")
        err = sum(1 for r in report if r.get("result") == "Error")
        print("Right: %d   Wrong: %d   Error: %d   (tong %d)" % (right, wrong, err, len(report)))
    else:
        ok = sum(1 for r in report if r.get("status") == "OK")
        print("OK: %d   FAIL: %d" % (ok, len(report)-ok))
    print("Report:", os.path.join(OUT_DIR, "_report.csv"))

if __name__ == "__main__":
    main()
