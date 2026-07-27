#!/usr/bin/env python3
# kiro_usage.py — GetUsageLimits (power credits) qua CodeWhisperer / Amazon Q runtime.
#
# Tach rieng khoi kiro_helper.py: kiro_helper la ban port thuan cua flow SSO login,
# con day la moi lo runtime API (GetUsageLimits) voi host-fallback + shape response
# rieng. Tai dung nguyen cac header-builder + _do_request cua kiro_helper de khong
# lap logic (giong probe_credit.py va batch._call_list_profiles da lam).
import json
import urllib.request

import kiro_helper as K

# X-Amz-Target cho GetUsageLimits (tu source AWS SDK amzn-codewhisperer-client).
USAGE_TARGET = "AmazonCodeWhispererService.GetUsageLimits"

# Host thu theo thu tu:
#   q.{region}.amazonaws.com          -> tenant hien tai (theo tai lieu SDK)
#   runtime.{region}.kiro.dev         -> host data-plane moi cua Kiro (fallback)
#   codewhisperer.{region}.amazonaws.com -> host cu; giu lai vi day la host DUY NHAT
#                                        repo nay tung goi thuc te (probe_credit.py)
# CAN 1 lan goi that de chot host q. vs runtime. tren account con hieu luc.
USAGE_HOST_TEMPLATES = [
    "https://q.%s.amazonaws.com/",
    "https://runtime.%s.kiro.dev/",
    "https://codewhisperer.%s.amazonaws.com/",
]


# _usage_headers dung y het bo header ma _call_list_profiles (batch.py) va
# probe_credit.py da dung, chi doi X-Amz-Target sang GetUsageLimits.
def _usage_headers(access_token, region, external_idp):
    machine_id = K.build_machine_id(access_token)
    headers = {
        "Content-Type": "application/x-amz-json-1.0",
        "Accept": "application/x-amz-json-1.0",
        "Authorization": "Bearer " + access_token,
        "X-Amz-Target": USAGE_TARGET,
        "amz-sdk-invocation-id": K.build_machine_id(access_token, region, "getusagelimits"),
        "amz-sdk-request": "attempt=1; max=1",
        "x-amzn-kiro-agent-mode": "vibe",
        "x-amzn-codewhisperer-optout": "true",
        "User-Agent": K.build_user_agent(machine_id),
        "x-amz-user-agent": K.build_x_amz_user_agent(machine_id),
    }
    if external_idp:
        headers["TokenType"] = "EXTERNAL_IDP"
    return headers


# parse_usage_breakdown tim entry POWER CREDIT trong usageBreakdownList. Uu tien
# entry co resourceType == "CREDIT" (khong phan biet hoa/thuong); neu khong entry
# nao co resourceType thi lay entry dau. Tra dict chuan hoa, hoac None neu shape la.
def parse_usage_breakdown(parsed):
    items = (parsed or {}).get("usageBreakdownList") or []
    if not isinstance(items, list) or not items:
        return None
    entry = None
    for it in items:
        if not isinstance(it, dict):
            continue
        if str(it.get("resourceType", "")).upper() == "CREDIT":
            entry = it
            break
    if entry is None:
        # khong tim thay CREDIT -> lay entry dict dau tien co du used/total
        for it in items:
            if isinstance(it, dict):
                entry = it
                break
    if entry is None:
        return None
    used = entry.get("currentUsage")
    total = entry.get("usageLimit")
    remaining = None
    if isinstance(used, (int, float)) and isinstance(total, (int, float)):
        remaining = total - used
    return {
        "used": used,
        "total": total,
        "remaining": remaining,
        "used_precise": entry.get("currentUsageWithPrecision"),
        "total_precise": entry.get("usageLimitWithPrecision"),
        "reset_epoch": entry.get("nextDateReset"),
        "unit": entry.get("unit"),
        "resource_type": entry.get("resourceType"),
        "raw": entry,
    }


# get_usage_limits goi GetUsageLimits, thu tuan tu cac host trong USAGE_HOST_TEMPLATES
# cho den khi duoc HTTP 2xx + body parse duoc usageBreakdownList. Tra ve
# (usage_dict_or_None, host_used_or_None, last_error_str_or_None).
def get_usage_limits(access_token, profile_arn, region, external_idp=True,
                     proxy_url=None, timeout=30):
    if not (access_token or "").strip():
        return None, None, "access token rong"
    region = (region or K.DEFAULT_REGION).strip() or K.DEFAULT_REGION
    payload = {"origin": "AI_EDITOR", "resourceType": "CREDIT"}
    if (profile_arn or "").strip():
        payload["profileArn"] = profile_arn
    body = json.dumps(payload).encode("utf-8")
    last_err = None
    for tmpl in USAGE_HOST_TEMPLATES:
        host = tmpl % region
        headers = _usage_headers(access_token, region, external_idp)
        req = urllib.request.Request(host, data=body, method="POST", headers=headers)
        try:
            status, parsed, text = K._do_request(req, proxy_url, timeout)
        except Exception as exc:  # noqa: BLE001 - DNS/timeout tai host nay -> thu host sau
            last_err = "loi ket noi %s: %s" % (host, exc)
            continue
        if 200 <= status < 300:
            usage = parse_usage_breakdown(parsed)
            if usage is not None:
                return usage, host, None
            last_err = "status %d tai %s nhung khong parse duoc usageBreakdownList: %s" % (
                status, host, (text or "")[:200])
        else:
            last_err = "status %d tai %s: %s" % (status, host, (text or "")[:200])
    return None, None, last_err
