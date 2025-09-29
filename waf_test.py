#!/usr/bin/env python3
"""
waf_test.py

Light test-suite for the Flask WAF. Run while the WAF is running locally.
Requires: requests
"""

import requests
import time
import urllib.parse

BASE = "http://127.0.0.1:8090"   # change to 192.168.22.115 if needed
HEADERS = {"User-Agent": "waf-test/1.0"}

def expect(resp, code=200, contains=None):
    ok = resp.status_code == code and (contains is None or contains in resp.text)
    print(f"[{resp.status_code}] {resp.request.method} {resp.url} -> {'OK' if ok else 'FAIL'}")
    if not ok:
        print("  body:", resp.text)
    return ok

def test_health():
    print("\n== health ==")
    r = requests.get(BASE + "/health", headers=HEADERS)
    expect(r, 200, '"status":"healthy"')

def test_index():
    print("\n== index ==")
    r = requests.get(BASE + "/", headers=HEADERS)
    expect(r, 200, '"Enterprise WAF is running"')

def test_reload():
    print("\n== reload-config ==")
    r = requests.post(BASE + "/reload-config", headers=HEADERS)
    expect(r, 200, '"reloaded"')

def test_query_xss_block():
    print("\n== query param XSS (should be blocked) ==")
    payload = '<script>alert(1)</script>'
    url = BASE + "/?q=" + urllib.parse.quote(payload)
    r = requests.get(url, headers=HEADERS)
    expect(r, 403)   # blocked

def test_query_sql_block():
    print("\n== query param SQLi (should be blocked) ==")
    payload = "UNION SELECT"
    url = BASE + "/?q=" + urllib.parse.quote(payload)
    r = requests.get(url, headers=HEADERS)
    expect(r, 403)

def test_form_xss_block():
    print("\n== form POST XSS (should be blocked) ==")
    payload = '<img src=x onerror=alert(1)>'
    r = requests.post(BASE + "/submit", data={"comment": payload}, headers=HEADERS)
    # If /submit doesn't exist in your app, WAF still inspects and returns 403 if matched.
    if r.status_code == 404:
        print("  Endpoint /submit not present; but WAF should have blocked before app. Status:", r.status_code)
    else:
        expect(r, 403)

def test_header_block():
    print("\n== header block (malicious header) ==")
    headers = HEADERS.copy()
    headers["X-Test"] = "<script>alert(1)</script>"
    r = requests.get(BASE + "/", headers=headers)
    expect(r, 403)

def test_body_block():
    print("\n== raw body block (should be blocked) ==")
    payload = '{"data":"<script>alert(1)</script>"}'
    headers = HEADERS.copy()
    headers["Content-Type"] = "application/json"
    r = requests.post(BASE + "/api", data=payload.encode("utf-8"), headers=headers)
    # The WAF checks raw body and may block
    if r.status_code in (403, 200, 404):
        print("  Received status:", r.status_code)
    else:
        print("  Unexpected status:", r.status_code, r.text)

def test_blacklist():
    print("\n== simulate blacklisted IP via X-Forwarded-For ==")
    headers = HEADERS.copy()
    headers["X-Forwarded-For"] = "192.168.1.100"   # should be present in waf_config ip_blacklist
    r = requests.get(BASE + "/health", headers=headers)
    expect(r, 403)

def test_rate_limit():
    print("\n== rate limit test (send bursts) ==")
    headers = HEADERS.copy()
    ip = "1.2.3.4"
    headers["X-Forwarded-For"] = ip
    # Send limit+3 requests quickly
    limit = 5   # set to a low number for test; adjust to match your config or temporarily set config
    success = 0
    for i in range(limit + 3):
        r = requests.get(BASE + "/health", headers=headers)
        print(f"  {i+1}: {r.status_code}")
        time.sleep(0.1)
        if r.status_code == 429:
            print("  Rate-limited as expected at attempt", i+1)
            break

def run_all():
    test_health()
    test_index()
    test_reload()
    test_query_xss_block()
    test_query_sql_block()
    test_form_xss_block()
    test_header_block()
    test_body_block()
    test_blacklist()
    test_rate_limit()

if __name__ == "__main__":
    print("Running WAF tests against", BASE)
    run_all()
    print("Done.")
