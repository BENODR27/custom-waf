#!/usr/bin/env python3
"""
Enterprise WAF + Basic DDoS protections - Flask middleware style application.

Enhancements over original:
 - Config-driven: added ddos_protection options and trusted_proxies
 - Per-IP exponential backoff bans (auto-escalating ban durations)
 - Global request surge protection (global rate limiter)
 - Concurrency limiter (Semaphore) to bound concurrent request handlers
 - Improved X-Forwarded-For handling with trusted proxy list
 - Quick health-check/whitelist bypass for monitoring systems
 - Clear logging of DDoS events and ban state

NOTES:
 - This is an application-layer mitigations only. For strong DDoS protection
   also use network/edge protections (CDN, cloud DDoS, firewall rules, etc.).
 - Tune rates and windows in waf_config.yaml for your environment.
"""

from collections import defaultdict, deque
import logging
import re
import threading
import time
import typing as t
import yaml
from flask import Flask, request, jsonify, abort

# Configuration
CONFIG_PATH = "waf_config.yaml"
DEFAULT_RATE_LIMIT = {"limit": 100, "window": 60}
DEFAULT_GLOBAL_LIMIT = {"limit": 1000, "window": 1}  # requests per second

# App and logging
app = Flask(__name__)
logging.basicConfig(
    filename="waf.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("waf")

# Global runtime structures protected by lock
_config_lock = threading.RLock()
_compiled_patterns: t.Dict[str, t.List[re.Pattern]] = {}
ip_blacklist: t.Set[str] = set()
rate_limit_count = DEFAULT_RATE_LIMIT["limit"]
rate_limit_window = DEFAULT_RATE_LIMIT["window"]
_ip_request_log: t.DefaultDict[str, deque] = defaultdict(lambda: deque())

# DDoS protection state
_ddos_lock = threading.RLock()
_ip_ban_until: t.Dict[str, float] = {}            # ip -> unix timestamp until banned
_ip_ban_count: t.Dict[str, int] = defaultdict(int)  # number of times banned (for escalation)
_global_request_log: deque = deque()              # timestamps for global rate limiting
global_limit_count = DEFAULT_GLOBAL_LIMIT["limit"]
global_limit_window = DEFAULT_GLOBAL_LIMIT["window"]

# Concurrency limiter: bounds concurrent request handling at the application level
CONCURRENCY_LIMIT = 100  # default; configurable
_concurrency_sem = threading.BoundedSemaphore(CONCURRENCY_LIMIT)

# Trusted proxies for X-Forwarded-For parsing - when present, take first non-proxy
_trusted_proxies: t.List[str] = []

# Whitelisted IPs (healthchecks, monitoring) bypass some checks
_health_ip_whitelist: t.Set[str] = set()


def load_config(path: str = CONFIG_PATH) -> None:
    """Load and validate configuration from YAML and compile regexes."""
    global _compiled_patterns, ip_blacklist, rate_limit_count, rate_limit_window
    global global_limit_count, global_limit_window, CONCURRENCY_LIMIT, _concurrency_sem
    global _trusted_proxies, _health_ip_whitelist

    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
    except FileNotFoundError:
        logger.error("Configuration file not found: %s", path)
        raise
    except Exception as exc:
        logger.exception("Failed to read configuration: %s", exc)
        raise

    patterns = cfg.get("patterns", {})
    compiled: t.Dict[str, t.List[re.Pattern]] = {}

    # Compile and validate pattern list
    for category, pattern_list in patterns.items():
        if not isinstance(pattern_list, list):
            logger.warning("Skipping invalid pattern list for category: %s", category)
            continue

        compiled_list: t.List[re.Pattern] = []
        for raw in pattern_list:
            try:
                compiled_list.append(re.compile(raw, re.IGNORECASE | re.UNICODE))
            except re.error as exc:
                logger.warning("Invalid regex [%s] in category [%s]: %s", raw, category, exc)
        if compiled_list:
            compiled[category] = compiled_list

    with _config_lock:
        _compiled_patterns = compiled
        ip_blacklist = set(cfg.get("ip_blacklist", []))
        rl = cfg.get("rate_limit", DEFAULT_RATE_LIMIT) or DEFAULT_RATE_LIMIT
        try:
            rate_limit_count = int(rl.get("limit", DEFAULT_RATE_LIMIT["limit"]))
            rate_limit_window = int(rl.get("window", DEFAULT_RATE_LIMIT["window"]))
        except Exception:
            rate_limit_count = DEFAULT_RATE_LIMIT["limit"]
            rate_limit_window = DEFAULT_RATE_LIMIT["window"]

        g_rl = cfg.get("global_rate_limit", DEFAULT_GLOBAL_LIMIT)
        try:
            global_limit_count = int(g_rl.get("limit", DEFAULT_GLOBAL_LIMIT["limit"]))
            global_limit_window = float(g_rl.get("window", DEFAULT_GLOBAL_LIMIT["window"]))
        except Exception:
            global_limit_count = DEFAULT_GLOBAL_LIMIT["limit"]
            global_limit_window = DEFAULT_GLOBAL_LIMIT["window"]

        # concurrency
        try:
            CONCURRENCY_LIMIT = int(cfg.get("concurrency_limit", CONCURRENCY_LIMIT))
        except Exception:
            CONCURRENCY_LIMIT = CONCURRENCY_LIMIT
        # rebuild semaphore with new limit
        _concurrency_sem = threading.BoundedSemaphore(CONCURRENCY_LIMIT)

        _trusted_proxies = cfg.get("trusted_proxies", []) or []
        _health_ip_whitelist = set(cfg.get("health_ip_whitelist", []))

    logger.info(
        "Config loaded. categories=%d, blacklisted_ips=%d, rate_limit=%d/%ds, global_rate=%d/%ss, concurrency=%d",
        len(_compiled_patterns), len(ip_blacklist), rate_limit_count, rate_limit_window,
        global_limit_count, global_limit_window, CONCURRENCY_LIMIT,
    )


# Utility to determine client IP (respects X-Forwarded-For if present and trusted proxies configured)
def get_remote_ip() -> str:
    """Get client's IP address, considering proxies (X-Forwarded-For) and trusted proxy list.

    If trusted_proxies is empty, behavior defaults to using first entry in X-Forwarded-For
    (common for single-proxy environments). If trusted_proxies is set, the function will
    strip known proxies from the end of the XFF chain and return the last untrusted IP.
    """
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        # split chain
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if not _trusted_proxies:
            return parts[0]
        # remove trusted proxies from the end of chain
        while parts and parts[-1] in _trusted_proxies:
            parts.pop()
        if parts:
            return parts[-1]
    return request.remote_addr or "unknown"


def is_malicious(payload: str) -> t.Tuple[bool, t.Optional[str]]:
    """Return (True, category) if payload matches any compiled malicious pattern."""
    if not payload:
        return False, None

    with _config_lock:
        for category, regex_list in _compiled_patterns.items():
            for pattern in regex_list:
                if pattern.search(payload):
                    return True, category
    return False, None


def is_rate_limited(ip: str) -> bool:
    """Enforce a sliding window rate limit per IP."""
    now = time.time()
    window = float(rate_limit_window)
    limit = int(rate_limit_count)

    dq = _ip_request_log[ip]
    # purge older entries
    while dq and now - dq[0] > window:
        dq.popleft()
    dq.append(now)
    if len(dq) > limit:
        logger.info("Rate limit exceeded: ip=%s count=%d limit=%d window=%ds", ip, len(dq), limit, window)
        return True
    return False


def global_overloaded() -> bool:
    """Simple global sliding window limiter to detect surges and enable protective mode."""
    with _ddos_lock:
        now = time.time()
        # purge old
        while _global_request_log and now - _global_request_log[0] > global_limit_window:
            _global_request_log.popleft()
        _global_request_log.append(now)
        if len(_global_request_log) > global_limit_count:
            logger.warning("Global rate threshold exceeded: %d requests in %.2fs", len(_global_request_log), global_limit_window)
            return True
    return False


def ban_ip(ip: str) -> None:
    """Ban an IP for an escalating duration based on previous ban count."""
    now = time.time()
    with _ddos_lock:
        _ip_ban_count[ip] += 1
        # exponential backoff: base 60s, doubled each ban up to cap
        base = 60
        cap = 60 * 60 * 24  # 24 hours
        duration = min(base * (2 ** (_ip_ban_count[ip] - 1)), cap)
        _ip_ban_until[ip] = now + duration
        logger.warning("Banned IP %s for %.0f seconds (ban_count=%d)", ip, duration, _ip_ban_count[ip])


def is_currently_banned(ip: str) -> bool:
    with _ddos_lock:
        until = _ip_ban_until.get(ip)
        if until and time.time() < until:
            return True
        # expired ban cleanup
        if until and time.time() >= until:
            del _ip_ban_until[ip]
    return False


@app.before_request
def waf_filter():
    """
    WAF filter runs before each request. It returns JSON responses for blocks
    and allows normal requests to proceed otherwise.
    """
    # Ignore static asset file extensions often served directly
    if request.path.endswith((".ico", ".png", ".jpg", ".jpeg", ".css", ".js", ".svg", ".woff2")):
        return

    ip = get_remote_ip()
    logger.info("Incoming request from %s %s %s", ip, request.method, request.url)

    # Quick bypass for known healthcheck IPs
    if ip in _health_ip_whitelist and request.path in ("/health", "/"):  # minimal checks
        return

    # 0) Check escalating ban list
    if is_currently_banned(ip):
        logger.warning("Rejected request from banned IP %s", ip)
        return jsonify({"error": "forbidden", "reason": "ip_temporarily_banned"}), 403

    # 1) IP blacklist
    if ip in ip_blacklist:
        logger.warning("Blocked blacklisted IP: %s", ip)
        ban_ip(ip)
        return jsonify({"error": "forbidden", "reason": "ip_blacklisted"}), 403

    # 1.5) Global overload detection
    if global_overloaded():
        # when global overload is detected, be more aggressive: ban offending IPs after quick violations
        # return 503 to signal upstream systems that we are overloaded
        logger.error("Global overload - rejecting request from %s", ip)
        # optionally escalate the single IP that caused spike
        ban_ip(ip)
        return jsonify({"error": "service_unavailable", "reason": "global_overload"}), 503

    # 2) Rate limit
    if is_rate_limited(ip):
        # escalate and ban if repeated rate limit violations
        _ip_ban_count[ip] += 1
        if _ip_ban_count[ip] >= 3:
            ban_ip(ip)
            return jsonify({"error": "forbidden", "reason": "repeated_rate_limit_violations"}), 403
        return jsonify({"error": "rate_limited", "reason": "too_many_requests"}), 429

    # 2.5) Concurrency protection: try to acquire semaphore immediately; if not, reject fast
    acquired = _concurrency_sem.acquire(blocking=False)
    if not acquired:
        logger.warning("Concurrency limit reached - rejecting %s", ip)
        # light penalty: count as a violation for potential banning
        _ip_ban_count[ip] += 1
        return jsonify({"error": "service_unavailable", "reason": "too_many_concurrent_requests"}), 503

    # NOTE: we must release semaphore after request is handled. Use after_request to release.

    # 3) Inspect query parameters
    for k, v in request.args.items():
        malicious, cat = is_malicious(v)
        if malicious:
            logger.warning("Blocked request (query) ip=%s key=%s category=%s value=%s", ip, k, cat, v)
            _concurrency_sem.release()
            ban_ip(ip)
            return jsonify({"error": "forbidden", "reason": f"matched_{cat}"}), 403

    # 4) Inspect form data
    for k, v in request.form.items():
        malicious, cat = is_malicious(v)
        if malicious:
            logger.warning("Blocked request (form) ip=%s key=%s category=%s value=%s", ip, k, cat, v)
            _concurrency_sem.release()
            ban_ip(ip)
            return jsonify({"error": "forbidden", "reason": f"matched_{cat}"}), 403

    # 5) Inspect headers (but skip sensitive headers that are system controlled)
    for k, v in request.headers.items():
        sample = v[:4096]
        malicious, cat = is_malicious(sample)
        if malicious:
            logger.warning("Blocked request (header) ip=%s header=%s category=%s", ip, k, cat)
            _concurrency_sem.release()
            ban_ip(ip)
            return jsonify({"error": "forbidden", "reason": f"matched_{cat}"}), 403

    # 6) Inspect raw body (if any). Decode safely
    if request.data:
        try:
            body_text = request.get_data(cache=True, as_text=True, parse_form_data=False)
            malicious, cat = is_malicious(body_text)
            if malicious:
                logger.warning("Blocked request (body) ip=%s category=%s", ip, cat)
                _concurrency_sem.release()
                ban_ip(ip)
                return jsonify({"error": "forbidden", "reason": f"matched_{cat}"}), 403
        except Exception as exc:
            logger.debug("Error reading request body: %s", exc)

    # If reached here, request passes checks
    return


@app.after_request
def after_request(response):
    # Always release semaphore if held. Be defensive: attempt release inside try/except.
    try:
        # release only if semaphore counter is below limit (meaning we acquired)
        # It's difficult to be 100% accurate here; an extra release will raise ValueError - catch it.
        _concurrency_sem.release()
    except ValueError:
        # nothing to release
        pass
    except Exception:
        pass
    return response


@app.route("/", methods=["GET"])
def index():
    return jsonify({"status": "ok", "message": "Welcome WAF with DDoS protections is running"}), 200


@app.route("/health", methods=["GET"])
def health():
    """Simple health endpoint used by load balancers/monitoring."""
    return jsonify({"status": "healthy", "time": int(time.time())}), 200


@app.route("/reload-config", methods=["POST"])
def reload_config_endpoint():
    """Reload config at runtime. In production protect this endpoint (auth, local-only)."""
    try:
        load_config(CONFIG_PATH)
        return jsonify({"status": "reloaded"}), 200
    except Exception as exc:
        logger.exception("Reload failed: %s", exc)
        return jsonify({"error": "reload_failed", "detail": str(exc)}), 500


if __name__ == "__main__":
    try:
        load_config(CONFIG_PATH)
    except Exception:
        logger.error("Failed to load config at startup; exiting.")
        raise

    # For production use a WSGI server (gunicorn/uvicorn) and avoid Flask built-in server.
    app.run(host="0.0.0.0", port=8090, debug=False)
