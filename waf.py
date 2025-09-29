#!/usr/bin/env python3
"""
Enterprise WAF - Flask middleware style application.

Features:
 - Loads patterns from YAML config
 - Compiles regexes once for performance
 - Thread-safe rate limiting per-IP using deque
 - IP blacklist support
 - Checks query args, form data, headers, and raw body
 - Safer, clearer logging and JSON responses
 - Handles X-Forwarded-For for proxied deployments
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


def load_config(path: str = CONFIG_PATH) -> None:
    """Load and validate configuration from YAML and compile regexes."""
    global _compiled_patterns, ip_blacklist, rate_limit_count, rate_limit_window

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
                # compile each pattern; treat raw strings as regex
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

    logger.info("Config loaded. categories=%d, blacklisted_ips=%d, rate_limit=%d/%ds",
                len(_compiled_patterns), len(ip_blacklist), rate_limit_count, rate_limit_window)


# Utility to determine client IP (respects X-Forwarded-For if present)
def get_remote_ip() -> str:
    """Get client's IP address, considering proxies (X-Forwarded-For)."""
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        # X-Forwarded-For can be a comma-separated list; the first is original client
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def is_malicious(payload: str) -> t.Tuple[bool, t.Optional[str]]:
    """Return (True, category) if payload matches any compiled malicious pattern."""
    if not payload:
        return False, None

    with _config_lock:
        for category, regex_list in _compiled_patterns.items():
            for pattern in regex_list:
                # Use search to find anywhere in payload
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
        logger.info("Rate limit exceeded: ip=%s count=%d limit=%d window=%ds",
                    ip, len(dq), limit, window)
        return True
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

    # 1) IP blacklist
    if ip in ip_blacklist:
        logger.warning("Blocked blacklisted IP: %s", ip)
        return jsonify({"error": "forbidden", "reason": "ip_blacklisted"}), 403

    # 2) Rate limit
    if is_rate_limited(ip):
        return jsonify({"error": "rate_limited", "reason": "too_many_requests"}), 429

    # 3) Inspect query parameters
    for k, v in request.args.items():
        malicious, cat = is_malicious(v)
        if malicious:
            logger.warning("Blocked request (query) ip=%s key=%s category=%s value=%s", ip, k, cat, v)
            return jsonify({"error": "forbidden", "reason": f"matched_{cat}"}), 403

    # 4) Inspect form data (application/x-www-form-urlencoded or multipart/form-data)
    for k, v in request.form.items():
        malicious, cat = is_malicious(v)
        if malicious:
            logger.warning("Blocked request (form) ip=%s key=%s category=%s value=%s", ip, k, cat, v)
            return jsonify({"error": "forbidden", "reason": f"matched_{cat}"}), 403

    # 5) Inspect headers (but skip sensitive headers that are system controlled)
    for k, v in request.headers.items():
        # limit header size to inspect (avoid huge binary headers)
        sample = v[:4096]
        malicious, cat = is_malicious(sample)
        if malicious:
            logger.warning("Blocked request (header) ip=%s header=%s category=%s", ip, k, cat)
            return jsonify({"error": "forbidden", "reason": f"matched_{cat}"}), 403

    # 6) Inspect raw body (if any). Decode safely
    if request.data:
        try:
            body_text = request.get_data(cache=True, as_text=True, parse_form_data=False)
            malicious, cat = is_malicious(body_text)
            if malicious:
                logger.warning("Blocked request (body) ip=%s category=%s", ip, cat)
                return jsonify({"error": "forbidden", "reason": f"matched_{cat}"}), 403
        except Exception as exc:
            # Don't break on decode errors; just log them
            logger.debug("Error reading request body: %s", exc)

    # If reached here, request passes checks
    return


@app.route("/", methods=["GET"])
def index():
    return jsonify({"status": "ok", "message": "Enterprise WAF is running"}), 200


@app.route("/health", methods=["GET"])
def health():
    """Simple health endpoint used by load balancers/monitoring."""
    return jsonify({"status": "healthy", "time": int(time.time())}), 200


@app.route("/reload-config", methods=["POST"])
def reload_config_endpoint():
    """Reload config at runtime. In production protect this endpoint (auth, local-only)."""
    # NOTE: this endpoint is intentionally simple. Protect in production.
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
