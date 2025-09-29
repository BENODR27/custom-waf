import re
import time
import yaml
import logging
from flask import Flask, request, abort
from collections import defaultdict

# Load WAF configuration from YAML file
with open("waf_config.yaml", "r") as f:
    config = yaml.safe_load(f)

# Initialize Flask app
app = Flask(__name__)

# Setup logging
logging.basicConfig(filename='waf.log', level=logging.INFO, format='%(asctime)s %(message)s')

# Load patterns from config
patterns = config.get("patterns", {})

# IP blacklist
ip_blacklist = set(config.get("ip_blacklist", []))

# Rate limiting
rate_limit_config = config.get("rate_limit", {"limit": 100, "window": 60})
rate_limit_window = rate_limit_config["window"]
rate_limit_count = rate_limit_config["limit"]
ip_request_log = defaultdict(list)

# Function to check if request matches any malicious pattern
def is_malicious(data):
    for category, regex_list in patterns.items():
        for pattern in regex_list:
            if re.search(pattern, data, re.IGNORECASE):
                logging.info(f"Blocked due to {category}: {data}")
                return True
    return False

# Function to enforce rate limiting
def is_rate_limited(ip):
    current_time = time.time()
    ip_request_log[ip] = [t for t in ip_request_log[ip] if current_time - t < rate_limit_window]
    ip_request_log[ip].append(current_time)
    if len(ip_request_log[ip]) > rate_limit_count:
        logging.info(f"Rate limit exceeded for IP: {ip}")
        return True
    return False

# WAF filter applied before each request
@app.before_request
def waf_filter():
    ip = request.remote_addr
    logging.info(f"IP: {ip}")

    # Check IP blacklist
    if ip in ip_blacklist:
        logging.info(f"Blocked blacklisted IP: {ip}")
        abort(403)

    # Rate limiting
    if is_rate_limited(ip):
        abort(429)

    # Check query parameters
    for key, value in request.args.items():
        if is_malicious(value):
            abort(403)

    # Check form data
    for key, value in request.form.items():
        if is_malicious(value):
            abort(403)

    # Check headers
    for key, value in request.headers.items():
        if is_malicious(value):
            abort(403)

    # Check raw body
    if request.data and is_malicious(request.data.decode(errors='ignore')):
        abort(403)

# Default route
@app.route('/')
def index():
    return "Enterprise WAF is running and filtering traffic."

# Run the WAF service
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8090)
