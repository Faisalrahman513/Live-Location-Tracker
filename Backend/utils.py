# utils.py
import json
import re
import requests
import time
from functools import wraps

# ==================================================================================
# UTILITY FUNCTIONS - DRY PRINCIPLE
# ==================================================================================

def parse_json_safe(data):
    """Safe JSON parser with fallback"""
    if not data:
        return None
    if isinstance(data, dict) or isinstance(data, list):
        return data
    try:
        return json.loads(data)
    except (json.JSONDecodeError, TypeError):
        return None

def retry_on_failure(max_retries=3, delay=1):
    """Decorator for retrying failed API calls"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try: 
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt == max_retries - 1:
                        print(f"[RETRY FAILED] {func.__name__}:  {e}")
                        raise
                    time.sleep(delay * (attempt + 1))
            return None
        return wrapper
    return decorator

def validate_email(email):
    """Comprehensive email validation"""
    if not email or not isinstance(email, str):
        return False
    # RFC 5322 compliant regex
    pattern = r'^[a-zA-Z0-9.! #$%&\'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
    return bool(re.match(pattern, email. strip().lower()))

def validate_username(username):
    """Username validation for social media"""
    if not username or not isinstance(username, str):
        return False
    # Alphanumeric + underscore/hyphen, 1-39 chars
    pattern = r'^[a-zA-Z0-9_-]{1,39}$'
    return bool(re.match(pattern, username. strip()))

def sanitize_input(text, max_length=100):
    """Sanitize user input against XSS and injection"""
    if not text:
        return ""
    # Remove dangerous characters
    text = re.sub(r'[<>"\'\(\);=]', '', str(text))
    return text. strip()[:max_length]

def format_number(num):
    """Human-readable number formatting"""
    if not num or not isinstance(num, (int, float)):
        return '0'
    try:
        num = int(num)
        if num >= 1000000000:
            return f"{num / 1000000000:.1f}B"
        if num >= 1000000:
            return f"{num / 1000000:.1f}M"
        if num >= 1000:
            return f"{num / 1000:.1f}K"
        return str(num)
    except:
        return '0'

def get_user_agent():
    """Random user agent for requests"""
    agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ]
    import random
    return random.choice(agents)