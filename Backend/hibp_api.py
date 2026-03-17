# hibp_api.py
import requests
import time
import hashlib
from utils import retry_on_failure, get_user_agent

# ==================================================================================
# HAVE I BEEN PWNED (HIBP) API INTEGRATION
# Real-time breach checking with official API
# ==================================================================================

class HIBPClient:
    """Official Have I Been Pwned API Client"""
    
    BASE_URL = "https://api.pwnedpasswords.com/range/"
    BREACH_API = "https://haveibeenpwned.com/api/v3/breachedaccount/"
    
    def __init__(self, api_key=None):
        """
        Initialize HIBP client
        API key optional for basic checks, required for email breach search
        Get free API key:  https://haveibeenpwned.com/API/Key
        """
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': get_user_agent(),
            'Accept': 'application/json'
        })
        if api_key:
            self. session.headers. update({'hibp-api-key': api_key})
    
    @retry_on_failure(max_retries=2, delay=1)
    def check_email_breaches(self, email):
        """
        Check if email appears in any breaches using HIBP API
        Returns list of breach objects with full details
        """
        if not self.api_key:
            print("[HIBP] No API key - using fallback local database")
            return None
        
        try:
            url = f"{self. BREACH_API}{email}? truncateResponse=false"
            response = self.session.get(url, timeout=10)
            
            # Rate limit handling
            if response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', 2))
                time.sleep(retry_after)
                response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                breaches = response.json()
                return self._parse_hibp_breaches(breaches)
            elif response.status_code == 404:
                # No breaches found - good news!
                return []
            else:
                print(f"[HIBP ERROR] Status {response.status_code}")
                return None
                
        except Exception as e:
            print(f"[HIBP ERROR] {e}")
            return None
    
    def _parse_hibp_breaches(self, breaches):
        """Parse HIBP API response into our format"""
        parsed = []
        for breach in breaches:
            parsed.append({
                'name': breach. get('Name', 'Unknown'),
                'title': breach.get('Title', breach.get('Name', 'Unknown')),
                'domain': breach.get('Domain', ''),
                'date': breach.get('BreachDate', 'Unknown'),
                'added_date': breach.get('AddedDate', ''),
                'modified_date': breach.get('ModifiedDate', ''),
                'records': breach.get('PwnCount', 0),
                'description': breach.get('Description', '').replace('</', '').replace('<', '').replace('>', ''),
                'data_types': breach.get('DataClasses', []),
                'is_verified': breach.get('IsVerified', False),
                'is_fabricated': breach.get('IsFabricated', False),
                'is_sensitive': breach.get('IsSensitive', False),
                'is_retired': breach.get('IsRetired', False),
                'is_spam_list': breach.get('IsSpamList', False),
                'logo_path': breach.get('LogoPath', ''),
                'severity': self._calculate_severity(breach),
                'source': 'HIBP_API'
            })
        return parsed
    
    def _calculate_severity(self, breach):
        """Calculate breach severity based on data types and verification"""
        data_classes = [dc.lower() for dc in breach.get('DataClasses', [])]
        is_verified = breach. get('IsVerified', False)
        pwn_count = breach.get('PwnCount', 0)
        
        score = 0
        
        # Data type scoring
        if any(x in data_classes for x in ['passwords', 'password']):
            score += 40
        if any(x in data_classes for x in ['credit cards', 'bank account']):
            score += 35
        if any(x in data_classes for x in ['social security numbers', 'national ids']):
            score += 35
        if any(x in data_classes for x in ['phone numbers', 'physical addresses']):
            score += 15
        if any(x in data_classes for x in ['security questions', 'answers']):
            score += 20
        
        # Verification bonus
        if is_verified: 
            score += 10
        
        # Volume impact
        if pwn_count > 100000000:  # 100M+
            score += 15
        elif pwn_count > 10000000:  # 10M+
            score += 10
        elif pwn_count > 1000000:  # 1M+
            score += 5
        
        # Severity levels
        if score >= 70:
            return 'CRITICAL'
        elif score >= 50:
            return 'HIGH'
        elif score >= 30:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def check_password_hash(self, password):
        """
        Check if password has been pwned using k-anonymity
        Never sends full password - only first 5 chars of SHA1 hash
        """
        try:
            # SHA1 hash of password
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            
            # Query API with prefix only
            url = f"{self. BASE_URL}{prefix}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                # Check if our suffix appears in results
                hashes = response.text.splitlines()
                for line in hashes:
                    hash_suffix, count = line.split(': ')
                    if hash_suffix == suffix:
                        return int(count)  # Times password was pwned
                return 0  # Not found - safe! 
            else:
                return None
                
        except Exception as e:
            print(f"[HIBP PASSWORD CHECK ERROR] {e}")
            return None

# ==================================================================================
# HYBRID BREACH CHECKER - Combines Local DB + HIBP API
# ==================================================================================

def check_breaches_hybrid(email, local_database, hibp_api_key=None):
    """
    Hybrid approach: Use HIBP API if available, fallback to local DB
    Returns comprehensive breach analysis
    """
    result = {
        'breached':  False,
        'total_breaches': 0,
        'total_records_exposed': 0,
        'breaches':  [],
        'risk_level': 'NONE',
        'recommendations': [],
        'exposure_timeline': [],
        'data_types_exposed': set(),
        'verified_breaches': 0,
        'source': 'HYBRID'
    }
    
    # Try HIBP API first
    hibp_breaches = None
    if hibp_api_key: 
        client = HIBPClient(api_key=hibp_api_key)
        hibp_breaches = client.check_email_breaches(email)
    
    # Use HIBP data if available
    if hibp_breaches is not None:
        result['breaches'] = hibp_breaches
        result['source'] = 'HIBP_API'
        print(f"[HIBP] Found {len(hibp_breaches)} breaches for {email}")
    else:
        # Fallback to local database (domain-based only)
        print(f"[LOCAL DB] Using local breach database for {email}")
        if '@' in email:
            domain = email.split('@')[1].lower()
            if domain in local_database:
                result['breaches'] = local_database[domain]
                result['source'] = 'LOCAL_DB'
    
    # Calculate statistics
    for breach in result['breaches']: 
        if not breach. get('is_spam_list', False) and not breach.get('is_fabricated', False):
            result['total_breaches'] += 1
            result['total_records_exposed'] += breach.get('records', 0)
            result['data_types_exposed'].update(breach.get('data_types', []))
            
            if breach.get('is_verified', True):
                result['verified_breaches'] += 1
            
            date = breach.get('date', 'N/A')
            if date != 'N/A':
                result['exposure_timeline'].append({
                    'date': date,
                    'breach':  breach. get('name', 'Unknown')
                })
    
    result['breached'] = result['total_breaches'] > 0
    result['data_types_exposed'] = list(result['data_types_exposed'])
    
    # Risk level calculation
    critical_count = len([b for b in result['breaches'] if b.get('severity') == 'CRITICAL'])
    high_count = len([b for b in result['breaches'] if b.get('severity') == 'HIGH'])
    
    if critical_count >= 2 or result['total_records_exposed'] > 500000000:
        result['risk_level'] = 'CRITICAL'
    elif critical_count >= 1 or high_count >= 2:
        result['risk_level'] = 'HIGH'
    elif high_count >= 1 or result['total_breaches'] >= 2:
        result['risk_level'] = 'MEDIUM'
    elif result['total_breaches'] >= 1:
        result['risk_level'] = 'LOW'
    
    # Generate recommendations
    data_types_str = str(result['data_types_exposed']).lower()
    if 'password' in data_types_str: 
        result['recommendations'].append("🚨 URGENT: Change password immediately on all accounts")
        result['recommendations'].append("Enable Two-Factor Authentication (2FA) everywhere")
    if 'phone' in data_types_str or 'mobile' in data_types_str:
        result['recommendations'].append("Enable 2FA using authenticator app instead of SMS")
    if 'credit card' in data_types_str or 'bank' in data_types_str: 
        result['recommendations'].append("Monitor bank statements and credit reports")
        result['recommendations'].append("Consider placing fraud alert on credit file")
    if 'security question' in data_types_str:
        result['recommendations'].append("Update security questions with non-guessable answers")
    if result['risk_level'] in ['CRITICAL', 'HIGH']: 
        result['recommendations'].append("Use a password manager with unique passwords")
        result['recommendations'].append("Check for identity theft and unauthorized accounts")
    
    # Sort timeline
    result['exposure_timeline']. sort(key=lambda x: x['date'] if x['date'] != 'N/A' else '9999')
    
    return result