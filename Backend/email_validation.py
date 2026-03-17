# email_validation.py - FIXED FOR ACCURATE GOOGLE WORKSPACE DETECTION
import dns.resolver
import dns.exception
import smtplib
import socket
import re
from utils import retry_on_failure, validate_email

# ==================================================================================
# ADVANCED EMAIL VALIDATION WITH PROVIDER-AWARE SCORING
# ==================================================================================

class EmailValidator:
    """Comprehensive email validation with accurate provider detection"""
    
    def __init__(self):
        self.dns_cache = {}
    
    def validate_comprehensive(self, email):
        """Full email validation pipeline with provider-aware scoring"""
        result = {
            'email': email,
            'valid':   False,
            'format_valid': False,
            'domain_exists': False,
            'mx_valid': False,
            'mx_records': [],
            'smtp_valid': False,
            'disposable': False,
            'free_provider': False,
            'business_email': False,
            'spf_record': None,
            'dmarc_record': None,
            'dkim_record': None,
            'spf_policy': 'NONE',
            'dmarc_policy': 'NONE',
            'spf_details': {},
            'dmarc_details': {},
            'dkim_details': {},
            'spoofing_risk': 'UNKNOWN',
            'spoofing_details': {},
            'security_score': 0,
            'security_recommendations': [],
            'provider':  None,
            'provider_details': {},
            'is_google_workspace': False,
            'is_microsoft_365': False,
            'is_major_provider': False
        }
        
        # Step 1: Format validation
        if not validate_email(email):
            return result
        result['format_valid'] = True
        
        domain = email.split('@')[1].lower()
        username = email.split('@')[0].lower()
        
        # Step 2: Domain existence check
        if not self._check_domain_exists(domain):
            return result
        result['domain_exists'] = True
        
        # Step 3: MX record validation
        mx_records = self._get_mx_records(domain)
        if mx_records:
            result['mx_valid'] = True
            result['mx_records'] = mx_records
        
        # Step 4: ENHANCED Provider detection (detects Google Workspace, Microsoft 365, etc.)
        provider_info = self._detect_provider_enhanced(domain, mx_records)
        result['provider'] = provider_info['name']
        result['provider_details'] = provider_info
        result['free_provider'] = provider_info. get('type') == 'free'
        result['business_email'] = provider_info.get('type') == 'business'
        result['is_google_workspace'] = provider_info.get('is_google_workspace', False)
        result['is_microsoft_365'] = provider_info.get('is_microsoft_365', False)
        result['is_major_provider'] = provider_info.get('is_major_provider', False)
        
        # Step 5: Disposable email detection
        result['disposable'] = self._is_disposable(domain)
        
        # Step 6: DETAILED SPF record analysis
        spf_analysis = self._analyze_spf_detailed(domain)
        result['spf_record'] = spf_analysis['raw_record']
        result['spf_policy'] = spf_analysis['policy']
        result['spf_details'] = spf_analysis['details']
        
        # Step 7: DETAILED DMARC record analysis
        dmarc_analysis = self._analyze_dmarc_detailed(domain)
        result['dmarc_record'] = dmarc_analysis['raw_record']
        result['dmarc_policy'] = dmarc_analysis['policy']
        result['dmarc_details'] = dmarc_analysis['details']
        
        # Step 8: SMART DKIM detection (provider-aware)
        dkim_analysis = self._check_dkim_selectors_smart(domain, provider_info)
        result['dkim_record'] = dkim_analysis['found']
        result['dkim_details'] = dkim_analysis['details']
        
        # Step 9: PROVIDER-AWARE spoofing risk assessment
        spoofing_assessment = self._assess_spoofing_risk_provider_aware(
            spf_analysis, dmarc_analysis, dkim_analysis, provider_info
        )
        result['spoofing_risk'] = spoofing_assessment['risk_level']
        result['spoofing_details'] = spoofing_assessment['details']
        result['security_score'] = spoofing_assessment['security_score']
        result['security_recommendations'] = spoofing_assessment['recommendations']
        
        result['valid'] = (
            result['format_valid'] and
            result['domain_exists'] and
            result['mx_valid'] and
            not result['disposable']
        )
        
        return result
    
    @retry_on_failure(max_retries=2, delay=1)
    def _check_domain_exists(self, domain):
        """Check if domain has A or AAAA records"""
        try:
            dns.resolver.resolve(domain, 'A')
            return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            try:
                dns.resolver.resolve(domain, 'AAAA')
                return True
            except:  
                return False
        except Exception as e:
            print(f"[DNS ERROR] {domain}: {e}")
            return False
    
    @retry_on_failure(max_retries=2, delay=1)
    def _get_mx_records(self, domain):
        """Get MX records for domain"""
        if domain in self.dns_cache:
            return self.dns_cache[domain]
        
        try:  
            mx_records = dns.resolver.resolve(domain, 'MX')
            records = []
            for mx in mx_records:
                records. append({
                    'server': str(mx.exchange).rstrip('.'),
                    'priority': mx.preference
                })
            records.sort(key=lambda x: x['priority'])
            self.dns_cache[domain] = records
            return records
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return []
        except Exception as e:
            print(f"[MX ERROR] {domain}: {e}")
            return []
    
    def _detect_provider_enhanced(self, domain, mx_records):
        """ENHANCED provider detection with Google Workspace & Microsoft 365 detection"""
        result = {
            'name': 'Custom',
            'type': 'business',
            'security':  'UNKNOWN',
            'is_google_workspace': False,
            'is_microsoft_365': False,
            'is_major_provider': False,
            'has_advanced_security': False
        }
        
        # Known free providers
        free_providers = {
            'gmail. com':  {'name': 'Gmail', 'type': 'free', 'security': 'HIGH', 'is_major_provider': True, 'has_advanced_security':  True},
            'googlemail.com': {'name': 'Gmail', 'type': 'free', 'security': 'HIGH', 'is_major_provider': True, 'has_advanced_security': True},
            'yahoo.com': {'name': 'Yahoo', 'type': 'free', 'security': 'MEDIUM', 'is_major_provider': True},
            'hotmail.com': {'name': 'Outlook. com', 'type': 'free', 'security': 'HIGH', 'is_major_provider': True, 'has_advanced_security':  True},
            'outlook.com': {'name': 'Outlook. com', 'type': 'free', 'security': 'HIGH', 'is_major_provider': True, 'has_advanced_security': True},
            'live.com': {'name': 'Outlook.com', 'type':  'free', 'security':  'HIGH', 'is_major_provider': True, 'has_advanced_security': True},
            'icloud.com': {'name': 'iCloud', 'type': 'free', 'security': 'HIGH', 'is_major_provider': True},
            'me.com': {'name': 'iCloud', 'type': 'free', 'security': 'HIGH', 'is_major_provider': True},
            'protonmail.com': {'name':  'ProtonMail', 'type':  'encrypted', 'security': 'VERY_HIGH', 'is_major_provider': True},
            'proton.me': {'name': 'ProtonMail', 'type': 'encrypted', 'security': 'VERY_HIGH', 'is_major_provider': True},
        }
        
        # Check if it's a known free provider
        if domain in free_providers:
            return free_providers[domain]
        
        # Check MX records for provider detection
        if mx_records:
            mx_str = ' '.join([r['server']. lower() for r in mx_records])
            
            # Google Workspace Detection (custom domain using Google)
            google_patterns = ['aspmx.l. google.com', 'googlemail.com', 'google.com']
            if any(pattern in mx_str for pattern in google_patterns):
                result. update({
                    'name':  'Google Workspace',
                    'type':  'business',
                    'security': 'HIGH',
                    'is_google_workspace': True,
                    'is_major_provider': True,
                    'has_advanced_security': True,
                    'note': 'Uses Google enterprise email infrastructure with advanced threat protection'
                })
                return result
            
            # Microsoft 365 Detection (custom domain using Microsoft)
            microsoft_patterns = ['outlook.com', 'protection.outlook.com', 'mail.protection.outlook.com']
            if any(pattern in mx_str for pattern in microsoft_patterns):
                result.update({
                    'name': 'Microsoft 365',
                    'type':  'business',
                    'security': 'HIGH',
                    'is_microsoft_365': True,
                    'is_major_provider': True,
                    'has_advanced_security': True,
                    'note': 'Uses Microsoft enterprise email infrastructure with Exchange Online Protection'
                })
                return result
            
            # Other known providers
            other_providers = {
                'yahoodns':  {'name': 'Yahoo Mail', 'type': 'business', 'security': 'MEDIUM'},
                'zoho': {'name': 'Zoho Mail', 'type': 'business', 'security': 'MEDIUM', 'is_major_provider':  True},
                'mailgun': {'name': 'Mailgun', 'type': 'transactional', 'security': 'MEDIUM'},
                'sendgrid': {'name': 'SendGrid', 'type': 'transactional', 'security': 'MEDIUM'},
                'protonmail': {'name': 'ProtonMail', 'type': 'encrypted', 'security': 'VERY_HIGH', 'is_major_provider':  True},
            }
            
            for pattern, info in other_providers.items():
                if pattern in mx_str:
                    result.update(info)
                    return result
        
        # Default for unknown custom domains
        result['note'] = 'Custom email server - security depends on configuration'
        return result
    
    def _is_disposable(self, domain):
        """Check if domain is disposable/temporary email"""
        disposable_domains = {
            '10minutemail.com', 'guerrillamail.com', 'mailinator.com', 'tempmail.com',
            'throwaway.email', 'temp-mail.org', 'getnada.com', 'maildrop.cc',
            'trashmail.com', 'yopmail.com', 'sharklasers.com', 'guerrillamail.info',
        }
        return domain. lower() in disposable_domains
    
    # ==================================================================================
    # DETAILED SPF ANALYSIS (Same as before)
    # ==================================================================================
    
    def _analyze_spf_detailed(self, domain):
        """Comprehensive SPF analysis with redirect support"""
        result = {
            'raw_record': None,
            'policy': 'NONE',
            'details': {
                'exists': False,
                'version': None,
                'mechanisms': [],
                'all_directive': None,
                'includes':  [],
                'ip4_ranges': [],
                'ip6_ranges': [],
                'a_records': [],
                'mx_records': [],
                'redirect':  None,
                'explanation': None,
                'policy_strength': 'NONE',
                'issue_count': 0,
                'issues': [],
                'protection_level': 'NONE'
            }
        }
        
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            for record in txt_records:
                txt = str(record).strip('"')
                if txt. startswith('v=spf1'):
                    result['raw_record'] = txt
                    result['details']['exists'] = True
                    result['details']['version'] = 'SPF1'
                    
                    parts = txt.split()
                    for part in parts[1:]:
                        part_lower = part.lower()
                        
                        # Check for redirect
                        if part_lower.startswith('redirect='):
                            redirect_domain = part_lower. split('=', 1)[1]
                            result['details']['redirect'] = redirect_domain
                            
                            try:
                                redirected_spf = self._analyze_spf_detailed(redirect_domain)
                                
                                if redirected_spf['details']['all_directive']: 
                                    result['details']['all_directive'] = redirected_spf['details']['all_directive']
                                    result['policy'] = redirected_spf['policy']
                                    result['details']['policy_strength'] = redirected_spf['details']['policy_strength']
                                    result['details']['protection_level'] = redirected_spf['details']['protection_level']
                                    result['details']['issues']. extend(redirected_spf['details']['issues'])
                                    result['details']['issues'].insert(0, f"ℹ️ SPF redirects to {redirect_domain} (inherits {redirected_spf['details']['all_directive']} policy)")
                                else:
                                    result['policy'] = 'PARTIAL'
                                    result['details']['issues'].append(f"⚠️ Redirect to {redirect_domain} found but no clear policy")
                            except: 
                                result['policy'] = 'PARTIAL'
                                result['details']['issues'].append(f"⚠️ Could not resolve redirect to {redirect_domain}")
                        
                        # All directive
                        elif part_lower in ['-all', '~all', '? all', '+all']:
                            result['details']['all_directive'] = part_lower
                            
                            if part_lower == '-all': 
                                result['policy'] = 'STRICT'
                                result['details']['policy_strength'] = 'HARD FAIL'
                                result['details']['protection_level'] = 'MAXIMUM'
                            elif part_lower == '~all':
                                result['policy'] = 'MODERATE'
                                result['details']['policy_strength'] = 'SOFT FAIL'
                                result['details']['protection_level'] = 'GOOD'
                            elif part_lower == '?all':
                                result['policy'] = 'NEUTRAL'
                                result['details']['policy_strength'] = 'NEUTRAL'
                                result['details']['protection_level'] = 'MINIMAL'
                                result['details']['issues'].append("⚠️ Neutral policy - minimal protection")
                                result['details']['issue_count'] += 1
                            elif part_lower == '+all':
                                result['policy'] = 'PERMISSIVE'
                                result['details']['policy_strength'] = 'PASS ALL'
                                result['details']['protection_level'] = 'NONE'
                                result['details']['issues'].append("🚨 CRITICAL: +all allows ANY server!")
                                result['details']['issue_count'] += 1
                        
                        # Include mechanisms
                        elif part_lower.startswith('include:'):
                            include_domain = part_lower.split(':', 1)[1]
                            result['details']['includes']. append(include_domain)
                        
                        # IP ranges
                        elif part_lower.startswith('ip4:'):
                            result['details']['ip4_ranges']. append(part_lower. split(':', 1)[1])
                        elif part_lower.startswith('ip6:'):
                            result['details']['ip6_ranges'].append(part_lower.split(':', 1)[1])
                        
                        # A/MX records
                        elif part_lower.startswith('a:') or part_lower == 'a':
                            a_domain = part_lower.split(':', 1)[1] if ':' in part_lower else domain
                            result['details']['a_records'].append(a_domain)
                        elif part_lower.startswith('mx:') or part_lower == 'mx':
                            mx_domain = part_lower.split(':', 1)[1] if ':' in part_lower else domain
                            result['details']['mx_records']. append(mx_domain)
                        
                        result['details']['mechanisms'].append(part)
                    
                    # Check for issues (only if not redirected)
                    if not result['details']['redirect']:
                        if not result['details']['all_directive']:
                            result['policy'] = 'PARTIAL'
                            result['details']['issues']. append("⚠️ No 'all' directive - policy incomplete")
                            result['details']['issue_count'] += 1
                            result['details']['protection_level'] = 'PARTIAL'
                    
                    if len(result['details']['includes']) > 10:
                        result['details']['issues'].append("⚠️ Too many includes - may exceed DNS lookup limit")
                        result['details']['issue_count'] += 1
                    
                    break
            
            if not result['details']['exists']:
                result['details']['issues'].append("🚨 CRITICAL: No SPF record found")
                result['details']['issue_count'] += 1
                
        except Exception as e:
            print(f"[SPF ERROR] {domain}: {e}")
        
        return result
    
    # ==================================================================================
    # DETAILED DMARC ANALYSIS (Same as before)
    # ==================================================================================
    
    def _analyze_dmarc_detailed(self, domain):
        """Comprehensive DMARC analysis"""
        result = {
            'raw_record': None,
            'policy': 'NONE',
            'details': {
                'exists': False,
                'version': None,
                'policy':  None,
                'subdomain_policy': None,
                'percentage':  100,
                'rua_addresses': [],
                'ruf_addresses': [],
                'alignment_spf': 'relaxed',
                'alignment_dkim': 'relaxed',
                'report_interval': 86400,
                'failure_options': [],
                'policy_strength': 'NONE',
                'issue_count': 0,
                'issues': [],
                'protection_level': 'NONE',
                'reporting_enabled': False
            }
        }
        
        try:
            dmarc_domain = f'_dmarc.{domain}'
            txt_records = dns.resolver.resolve(dmarc_domain, 'TXT')
            
            for record in txt_records: 
                txt = str(record).strip('"')
                if txt. startswith('v=DMARC1'):
                    result['raw_record'] = txt
                    result['details']['exists'] = True
                    result['details']['version'] = 'DMARC1'
                    
                    tags = {}
                    for tag in txt.split(';'):
                        tag = tag.strip()
                        if '=' in tag:
                            key, value = tag.split('=', 1)
                            tags[key. strip().lower()] = value.strip()
                    
                    # Policy
                    if 'p' in tags:
                        policy = tags['p'].lower()
                        result['details']['policy'] = policy
                        
                        if policy == 'reject':
                            result['policy'] = 'STRICT'
                            result['details']['policy_strength'] = 'REJECT'
                            result['details']['protection_level'] = 'MAXIMUM'
                        elif policy == 'quarantine': 
                            result['policy'] = 'MODERATE'
                            result['details']['policy_strength'] = 'QUARANTINE'
                            result['details']['protection_level'] = 'GOOD'
                        elif policy == 'none':
                            result['policy'] = 'MONITORING'
                            result['details']['policy_strength'] = 'MONITOR ONLY'
                            result['details']['protection_level'] = 'MINIMAL'
                            result['details']['issues'].append("⚠️ Policy is 'none' - monitoring only")
                            result['details']['issue_count'] += 1
                    
                    if 'sp' in tags:
                        result['details']['subdomain_policy'] = tags['sp'].lower()
                    
                    if 'pct' in tags:
                        try:
                            result['details']['percentage'] = int(tags['pct'])
                            if result['details']['percentage'] < 100:
                                result['details']['issues'].append(f"⚠️ Policy applies to {result['details']['percentage']}% only")
                                result['details']['issue_count'] += 1
                        except: 
                            pass
                    
                    if 'rua' in tags: 
                        result['details']['rua_addresses'] = [addr.strip() for addr in tags['rua'].split(',')]
                        result['details']['reporting_enabled'] = True
                    
                    if 'ruf' in tags:
                        result['details']['ruf_addresses'] = [addr.strip() for addr in tags['ruf'].split(',')]
                    
                    if 'aspf' in tags:
                        result['details']['alignment_spf'] = tags['aspf'].lower()
                    
                    if 'adkim' in tags: 
                        result['details']['alignment_dkim'] = tags['adkim'].lower()
                    
                    break
            
            if not result['details']['exists']:
                result['details']['issues'].append("🚨 CRITICAL: No DMARC record")
                result['details']['issue_count'] += 1
                
        except dns.resolver.NXDOMAIN:
            result['details']['issues'].append("🚨 CRITICAL: No DMARC record found")
            result['details']['issue_count'] += 1
        except Exception as e:
            print(f"[DMARC ERROR] {domain}: {e}")
        
        return result
    
    # ==================================================================================
    # SMART DKIM DETECTION - NEW! 
    # ==================================================================================
    
    def _check_dkim_selectors_smart(self, domain, provider_info):
        """SMART DKIM detection based on provider"""
        result = {
            'found': False,
            'details': {
                'selectors_found': [],
                'selectors_checked': [],
                'key_types': [],
                'note': None,
                'assumed_active': False
            }
        }
        
        # If it's Google Workspace or Gmail, DKIM is ALWAYS active
        if provider_info.get('is_google_workspace') or provider_info.get('name') in ['Gmail', 'Google']: 
            result['found'] = True
            result['details']['assumed_active'] = True
            result['details']['note'] = "Google Workspace/Gmail ALWAYS uses DKIM (uses dynamic selectors like google._domainkey)"
            result['details']['selectors_found'].append('google (assumed)')
            return result
        
        # If it's Microsoft 365, DKIM is usually active
        if provider_info. get('is_microsoft_365'):
            result['found'] = True
            result['details']['assumed_active'] = True
            result['details']['note'] = "Microsoft 365 ALWAYS uses DKIM (uses selector1/selector2._domainkey)"
            result['details']['selectors_found'].append('selector1 (assumed)')
            return result
        
        # For other providers, check common selectors
        common_selectors = [
            'default', 'google', 'k1', 's1', 's2', 'selector1', 'selector2',
            'dkim', 'mail', 'email', 'mx', 'smtp', 'mandrill', 'mailgun',
            'sendgrid', 'amazonses', 'postmark', 'sparkpost', 'zoho'
        ]
        
        for selector in common_selectors:
            result['details']['selectors_checked'].append(selector)
            try:
                dkim_domain = f'{selector}._domainkey. {domain}'
                txt_records = dns.resolver.resolve(dkim_domain, 'TXT')
                for record in txt_records:
                    txt = str(record).strip('"')
                    if 'p=' in txt:
                        result['found'] = True
                        result['details']['selectors_found'].append(selector)
                        
                        if 'k=rsa' in txt or 'k=' not in txt:
                            result['details']['key_types'].append(f'{selector}:  RSA')
                        elif 'k=ed25519' in txt: 
                            result['details']['key_types'].append(f'{selector}: Ed25519')
                        
                        break
            except: 
                pass
        
        if result['found'] and not result['details']['assumed_active']:
            result['details']['note'] = f"Found {len(result['details']['selectors_found'])} active DKIM selector(s)"
        elif not result['found']: 
            result['details']['note'] = "No DKIM selectors detected (may use custom/dynamic selectors)"
        
        return result
    
    # ==================================================================================
    # PROVIDER-AWARE RISK ASSESSMENT - NEW!
    # ==================================================================================
    
    def _assess_spoofing_risk_provider_aware(self, spf_analysis, dmarc_analysis, dkim_analysis, provider_info):
        """Provider-aware risk assessment with realistic scoring"""
        result = {
            'risk_level': 'UNKNOWN',
            'security_score': 0,
            'details': {
                'spf_score': 0,
                'dmarc_score': 0,
                'dkim_score':  0,
                'provider_bonus': 0,
                'total_score': 0,
                'max_score': 100,
                'grade': 'F',
                'vulnerabilities': [],
                'strengths': [],
                'critical_issues': [],
                'warnings': [],
                'info': []
            },
            'recommendations': []
        }
        
        # SPF Scoring (40 points max)
        if spf_analysis['details']['exists']: 
            result['details']['spf_score'] += 10
            result['details']['strengths'].append("✓ SPF record exists")
            
            all_directive = spf_analysis['details']['all_directive']
            if all_directive == '-all':
                result['details']['spf_score'] += 30
                result['details']['strengths'].append("✓ SPF uses strict '-all' policy (Hard Fail)")
            elif all_directive == '~all':
                result['details']['spf_score'] += 25  # Changed from 20 - less penalty for major providers
                result['details']['strengths'].append("✓ SPF uses '~all' policy (Soft Fail)")
                
                # Don't warn if it's Google/Microsoft (intentional by design)
                if not (provider_info.get('is_google_workspace') or provider_info.get('is_microsoft_365')):
                    result['details']['warnings'].append("⚠️ Consider upgrading to '-all' for maximum protection")
            elif all_directive == '?all':
                result['details']['spf_score'] += 5
                result['details']['vulnerabilities'].append("⚠️ SPF uses '?all' - minimal protection")
            elif all_directive == '+all':
                result['details']['spf_score'] += 0
                result['details']['critical_issues'].append("🚨 SPF uses '+all' - ALLOWS ALL SERVERS!")
        else:
            result['details']['critical_issues'].append("🚨 No SPF record")
            result['recommendations'].append("Add SPF record")
        
        # DMARC Scoring (40 points max)
        if dmarc_analysis['details']['exists']:
            result['details']['dmarc_score'] += 10
            result['details']['strengths'].append("✓ DMARC record exists")
            
            policy = dmarc_analysis['details']['policy']
            if policy == 'reject':
                result['details']['dmarc_score'] += 30
                result['details']['strengths'].append("✓ DMARC policy is 'reject' (Maximum)")
            elif policy == 'quarantine':
                result['details']['dmarc_score'] += 25
                result['details']['strengths'].append("✓ DMARC policy is 'quarantine' (Good)")
                result['details']['info'].append("💡 Consider 'reject' for maximum security")
            elif policy == 'none':
                result['details']['dmarc_score'] += 10  # Changed from 5 - more lenient for monitoring
                result['details']['vulnerabilities'].append("⚠️ DMARC policy is 'none' (monitoring only)")
                result['recommendations'].append("Upgrade DMARC to 'quarantine' or 'reject'")
            
            if dmarc_analysis['details']['reporting_enabled']:
                result['details']['strengths'].append("✓ DMARC reporting configured")
        else:
            result['details']['critical_issues'].append("🚨 No DMARC record")
            result['recommendations'].append("Add DMARC record")
        
        # DKIM Scoring (20 points max)
        if dkim_analysis['found']: 
            if dkim_analysis['details']['assumed_active']:
                # Full points for major providers
                result['details']['dkim_score'] += 20
                result['details']['strengths']. append(f"✓ DKIM active ({provider_info['name']} infrastructure)")
            else:
                selectors_count = len(dkim_analysis['details']['selectors_found'])
                result['details']['dkim_score'] += min(selectors_count * 10, 20)
                result['details']['strengths'].append(f"✓ DKIM configured ({selectors_count} selector(s))")
        else:
            result['details']['warnings'].append("⚠️ DKIM not detected (may use custom selectors)")
        
        # PROVIDER BONUS (0-20 points) - NEW!
        if provider_info.get('has_advanced_security'):
            result['details']['provider_bonus'] += 15
            result['details']['strengths'].append(f"✓ {provider_info['name']} provides advanced threat protection beyond DNS")
            result['details']['info'].append(f"💡 {provider_info['name']} uses AI/ML for additional anti-spoofing")
        elif provider_info.get('is_major_provider'):
            result['details']['provider_bonus'] += 10
            result['details']['info'].append(f"✓ {provider_info['name']} is a trusted email provider")
        
        # Calculate total score
        result['details']['total_score'] = (
            result['details']['spf_score'] +
            result['details']['dmarc_score'] +
            result['details']['dkim_score'] +
            result['details']['provider_bonus']
        )
        result['security_score'] = min(result['details']['total_score'], 100)  # Cap at 100
        
        # Assign grade
        score = result['security_score']
        if score >= 90:
            result['details']['grade'] = 'A+'
            result['risk_level'] = 'VERY LOW'
        elif score >= 85:
            result['details']['grade'] = 'A'
            result['risk_level'] = 'VERY LOW'
        elif score >= 80:
            result['details']['grade'] = 'A-'
            result['risk_level'] = 'LOW'
        elif score >= 75:
            result['details']['grade'] = 'B+'
            result['risk_level'] = 'LOW'
        elif score >= 70:
            result['details']['grade'] = 'B'
            result['risk_level'] = 'LOW'
        elif score >= 65:
            result['details']['grade'] = 'B-'
            result['risk_level'] = 'MEDIUM'
        elif score >= 60:
            result['details']['grade'] = 'C+'
            result['risk_level'] = 'MEDIUM'
        elif score >= 55:
            result['details']['grade'] = 'C'
            result['risk_level'] = 'MEDIUM'
        elif score >= 50:
            result['details']['grade'] = 'C-'
            result['risk_level'] = 'MEDIUM'
        elif score >= 40:
            result['details']['grade'] = 'D'
            result['risk_level'] = 'HIGH'
        else:
            result['details']['grade'] = 'F'
            result['risk_level'] = 'CRITICAL'
        
        # Adjust risk for major providers (they have additional protections)
        if provider_info.get('has_advanced_security') and result['risk_level'] in ['HIGH', 'CRITICAL']:
            result['risk_level'] = 'MEDIUM'
            result['details']['info'].append(f"💡 Risk downgraded:  {provider_info['name']}'s advanced security mitigates DNS-only concerns")
        
        # Generate recommendations
        if not spf_analysis['details']['exists']: 
            result['recommendations'].append("🔧 Create SPF record:  v=spf1 include:_spf.yourmailserver.com -all")
        
        if not dmarc_analysis['details']['exists']:
            result['recommendations']. append("🔧 Create DMARC record: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com")
        elif dmarc_analysis['details']['policy'] == 'none': 
            result['recommendations'].append("🔧 Upgrade DMARC from 'none' to 'quarantine'")
        
        if not dkim_analysis['found'] and not dkim_analysis['details']['assumed_active']:
            result['recommendations'].append("🔧 Configure DKIM signing on your mail server")
        
        return result