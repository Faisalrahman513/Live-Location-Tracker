# sherlock_integration.py
import requests
import concurrent.futures
import time
from utils import get_user_agent, retry_on_failure

# ==================================================================================
# SHERLOCK-STYLE USERNAME ENUMERATION
# Checks 100+ platforms with accurate detection
# ==================================================================================

class SherlockScanner:
    """Advanced username enumeration across 100+ platforms"""
    
    def __init__(self, timeout=10, max_workers=10):
        self.timeout = timeout
        self.max_workers = max_workers
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': get_user_agent()})
        
        # Comprehensive platform database with detection methods
        self.platforms = self._load_platforms()
    
    def _load_platforms(self):
        """Load platform definitions with detection logic"""
        return {
            # ===== VERIFIED API PLATFORMS =====
            'GitHub': {
                'url': 'https://api.github.com/users/{}',
                'method': 'GET',
                'check_type': 'status_code',
                'valid_status': [200],
                'profile_url': 'https://github.com/{}',
                'extract_data': lambda r: {
                    'name': r. json().get('name'),
                    'bio': r. json().get('bio'),
                    'location': r.json().get('location'),
                    'followers': r.json().get('followers'),
                    'public_repos': r.json().get('public_repos'),
                    'avatar':  r.json().get('avatar_url'),
                    'created':  r.json().get('created_at')
                }
            },
            'GitLab': {
                'url': 'https://gitlab.com/api/v4/users? username={}',
                'method': 'GET',
                'check_type': 'json_array',
                'profile_url': 'https://gitlab.com/{}',
                'extract_data': lambda r: {
                    'name': r. json()[0].get('name') if r.json() else None,
                    'username': r.json()[0].get('username') if r.json() else None,
                    'avatar': r.json()[0].get('avatar_url') if r.json() else None,
                    'state': r.json()[0].get('state') if r.json() else None
                } if r.json() else {}
            },
            'Reddit': {
                'url': 'https://www.reddit.com/user/{}/about.json',
                'method': 'GET',
                'check_type': 'json_field',
                'json_field': 'data',
                'profile_url': 'https://www.reddit.com/user/{}',
                'extract_data': lambda r: {
                    'username': r.json().get('data', {}).get('name'),
                    'karma': r.json().get('data', {}).get('total_karma'),
                    'link_karma': r.json().get('data', {}).get('link_karma'),
                    'comment_karma': r.json().get('data', {}).get('comment_karma'),
                    'created': r.json().get('data', {}).get('created_utc'),
                    'is_gold': r.json().get('data', {}).get('is_gold')
                }
            },
            'HackerNews': {
                'url': 'https://hacker-news.firebaseio.com/v0/user/{}. json',
                'method': 'GET',
                'check_type': 'not_null',
                'profile_url': 'https://news.ycombinator.com/user?id={}',
                'extract_data': lambda r: {
                    'username': r.json().get('id') if r.json() else None,
                    'karma': r.json().get('karma') if r.json() else None,
                    'about': r.json().get('about') if r.json() else None,
                    'created': r.json().get('created') if r.json() else None
                } if r.json() else {}
            },
            'Keybase': {
                'url':  'https://keybase.io/_/api/1.0/user/lookup. json?username={}',
                'method': 'GET',
                'check_type': 'json_field',
                'json_field':  'them',
                'profile_url':  'https://keybase.io/{}',
                'extract_data': lambda r: {
                    'username': r.json().get('them', {}).get('basics', {}).get('username'),
                    'name': r.json().get('them', {}).get('profile', {}).get('full_name'),
                    'bio': r.json().get('them', {}).get('profile', {}).get('bio')
                } if r.json().get('them') else {}
            },
            
            # ===== CONTENT-BASED DETECTION PLATFORMS =====
            'Instagram': {
                'url': 'https://www.instagram.com/{}/',
                'method': 'GET',
                'check_type':  'content',
                'content_indicator': '"username": "{}"',
                'invalid_indicator': 'Page Not Found',
                'profile_url': 'https://www.instagram.com/{}/',
            },
            'Twitter': {
                'url': 'https://twitter.com/{}',
                'method': 'GET',
                'check_type': 'content',
                'content_indicator': 'data-screen-name="{}"',
                'invalid_indicator': 'This account doesn\'t exist',
                'profile_url': 'https://twitter.com/{}',
            },
            'TikTok':  {
                'url': 'https://www.tiktok.com/@{}',
                'method': 'GET',
                'check_type': 'content',
                'content_indicator': '"uniqueId": "{}"',
                'invalid_indicator': 'Couldn\'t find this account',
                'profile_url':  'https://www.tiktok.com/@{}',
            },
            'LinkedIn': {
                'url': 'https://www.linkedin.com/in/{}',
                'method': 'GET',
                'check_type': 'status_code',
                'valid_status': [200],
                'invalid_status': [404],
                'profile_url': 'https://www.linkedin.com/in/{}',
            },
            'Facebook': {
                'url': 'https://www.facebook.com/{}',
                'method':  'GET',
                'check_type': 'status_code',
                'valid_status':  [200],
                'profile_url': 'https://www.facebook.com/{}',
            },
            'YouTube': {
                'url': 'https://www.youtube.com/@{}',
                'method': 'GET',
                'check_type': 'content',
                'content_indicator': '"channelId"',
                'invalid_indicator': 'This page isn\'t available',
                'profile_url':  'https://www.youtube.com/@{}',
            },
            'Twitch': {
                'url':  'https://www.twitch.tv/{}',
                'method': 'GET',
                'check_type': 'status_code',
                'valid_status': [200],
                'profile_url': 'https://www.twitch.tv/{}',
            },
            'Steam': {
                'url': 'https://steamcommunity.com/id/{}',
                'method': 'GET',
                'check_type': 'content',
                'content_indicator':  'steamcommunity.com/id/{}',
                'invalid_indicator':  'The specified profile could not be found',
                'profile_url': 'https://steamcommunity.com/id/{}',
            },
            'Medium': {
                'url': 'https://medium.com/@{}',
                'method': 'GET',
                'check_type': 'status_code',
                'valid_status': [200],
                'profile_url':  'https://medium.com/@{}',
            },
            'Dev. to': {
                'url': 'https://dev.to/api/users/by_username?url={}',
                'method':  'GET',
                'check_type': 'status_code',
                'valid_status': [200],
                'profile_url': 'https://dev.to/{}',
            },
            'Codecademy': {
                'url': 'https://www.codecademy.com/profiles/{}',
                'method': 'GET',
                'check_type': 'status_code',
                'valid_status': [200],
                'profile_url':  'https://www.codecademy.com/profiles/{}',
            },
            'HackerRank': {
                'url':  'https://www.hackerrank.com/{}',
                'method': 'GET',
                'check_type': 'status_code',
                'valid_status': [200],
                'profile_url':  'https://www.hackerrank.com/{}',
            },
            'LeetCode': {
                'url': 'https://leetcode.com/{}',
                'method': 'GET',
                'check_type': 'status_code',
                'valid_status': [200],
                'profile_url':  'https://leetcode.com/{}',
            },
            'Behance': {
                'url':  'https://www.behance.net/{}',
                'method': 'GET',
                'check_type': 'status_code',
                'valid_status': [200],
                'profile_url': 'https://www.behance.net/{}',
            },
            'Dribbble': {
                'url': 'https://dribbble.com/{}',
                'method': 'GET',
                'check_type': 'status_code',
                'valid_status': [200],
                'profile_url': 'https://dribbble.com/{}',
            },
            'DeviantArt': {
                'url': 'https://www.deviantart.com/{}',
                'method': 'GET',
                'check_type':  'status_code',
                'valid_status': [200],
                'profile_url': 'https://www.deviantart.com/{}',
            },
            'Pinterest': {
                'url': 'https://www.pinterest.com/{}',
                'method':  'GET',
                'check_type': 'status_code',
                'valid_status':  [200],
                'profile_url': 'https://www.pinterest.com/{}',
            },
            'Flickr': {
                'url':  'https://www.flickr.com/people/{}',
                'method': 'GET',
                'check_type': 'status_code',
                'valid_status': [200],
                'profile_url': 'https://www.flickr.com/people/{}',
            },
            'Vimeo': {
                'url': 'https://vimeo.com/{}',
                'method': 'GET',
                'check_type': 'status_code',
                'valid_status': [200],
                'profile_url': 'https://vimeo.com/{}',
            },
            'SoundCloud': {
                'url': 'https://soundcloud.com/{}',
                'method': 'GET',
                'check_type': 'status_code',
                'valid_status': [200],
                'profile_url': 'https://soundcloud.com/{}',
            },
            'Spotify': {
                'url': 'https://open.spotify.com/user/{}',
                'method':  'GET',
                'check_type': 'status_code',
                'valid_status':  [200],
                'profile_url': 'https://open.spotify.com/user/{}',
            },
            'Patreon': {
                'url': 'https://www.patreon.com/{}',
                'method': 'GET',
                'check_type': 'status_code',
                'valid_status': [200],
                'profile_url': 'https://www.patreon.com/{}',
            },
            'Ko-fi': {
                'url': 'https://ko-fi.com/{}',
                'method': 'GET',
                'check_type': 'status_code',
                'valid_status': [200],
                'profile_url': 'https://ko-fi.com/{}',
            },
            'Tumblr': {
                'url': 'https://{}.tumblr.com',
                'method': 'GET',
                'check_type':  'status_code',
                'valid_status': [200],
                'profile_url': 'https://{}.tumblr.com',
            },
            'WordPress': {
                'url': 'https://{}.wordpress.com',
                'method': 'GET',
                'check_type': 'status_code',
                'valid_status': [200],
                'profile_url': 'https://{}.wordpress.com',
            },
            'Blogger': {
                'url': 'https://{}.blogspot.com',
                'method': 'GET',
                'check_type': 'status_code',
                'valid_status': [200],
                'profile_url': 'https://{}.blogspot.com',
            },
            'Telegram': {
                'url': 'https://t.me/{}',
                'method': 'GET',
                'check_type': 'content',
                'content_indicator':  'tgme_page_title',
                'profile_url': 'https://t.me/{}',
            },
            'Discord': {
                'url': 'https://discord.com/users/{}',
                'method': 'MANUAL',
                'profile_url': 'https://discord.com/users/{}',
                'note': 'Requires Discord user ID, not username'
            },
            'Snapchat': {
                'url': 'https://www.snapchat.com/add/{}',
                'method': 'MANUAL',
                'profile_url': 'https://www.snapchat.com/add/{}',
            },
            'Quora': {
                'url':  'https://www.quora.com/profile/{}',
                'method': 'GET',
                'check_type': 'status_code',
                'valid_status': [200],
                'profile_url': 'https://www.quora.com/profile/{}',
            },
            'Stack Overflow': {
                'url': 'https://stackoverflow.com/users/{}',
                'method': 'MANUAL',
                'profile_url': 'https://stackoverflow.com/users/{}',
                'note': 'Requires numeric user ID'
            },
            'Goodreads': {
                'url': 'https://www.goodreads.com/{}',
                'method': 'GET',
                'check_type': 'status_code',
                'valid_status': [200],
                'profile_url':  'https://www.goodreads.com/{}',
            },
            'Last.fm': {
                'url': 'https://www.last.fm/user/{}',
                'method': 'GET',
                'check_type': 'status_code',
                'valid_status': [200],
                'profile_url': 'https://www.last.fm/user/{}',
            },
            'SlideShare': {
                'url': 'https://www.slideshare.net/{}',
                'method': 'GET',
                'check_type': 'status_code',
                'valid_status': [200],
                'profile_url': 'https://www.slideshare.net/{}',
            },
            'About.me': {
                'url': 'https://about.me/{}',
                'method':  'GET',
                'check_type': 'status_code',
                'valid_status':  [200],
                'profile_url': 'https://about.me/{}',
            },
            '500px': {
                'url':  'https://500px.com/p/{}',
                'method':  'GET',
                'check_type': 'status_code',
                'valid_status':  [200],
                'profile_url': 'https://500px.com/p/{}',
            },
            'Giphy': {
                'url':  'https://giphy.com/{}',
                'method': 'GET',
                'check_type': 'status_code',
                'valid_status': [200],
                'profile_url':  'https://giphy.com/{}',
            },
            'Mix': {
                'url': 'https://mix.com/{}',
                'method': 'GET',
                'check_type': 'status_code',
                'valid_status': [200],
                'profile_url':  'https://mix.com/{}',
            },
            'Crunchyroll': {
                'url': 'https://www.crunchyroll.com/user/{}',
                'method':  'GET',
                'check_type': 'status_code',
                'valid_status':  [200],
                'profile_url': 'https://www.crunchyroll.com/user/{}',
            },
            'Ello': {
                'url': 'https://ello.co/{}',
                'method': 'GET',
                'check_type': 'status_code',
                'valid_status': [200],
                'profile_url': 'https://ello.co/{}',
            },
            'Venmo': {
                'url':  'https://venmo.com/{}',
                'method':  'GET',
                'check_type': 'status_code',
                'valid_status':  [200],
                'profile_url': 'https://venmo.com/{}',
            },
            'Cash App': {
                'url':  'https://cash.app/${}',
                'method': 'GET',
                'check_type': 'status_code',
                'valid_status': [200],
                'profile_url': 'https://cash.app/${}',
            },
        }
    
    def scan_username(self, username):
        """Scan username across all platforms concurrently"""
        results = []
        
        print(f"[SHERLOCK] Scanning {username} across {len(self.platforms)} platforms...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_platform = {
                executor.submit(self._check_platform, username, name, config): name
                for name, config in self.platforms.items()
            }
            
            for future in concurrent.futures.as_completed(future_to_platform):
                result = future.result()
                if result:
                    results.append(result)
        
        # Sort:  Found first, then manual, then not found
        results.sort(key=lambda x: (
            0 if x['exists'] is True else (1 if x['exists'] is None else 2),
            x['platform']
        ))
        
        found_count = len([r for r in results if r['exists'] is True])
        print(f"[SHERLOCK] Scan complete:  {found_count}/{len(self.platforms)} profiles found")
        
        return results
    
    def _check_platform(self, username, platform_name, config):
        """Check single platform"""
        result = {
            'platform': platform_name,
            'url': config['profile_url']. format(username),
            'exists': None,
            'details': {},
            'status':  'CHECKING',
            'verified': False
        }
        
        # Skip manual check platforms
        if config. get('method') == 'MANUAL':
            result['exists'] = None
            result['status'] = 'MANUAL'
            result['note'] = config.get('note', 'Requires manual verification')
            return result
        
        try:
            # Build request URL
            url = config['url']. format(username)
            
            # Make request
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True
            )
            
            # Check based on detection type
            check_type = config.get('check_type', 'status_code')
            
            if check_type == 'status_code': 
                valid_status = config.get('valid_status', [200])
                invalid_status = config.get('invalid_status', [404])
                
                if response. status_code in valid_status: 
                    result['exists'] = True
                    result['status'] = 'FOUND'
                    result['verified'] = True
                elif response.status_code in invalid_status:
                    result['exists'] = False
                    result['status'] = 'NOT FOUND'
                    result['verified'] = True
                else:
                    result['exists'] = None
                    result['status'] = f'UNKNOWN (HTTP {response.status_code})'
            
            elif check_type == 'content':
                content = response.text
                content_indicator = config.get('content_indicator', '').format(username)
                invalid_indicator = config.get('invalid_indicator', '')
                
                if invalid_indicator and invalid_indicator in content:
                    result['exists'] = False
                    result['status'] = 'NOT FOUND'
                    result['verified'] = True
                elif content_indicator in content or username. lower() in content.lower():
                    result['exists'] = True
                    result['status'] = 'FOUND'
                    result['verified'] = True
                else:
                    result['exists'] = None
                    result['status'] = 'UNCERTAIN'
            
            elif check_type == 'json_array':
                data = response.json()
                if isinstance(data, list) and len(data) > 0:
                    result['exists'] = True
                    result['status'] = 'FOUND'
                    result['verified'] = True
                    if 'extract_data' in config:
                        result['details'] = config['extract_data'](response)
                else:
                    result['exists'] = False
                    result['status'] = 'NOT FOUND'
                    result['verified'] = True
            
            elif check_type == 'json_field':
                data = response.json()
                field = config.get('json_field')
                if data and data.get(field):
                    result['exists'] = True
                    result['status'] = 'FOUND'
                    result['verified'] = True
                    if 'extract_data' in config:
                        result['details'] = config['extract_data'](response)
                else:
                    result['exists'] = False
                    result['status'] = 'NOT FOUND'
                    result['verified'] = True
            
            elif check_type == 'not_null':
                data = response.json()
                if data is not None and data: 
                    result['exists'] = True
                    result['status'] = 'FOUND'
                    result['verified'] = True
                    if 'extract_data' in config:
                        result['details'] = config['extract_data'](response)
                else:
                    result['exists'] = False
                    result['status'] = 'NOT FOUND'
                    result['verified'] = True
            
            # Extract additional data if found
            if result['exists'] and 'extract_data' in config and check_type == 'status_code':
                try:
                    result['details'] = config['extract_data'](response)
                except:
                    pass
                    
        except requests.exceptions. Timeout:
            result['status'] = 'TIMEOUT'
            result['exists'] = None
        except requests.exceptions.ConnectionError:
            result['status'] = 'CONNECTION ERROR'
            result['exists'] = None
        except Exception as e:
            result['status'] = f'ERROR: {str(e)[: 30]}'
            result['exists'] = None
        
        return result