"""
Feed Manager - Pull IOCs from free public threat intelligence feeds
"""

import os
import json
import requests
from datetime import datetime
from urllib.parse import urlparse


class FeedManager:
    # Feed configurations
    FEEDS = {
        'URLhaus': {
            'url': 'https://urlhaus-api.abuse.ch/v1/urls/recent/',
            'method': 'POST',
            'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
            'body': 'limit=100'
        },
        'ThreatFox': {
            'url': 'https://threatfox-api.abuse.ch/api/v1/',
            'method': 'POST',
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({"query": "get_iocs", "days": 3})
        },
        'Feodo': {
            'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
            'method': 'GET',
            'headers': {},
            'body': None
        },
        'MalwareBazaar': {
            'url': 'https://mb-api.abuse.ch/api/v1/',
            'method': 'POST',
            'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
            'body': 'query=get_recent&selector=100'
        }
    }
    
    TIMEOUT = 15  # seconds
    
    def __init__(self, db_manager, data_dir='data'):
        self.db = db_manager
        self.data_dir = data_dir
        self.feeds_dir = os.path.join(data_dir, 'feeds')
        self.demo_dir = os.path.join(data_dir, 'demo')
        
        # Create directories if they don't exist
        os.makedirs(self.feeds_dir, exist_ok=True)
        os.makedirs(self.demo_dir, exist_ok=True)
    
    def refresh_single_feed(self, feed_name):
        """Fetch and store IOCs from a single feed"""
        if feed_name not in self.FEEDS and feed_name != 'Demo':
            return {
                'feed_name': feed_name,
                'status': 'error',
                'error': f'Unknown feed: {feed_name}',
                'new_iocs_added': 0,
                'total_fetched': 0
            }
        
        if feed_name == 'Demo':
            return self.load_demo_feed()
        
        feed_config = self.FEEDS[feed_name]
        result = {
            'feed_name': feed_name,
            'status': 'success',
            'new_iocs_added': 0,
            'total_fetched': 0,
            'error': None
        }
        
        try:
            # Fetch from feed
            if feed_config['method'] == 'POST':
                response = requests.post(
                    feed_config['url'],
                    headers=feed_config['headers'],
                    data=feed_config['body'],
                    timeout=self.TIMEOUT
                )
            else:
                response = requests.get(
                    feed_config['url'],
                    headers=feed_config['headers'],
                    timeout=self.TIMEOUT
                )
            
            response.raise_for_status()
            data = response.json()
            
            # Cache the response
            cache_file = os.path.join(self.feeds_dir, f'{feed_name.lower()}_cache.json')
            with open(cache_file, 'w') as f:
                json.dump(data, f)
            
            # Parse and store IOCs
            iocs = self._parse_feed_response(feed_name, data)
            result['total_fetched'] = len(iocs)
            
            # Insert IOCs into database
            for ioc in iocs:
                ioc_id = self.db.insert_ioc(ioc)
                if ioc_id:
                    result['new_iocs_added'] += 1
            
            # Update feed status
            self.db.update_feed_status(feed_name, {
                'feed_url': feed_config['url'],
                'ioc_count': self.db.get_ioc_count_by_feed(feed_name),
                'status': 'active',
                'error_message': None
            })
            
        except requests.exceptions.Timeout:
            result['status'] = 'error'
            result['error'] = 'Request timeout'
            self._load_from_cache(feed_name, result)
            
        except requests.exceptions.RequestException as e:
            result['status'] = 'error'
            result['error'] = str(e)
            self._load_from_cache(feed_name, result)
            
        except json.JSONDecodeError:
            result['status'] = 'error'
            result['error'] = 'Invalid JSON response'
            self._load_from_cache(feed_name, result)
            
        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)
            self._load_from_cache(feed_name, result)
        
        # Update feed status on error
        if result['status'] == 'error':
            self.db.update_feed_status(feed_name, {
                'feed_url': self.FEEDS.get(feed_name, {}).get('url', ''),
                'status': 'error',
                'error_message': result['error']
            })
        
        return result
    
    def _load_from_cache(self, feed_name, result):
        """Load IOCs from cache file if available"""
        cache_file = os.path.join(self.feeds_dir, f'{feed_name.lower()}_cache.json')
        
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                iocs = self._parse_feed_response(feed_name, data)
                result['total_fetched'] = len(iocs)
                result['error'] += ' (loaded from cache)'
                
                for ioc in iocs:
                    ioc_id = self.db.insert_ioc(ioc)
                    if ioc_id:
                        result['new_iocs_added'] += 1
            except Exception:
                # Cache also failed, load demo
                demo_result = self.load_demo_feed()
                result['new_iocs_added'] = demo_result.get('new_iocs_added', 0)
                result['error'] += ' (loaded demo data)'
        else:
            # No cache, load demo
            demo_result = self.load_demo_feed()
            result['new_iocs_added'] = demo_result.get('new_iocs_added', 0)
            result['error'] += ' (loaded demo data)'
    
    def _parse_feed_response(self, feed_name, data):
        """Parse feed response and normalize IOCs"""
        iocs = []
        now = datetime.utcnow().isoformat()
        
        if feed_name == 'URLhaus':
            iocs = self._parse_urlhaus(data, now)
        elif feed_name == 'ThreatFox':
            iocs = self._parse_threatfox(data, now)
        elif feed_name == 'Feodo':
            iocs = self._parse_feodo(data, now)
        elif feed_name == 'MalwareBazaar':
            iocs = self._parse_malwarebazaar(data, now)
        
        return iocs
    
    def _parse_urlhaus(self, data, now):
        """Parse URLhaus feed response"""
        iocs = []
        urls = data.get('urls', [])
        
        for entry in urls[:100]:  # Limit to 100
            url = entry.get('url', '')
            if not url:
                continue
            
            # Add URL IOC
            iocs.append({
                'ioc_value': url,
                'ioc_type': 'url',
                'source_feed': 'URLhaus',
                'threat_type': entry.get('threat', 'malware'),
                'malware_family': None,
                'confidence': 75,
                'severity': 'High',
                'first_seen': entry.get('date_added', now),
                'last_seen': now,
                'tags': json.dumps(entry.get('tags', [])),
                'is_active': 1 if entry.get('url_status') == 'online' else 0
            })
            
            # Extract domain from URL
            try:
                parsed = urlparse(url)
                domain = parsed.netloc
                if ':' in domain:
                    domain = domain.split(':')[0]
                if domain and not domain.replace('.', '').isdigit():
                    iocs.append({
                        'ioc_value': domain,
                        'ioc_type': 'domain',
                        'source_feed': 'URLhaus',
                        'threat_type': entry.get('threat', 'malware'),
                        'malware_family': None,
                        'confidence': 70,
                        'severity': 'High',
                        'first_seen': entry.get('date_added', now),
                        'last_seen': now,
                        'tags': json.dumps(['extracted_from_url']),
                        'is_active': 1
                    })
            except Exception:
                pass
        
        return iocs
    
    def _parse_threatfox(self, data, now):
        """Parse ThreatFox feed response"""
        iocs = []
        
        if data.get('query_status') != 'ok':
            return iocs
        
        entries = data.get('data', [])
        
        for entry in entries[:100]:
            ioc_value = entry.get('ioc', '')
            ioc_type_raw = entry.get('ioc_type', '').lower()
            
            # Map ThreatFox types to our types
            if 'ip' in ioc_type_raw:
                ioc_type = 'ip'
            elif 'domain' in ioc_type_raw:
                ioc_type = 'domain'
            elif 'url' in ioc_type_raw:
                ioc_type = 'url'
            elif 'hash' in ioc_type_raw or 'sha' in ioc_type_raw or 'md5' in ioc_type_raw:
                ioc_type = 'hash'
            else:
                ioc_type = 'domain'  # Default
            
            # Handle IP:port format
            if ioc_type == 'ip' and ':' in ioc_value:
                ioc_value = ioc_value.split(':')[0]
            
            confidence = entry.get('confidence_level', 75)
            if isinstance(confidence, str):
                try:
                    confidence = int(confidence)
                except ValueError:
                    confidence = 75
            
            severity = 'High'
            if confidence >= 90:
                severity = 'Critical'
            elif confidence < 50:
                severity = 'Medium'
            
            iocs.append({
                'ioc_value': ioc_value,
                'ioc_type': ioc_type,
                'source_feed': 'ThreatFox',
                'threat_type': entry.get('threat_type', 'malware'),
                'malware_family': entry.get('malware', entry.get('malware_printable')),
                'confidence': confidence,
                'severity': severity,
                'first_seen': entry.get('first_seen', now),
                'last_seen': entry.get('last_seen', now),
                'tags': json.dumps(entry.get('tags', [])),
                'is_active': 1
            })
        
        return iocs
    
    def _parse_feodo(self, data, now):
        """Parse Feodo Tracker feed response"""
        iocs = []
        
        # Feodo returns a list directly
        entries = data if isinstance(data, list) else []
        
        for entry in entries[:100]:
            ip = entry.get('ip_address', '')
            if not ip:
                continue
            
            iocs.append({
                'ioc_value': ip,
                'ioc_type': 'ip',
                'source_feed': 'Feodo',
                'threat_type': 'c2',
                'malware_family': entry.get('malware', 'Unknown'),
                'confidence': 85,
                'severity': 'High',
                'first_seen': entry.get('first_seen', now),
                'last_seen': entry.get('last_seen', now),
                'tags': json.dumps(['c2', 'botnet', entry.get('malware', 'unknown').lower()]),
                'is_active': 1 if entry.get('status') == 'online' else 0
            })
        
        return iocs
    
    def _parse_malwarebazaar(self, data, now):
        """Parse MalwareBazaar feed response"""
        iocs = []
        
        if data.get('query_status') != 'ok':
            return iocs
        
        entries = data.get('data', [])
        
        for entry in entries[:100]:
            sha256 = entry.get('sha256_hash', '')
            if sha256:
                iocs.append({
                    'ioc_value': sha256.lower(),
                    'ioc_type': 'hash',
                    'source_feed': 'MalwareBazaar',
                    'threat_type': 'malware',
                    'malware_family': entry.get('signature', entry.get('file_type')),
                    'confidence': 90,
                    'severity': 'High',
                    'first_seen': entry.get('first_seen', now),
                    'last_seen': now,
                    'tags': json.dumps(entry.get('tags', []) + ['sha256']),
                    'is_active': 1
                })
            
            md5 = entry.get('md5_hash', '')
            if md5:
                iocs.append({
                    'ioc_value': md5.lower(),
                    'ioc_type': 'hash',
                    'source_feed': 'MalwareBazaar',
                    'threat_type': 'malware',
                    'malware_family': entry.get('signature', entry.get('file_type')),
                    'confidence': 85,
                    'severity': 'High',
                    'first_seen': entry.get('first_seen', now),
                    'last_seen': now,
                    'tags': json.dumps(['md5']),
                    'is_active': 1
                })
        
        return iocs
    
    def refresh_all_feeds(self):
        """Refresh all configured feeds"""
        results = {
            'feeds_updated': 0,
            'total_new_iocs': 0,
            'feed_results': []
        }
        
        for feed_name in self.FEEDS.keys():
            result = self.refresh_single_feed(feed_name)
            results['feed_results'].append(result)
            
            if result['status'] == 'success':
                results['feeds_updated'] += 1
            results['total_new_iocs'] += result.get('new_iocs_added', 0)
        
        return results
    
    def load_demo_feed(self):
        """Load demo IOCs from demo_iocs.json"""
        result = {
            'feed_name': 'Demo',
            'status': 'success',
            'new_iocs_added': 0,
            'total_fetched': 0,
            'error': None
        }
        
        demo_file = os.path.join(self.demo_dir, 'demo_iocs.json')
        
        try:
            with open(demo_file, 'r') as f:
                demo_iocs = json.load(f)
            
            result['total_fetched'] = len(demo_iocs)
            
            for ioc in demo_iocs:
                # Convert tags list to JSON string if needed
                if isinstance(ioc.get('tags'), list):
                    ioc['tags'] = json.dumps(ioc['tags'])
                
                # Ensure source_feed is set
                if not ioc.get('source_feed'):
                    ioc['source_feed'] = 'Demo'
                
                ioc_id = self.db.insert_ioc(ioc)
                if ioc_id:
                    result['new_iocs_added'] += 1
            
            # Update feed status
            self.db.update_feed_status('Demo', {
                'feed_url': 'local://demo_iocs.json',
                'ioc_count': self.db.get_ioc_count_by_feed('Demo'),
                'status': 'active',
                'error_message': None
            })
            
        except FileNotFoundError:
            result['status'] = 'error'
            result['error'] = f'Demo file not found: {demo_file}'
        except json.JSONDecodeError:
            result['status'] = 'error'
            result['error'] = 'Invalid JSON in demo file'
        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)
        
        return result
    
    def get_feed_status(self):
        """Get current status of all feeds"""
        statuses = self.db.get_feed_status()
        
        # Add any missing feeds with default status
        known_feeds = list(self.FEEDS.keys()) + ['Demo']
        existing_names = {s['feed_name'] for s in statuses}
        
        for feed_name in known_feeds:
            if feed_name not in existing_names:
                statuses.append({
                    'feed_name': feed_name,
                    'feed_url': self.FEEDS.get(feed_name, {}).get('url', 'local://demo'),
                    'last_updated': None,
                    'ioc_count': 0,
                    'status': 'never_fetched',
                    'error_message': None
                })
        
        return statuses
