"""
Enrichment Engine - Enrich IOCs with VirusTotal and AbuseIPDB
"""

import os
import time
import requests
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()


class EnrichmentEngine:
    VT_BASE_URL = 'https://www.virustotal.com/api/v3'
    ABUSEIPDB_BASE_URL = 'https://api.abuseipdb.com/api/v2'
    
    # Rate limiting for VT free tier (4 req/min)
    VT_RATE_LIMIT = 4
    VT_RATE_WINDOW = 60  # seconds
    
    def __init__(self, db_manager):
        self.db = db_manager
        self.vt_api_key = os.getenv('VIRUSTOTAL_API_KEY', '')
        self.abuseipdb_api_key = os.getenv('ABUSEIPDB_API_KEY', '')
        self.vt_request_times = []
    
    def _wait_for_vt_rate_limit(self):
        """Ensure we don't exceed VT rate limits"""
        now = time.time()
        
        # Remove requests older than rate window
        self.vt_request_times = [t for t in self.vt_request_times 
                                  if now - t < self.VT_RATE_WINDOW]
        
        # If at limit, wait
        if len(self.vt_request_times) >= self.VT_RATE_LIMIT:
            oldest = self.vt_request_times[0]
            wait_time = self.VT_RATE_WINDOW - (now - oldest) + 1
            if wait_time > 0:
                time.sleep(wait_time)
            self.vt_request_times = []
        
        self.vt_request_times.append(time.time())
    
    def enrich_ioc(self, ioc_dict):
        """
        Enrich a single IOC with VT and AbuseIPDB data
        
        Args:
            ioc_dict: IOC dictionary with ioc_value, ioc_type, etc.
        
        Returns:
            Dictionary with enrichment results
        """
        ioc_value = ioc_dict.get('ioc_value', '')
        ioc_type = ioc_dict.get('ioc_type', '')
        
        result = {
            'ioc_value': ioc_value,
            'ioc_type': ioc_type,
            'enriched': False,
            'virustotal': None,
            'abuseipdb': None,
            'mock_data': False,
            'error': None
        }
        
        # Skip if already enriched
        if ioc_dict.get('enriched'):
            result['error'] = 'Already enriched'
            return result
        
        # Skip low confidence IOCs
        if ioc_dict.get('confidence', 50) < 40:
            result['error'] = 'Confidence too low for enrichment'
            return result
        
        # Try VirusTotal enrichment
        if self.vt_api_key:
            vt_data = self._enrich_virustotal(ioc_value, ioc_type)
            if vt_data:
                result['virustotal'] = vt_data
                result['enriched'] = True
        
        # Try AbuseIPDB enrichment (IP only)
        if self.abuseipdb_api_key and ioc_type == 'ip':
            abuseipdb_data = self._enrich_abuseipdb(ioc_value)
            if abuseipdb_data:
                result['abuseipdb'] = abuseipdb_data
                result['enriched'] = True
        
        # If no API keys, return mock data
        if not self.vt_api_key and not self.abuseipdb_api_key:
            result = self._generate_mock_enrichment(ioc_dict)
        
        # Update database if enriched
        if result['enriched'] and ioc_dict.get('id'):
            enrichment_data = {
                'virustotal': result.get('virustotal'),
                'abuseipdb': result.get('abuseipdb'),
                'mock_data': result.get('mock_data', False),
                'enriched_at': datetime.utcnow().isoformat()
            }
            self.db.update_ioc(ioc_dict['id'], {
                'enriched': 1,
                'enrichment_data': enrichment_data
            })
        
        return result
    
    def _enrich_virustotal(self, ioc_value, ioc_type):
        """Query VirusTotal API"""
        try:
            self._wait_for_vt_rate_limit()
            
            headers = {'x-apikey': self.vt_api_key}
            
            if ioc_type == 'ip':
                url = f'{self.VT_BASE_URL}/ip_addresses/{ioc_value}'
            elif ioc_type == 'domain':
                url = f'{self.VT_BASE_URL}/domains/{ioc_value}'
            elif ioc_type == 'hash':
                url = f'{self.VT_BASE_URL}/files/{ioc_value}'
            elif ioc_type == 'url':
                # URL needs to be base64 encoded
                import base64
                url_id = base64.urlsafe_b64encode(ioc_value.encode()).decode().strip('=')
                url = f'{self.VT_BASE_URL}/urls/{url_id}'
            else:
                return None
            
            response = requests.get(url, headers=headers, timeout=15)
            
            if response.status_code == 429:
                # Rate limited, wait and retry once
                time.sleep(60)
                response = requests.get(url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                data = response.json().get('data', {}).get('attributes', {})
                return self._parse_vt_response(data, ioc_type)
            
            return None
            
        except Exception as e:
            return None
    
    def _parse_vt_response(self, data, ioc_type):
        """Parse VT response into standardized format"""
        result = {
            'reputation': data.get('reputation', 0),
            'last_analysis_stats': data.get('last_analysis_stats', {}),
            'detection_ratio': None,
            'country': data.get('country'),
            'as_owner': data.get('as_owner'),
            'registrar': data.get('registrar'),
            'creation_date': data.get('creation_date'),
            'categories': data.get('categories', {}),
            'malware_names': [],
            'file_type': data.get('type_description')
        }
        
        # Calculate detection ratio
        stats = result['last_analysis_stats']
        malicious = stats.get('malicious', 0)
        total = sum(stats.values()) if stats else 0
        if total > 0:
            result['detection_ratio'] = f"{malicious}/{total}"
        
        # Extract malware names from results
        if 'last_analysis_results' in data:
            for engine, info in data['last_analysis_results'].items():
                if info.get('category') == 'malicious' and info.get('result'):
                    result['malware_names'].append(info['result'])
            result['malware_names'] = list(set(result['malware_names']))[:10]
        
        # Popular threat classification
        if 'popular_threat_classification' in data:
            result['threat_classification'] = data['popular_threat_classification']
        
        return result
    
    def _enrich_abuseipdb(self, ip_address):
        """Query AbuseIPDB API"""
        try:
            headers = {
                'Key': self.abuseipdb_api_key,
                'Accept': 'application/json'
            }
            
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90
            }
            
            response = requests.get(
                f'{self.ABUSEIPDB_BASE_URL}/check',
                headers=headers,
                params=params,
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                return {
                    'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                    'country_code': data.get('countryCode'),
                    'usage_type': data.get('usageType'),
                    'isp': data.get('isp'),
                    'domain': data.get('domain'),
                    'total_reports': data.get('totalReports', 0),
                    'last_reported_at': data.get('lastReportedAt'),
                    'is_public': data.get('isPublic', True),
                    'is_whitelisted': data.get('isWhitelisted', False)
                }
            
            return None
            
        except Exception as e:
            return None
    
    def _generate_mock_enrichment(self, ioc_dict):
        """Generate realistic mock enrichment data for demo mode"""
        ioc_value = ioc_dict.get('ioc_value', '')
        ioc_type = ioc_dict.get('ioc_type', '')
        confidence = ioc_dict.get('confidence', 50)
        
        result = {
            'ioc_value': ioc_value,
            'ioc_type': ioc_type,
            'enriched': True,
            'mock_data': True,
            'virustotal': None,
            'abuseipdb': None,
            'error': None
        }
        
        # Generate mock VT data based on confidence
        if confidence >= 70:
            malicious_count = 35 + (confidence - 70)
        elif confidence >= 50:
            malicious_count = 15 + (confidence - 50)
        else:
            malicious_count = 5 + (confidence // 10)
        
        total_engines = 72
        
        result['virustotal'] = {
            'reputation': -(confidence // 5),
            'last_analysis_stats': {
                'malicious': malicious_count,
                'suspicious': 3,
                'undetected': total_engines - malicious_count - 5,
                'harmless': 2,
                'timeout': 0
            },
            'detection_ratio': f"{malicious_count}/{total_engines}",
            'country': 'RU' if confidence > 70 else 'US',
            'as_owner': 'Example Hosting Provider',
            'malware_names': [],
            'mock_data': True
        }
        
        # Add malware names based on IOC data
        malware_family = ioc_dict.get('malware_family')
        if malware_family:
            result['virustotal']['malware_names'] = [
                malware_family,
                f'Trojan.{malware_family}',
                f'Win32/{malware_family}'
            ]
        
        # Generate mock AbuseIPDB data for IPs
        if ioc_type == 'ip':
            result['abuseipdb'] = {
                'abuse_confidence_score': min(100, confidence + 10),
                'country_code': 'RU' if confidence > 70 else 'US',
                'usage_type': 'Data Center/Web Hosting/Transit',
                'isp': 'Example Hosting Inc.',
                'domain': 'example-hosting.com',
                'total_reports': confidence // 5,
                'last_reported_at': datetime.utcnow().isoformat(),
                'is_public': True,
                'is_whitelisted': False,
                'mock_data': True
            }
        
        return result
    
    def enrich_batch(self, ioc_ids=None, enrich_all=False, max_count=5):
        """
        Enrich multiple IOCs
        
        Args:
            ioc_ids: List of specific IOC IDs to enrich
            enrich_all: If True, enrich all unenriched IOCs
            max_count: Maximum number of IOCs to enrich (to conserve quota)
        
        Returns:
            List of enrichment results
        """
        results = []
        
        if enrich_all:
            # Get unenriched IOCs with confidence >= 40
            iocs = self.db.get_all_active_iocs()
            iocs = [i for i in iocs if not i.get('enriched') and i.get('confidence', 0) >= 40]
        elif ioc_ids:
            iocs = [self.db.get_ioc_by_id(ioc_id) for ioc_id in ioc_ids]
            iocs = [i for i in iocs if i]
        else:
            return results
        
        # Limit to max_count
        iocs = iocs[:max_count]
        
        for ioc in iocs:
            result = self.enrich_ioc(ioc)
            results.append(result)
        
        return results
    
    def get_enrichment_status(self):
        """Get enrichment statistics"""
        all_iocs = self.db.get_all_active_iocs()
        
        enriched_count = sum(1 for i in all_iocs if i.get('enriched'))
        eligible_count = sum(1 for i in all_iocs if i.get('confidence', 0) >= 40)
        
        return {
            'total_iocs': len(all_iocs),
            'enriched': enriched_count,
            'eligible_for_enrichment': eligible_count,
            'pending_enrichment': eligible_count - enriched_count,
            'vt_api_configured': bool(self.vt_api_key),
            'abuseipdb_api_configured': bool(self.abuseipdb_api_key)
        }
