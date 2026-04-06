"""
Log Correlator - Correlate IOCs against simulated system logs
"""

import os
import json
import uuid
from datetime import datetime
from urllib.parse import urlparse


class LogCorrelator:
    def __init__(self, db_manager, data_dir='data'):
        self.db = db_manager
        self.data_dir = data_dir
        self.logs_file = os.path.join(data_dir, 'logs', 'simulated_logs.json')
    
    def run_correlation(self):
        """Run correlation of IOCs against all log sources"""
        # Load active non-FP IOCs
        iocs = self.db.get_all_active_iocs()
        
        # Load simulated logs
        logs = self._load_logs()
        
        if not logs:
            return {
                'new_correlations': 0,
                'correlations': [],
                'error': 'No logs available'
            }
        
        correlations = []
        
        for ioc in iocs:
            ioc_correlations = self._correlate_ioc(ioc, logs)
            correlations.extend(ioc_correlations)
        
        # Store correlations in database
        new_count = 0
        for corr in correlations:
            corr_id = self.db.insert_correlation(corr)
            if corr_id:
                new_count += 1
        
        return {
            'new_correlations': new_count,
            'correlations': correlations,
            'total_iocs_checked': len(iocs),
            'total_logs_checked': sum(len(v) for v in logs.values())
        }
    
    def _load_logs(self):
        """Load simulated logs from JSON file"""
        try:
            with open(self.logs_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
        except json.JSONDecodeError:
            return {}
    
    def _correlate_ioc(self, ioc, logs):
        """Correlate a single IOC against all log sources"""
        correlations = []
        ioc_value = ioc.get('ioc_value', '')
        ioc_type = ioc.get('ioc_type', '')
        ioc_id = ioc.get('id')
        
        if ioc_type == 'ip':
            # Search firewall and auth logs
            for log_entry in logs.get('firewall_logs', []):
                if ioc_value == log_entry.get('dst_ip') or ioc_value == log_entry.get('src_ip'):
                    correlations.append(self._create_correlation(ioc, log_entry, 'firewall'))
            
            for log_entry in logs.get('auth_logs', []):
                if ioc_value == log_entry.get('source_ip'):
                    correlations.append(self._create_correlation(ioc, log_entry, 'auth'))
        
        elif ioc_type == 'domain':
            # Search DNS and proxy logs
            for log_entry in logs.get('dns_logs', []):
                if ioc_value.lower() == log_entry.get('query_name', '').lower():
                    correlations.append(self._create_correlation(ioc, log_entry, 'dns'))
            
            for log_entry in logs.get('proxy_logs', []):
                url = log_entry.get('url', '')
                try:
                    parsed = urlparse(url)
                    if ioc_value.lower() == parsed.netloc.lower():
                        correlations.append(self._create_correlation(ioc, log_entry, 'proxy'))
                except Exception:
                    pass
        
        elif ioc_type == 'url':
            # Search proxy logs for exact or partial URL match
            for log_entry in logs.get('proxy_logs', []):
                log_url = log_entry.get('url', '')
                if ioc_value == log_url or ioc_value in log_url:
                    correlations.append(self._create_correlation(ioc, log_entry, 'proxy'))
        
        elif ioc_type == 'hash':
            # Search file hash logs
            for log_entry in logs.get('file_hash_logs', []):
                if ioc_value.lower() == log_entry.get('file_hash', '').lower():
                    correlations.append(self._create_correlation(ioc, log_entry, 'file_hash'))
        
        elif ioc_type == 'email':
            # Search auth logs for username matches
            email_local = ioc_value.split('@')[0] if '@' in ioc_value else ioc_value
            for log_entry in logs.get('auth_logs', []):
                if email_local.lower() == log_entry.get('username', '').lower():
                    correlations.append(self._create_correlation(ioc, log_entry, 'auth'))
        
        return correlations
    
    def _create_correlation(self, ioc, log_entry, log_source):
        """Create a correlation record"""
        now = datetime.utcnow().isoformat()
        
        # Determine verdict based on confidence
        confidence = ioc.get('confidence', 50)
        is_active = ioc.get('is_active', 1)
        
        if confidence >= 70 and is_active:
            verdict = 'Confirmed Threat'
        elif confidence >= 40:
            verdict = 'Suspicious - Needs Review'
        else:
            verdict = 'Low Confidence Match'
        
        # Calculate threat score
        from .threat_scorer import ThreatScorer
        scorer = ThreatScorer()
        score_result = scorer.calculate_score(ioc, log_entry)
        threat_score = score_result.get('final_score', 50)
        
        # Extract internal host/user info from log
        internal_host = log_entry.get('hostname', 'Unknown')
        internal_user = log_entry.get('user', log_entry.get('username', 'Unknown'))
        
        correlation = {
            'correlation_id': f"COR-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}",
            'ioc_id': ioc.get('id'),
            'log_source': log_source,
            'log_entry': log_entry,
            'matched_at': log_entry.get('timestamp', now),
            'threat_score': threat_score,
            'verdict': verdict,
            'analyst_notes': None,
            'reviewed': 0
        }
        
        return correlation
    
    def get_correlations_for_ioc(self, ioc_id):
        """Get all correlations for a specific IOC"""
        return self.db.get_correlations({'ioc_id': ioc_id})
    
    def get_recent_correlations(self, limit=10):
        """Get most recent correlations"""
        return self.db.get_correlations({'limit': limit})
    
    def get_correlations_by_verdict(self, verdict):
        """Get correlations filtered by verdict"""
        return self.db.get_correlations({'verdict': verdict})
    
    def get_affected_hosts(self):
        """Get list of internal hosts with IOC matches"""
        correlations = self.db.get_correlations({})
        hosts = set()
        
        for corr in correlations:
            log_entry = corr.get('log_entry', {})
            if isinstance(log_entry, str):
                try:
                    log_entry = json.loads(log_entry)
                except json.JSONDecodeError:
                    log_entry = {}
            
            hostname = log_entry.get('hostname')
            if hostname:
                hosts.add(hostname)
        
        return list(hosts)
    
    def get_affected_users(self):
        """Get list of users with IOC matches"""
        correlations = self.db.get_correlations({})
        users = set()
        
        for corr in correlations:
            log_entry = corr.get('log_entry', {})
            if isinstance(log_entry, str):
                try:
                    log_entry = json.loads(log_entry)
                except json.JSONDecodeError:
                    log_entry = {}
            
            user = log_entry.get('user') or log_entry.get('username')
            if user:
                users.add(user)
        
        return list(users)
    
    def get_correlation_stats(self):
        """Get summary statistics of correlations"""
        correlations = self.db.get_correlations({})
        
        stats = {
            'total': len(correlations),
            'confirmed_threats': 0,
            'suspicious': 0,
            'low_confidence': 0,
            'reviewed': 0,
            'pending_review': 0,
            'by_log_source': {},
            'affected_hosts': set(),
            'affected_users': set()
        }
        
        for corr in correlations:
            verdict = corr.get('verdict', '')
            
            if verdict == 'Confirmed Threat':
                stats['confirmed_threats'] += 1
            elif verdict == 'Suspicious - Needs Review':
                stats['suspicious'] += 1
            else:
                stats['low_confidence'] += 1
            
            if corr.get('reviewed'):
                stats['reviewed'] += 1
            else:
                stats['pending_review'] += 1
            
            log_source = corr.get('log_source', 'unknown')
            stats['by_log_source'][log_source] = stats['by_log_source'].get(log_source, 0) + 1
            
            log_entry = corr.get('log_entry', {})
            if isinstance(log_entry, str):
                try:
                    log_entry = json.loads(log_entry)
                except json.JSONDecodeError:
                    log_entry = {}
            
            if log_entry.get('hostname'):
                stats['affected_hosts'].add(log_entry['hostname'])
            if log_entry.get('user') or log_entry.get('username'):
                stats['affected_users'].add(log_entry.get('user') or log_entry.get('username'))
        
        stats['affected_hosts'] = list(stats['affected_hosts'])
        stats['affected_users'] = list(stats['affected_users'])
        
        return stats
