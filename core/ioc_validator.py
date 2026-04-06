"""
IOC Validator - Automated false positive reduction system
"""

import ipaddress
from datetime import datetime, timedelta
from .ioc_parser import IOCParser


class IOCValidator:
    # Known good IPs (DNS servers, etc.) - never flag as threats
    WHITELIST_IPS = {
        '8.8.8.8', '8.8.4.4',           # Google DNS
        '1.1.1.1', '1.0.0.1',           # Cloudflare DNS
        '9.9.9.9', '149.112.112.112',   # Quad9 DNS
        '208.67.222.222', '208.67.220.220',  # OpenDNS
        '4.2.2.1', '4.2.2.2',           # Level3 DNS
        '64.6.64.6', '64.6.65.6'        # Verisign DNS
    }
    
    # Standard legitimate ports
    STANDARD_PORTS = {80, 443, 53, 25, 587, 22, 21, 3389, 8080, 8443}
    
    # Suspicious ports that increase threat score
    SUSPICIOUS_PORTS = {4444, 1337, 31337, 8888, 6666, 5555, 4443, 9001}
    
    def __init__(self, db_manager=None):
        self.db = db_manager
        self.parser = IOCParser()
    
    def validate(self, ioc_dict):
        """
        Validate an IOC and return validation result
        
        Args:
            ioc_dict: Dictionary with IOC data including ioc_value, ioc_type, etc.
        
        Returns:
            Dictionary with validation results
        """
        result = {
            'ioc_value': ioc_dict.get('ioc_value'),
            'is_valid': True,
            'false_positive': False,
            'fp_reason': None,
            'adjusted_confidence': ioc_dict.get('confidence', 50),
            'adjusted_severity': ioc_dict.get('severity', 'Medium'),
            'validation_notes': []
        }
        
        ioc_value = ioc_dict.get('ioc_value', '')
        ioc_type = ioc_dict.get('ioc_type', '')
        
        # Parse the IOC for additional validation
        parsed = self.parser.parse(ioc_value, ioc_type)
        
        # Run all validation checks
        self._check_whitelist(ioc_value, ioc_type, result)
        self._check_private_range(ioc_value, ioc_type, result)
        self._check_known_good_domain(ioc_value, ioc_type, result)
        self._check_confidence_threshold(ioc_dict, result)
        self._check_cross_feed_validation(ioc_dict, result)
        self._check_age_validation(ioc_dict, result)
        self._check_context_validation(ioc_dict, parsed, result)
        
        # Cap confidence at 100, minimum 0
        result['adjusted_confidence'] = max(0, min(100, result['adjusted_confidence']))
        
        # Update severity based on adjusted confidence if needed
        if result['adjusted_confidence'] >= 90:
            result['adjusted_severity'] = 'Critical'
        elif result['adjusted_confidence'] < 30 and result['adjusted_severity'] in ['Critical', 'High']:
            result['adjusted_severity'] = 'Medium'
        
        return result
    
    def _check_whitelist(self, ioc_value, ioc_type, result):
        """Check against whitelist of known good IPs"""
        if ioc_type == 'ip':
            # Extract IP without port
            ip_str = ioc_value.split(':')[0] if ':' in ioc_value else ioc_value
            if ip_str.startswith('['):
                ip_str = ip_str.split(']')[0][1:]
            
            if ip_str in self.WHITELIST_IPS:
                result['false_positive'] = True
                result['fp_reason'] = f'Whitelisted IP (known DNS server): {ip_str}'
                result['is_valid'] = False
                result['validation_notes'].append(f'Matched whitelist: {ip_str}')
    
    def _check_private_range(self, ioc_value, ioc_type, result):
        """Check if IP is in private/reserved ranges"""
        if result['false_positive']:
            return
        
        if ioc_type == 'ip':
            ip_str = ioc_value.split(':')[0] if ':' in ioc_value else ioc_value
            if ip_str.startswith('['):
                ip_str = ip_str.split(']')[0][1:]
            
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
                    result['false_positive'] = True
                    result['fp_reason'] = 'Private or reserved IP range'
                    result['is_valid'] = False
                    result['validation_notes'].append('IP in private/reserved range')
            except ValueError:
                pass
    
    def _check_known_good_domain(self, ioc_value, ioc_type, result):
        """Check if domain is in known good list"""
        if result['false_positive']:
            return
        
        if ioc_type == 'domain':
            domain_lower = ioc_value.lower()
            for good_domain in self.parser.KNOWN_GOOD_DOMAINS:
                if domain_lower == good_domain or domain_lower.endswith('.' + good_domain):
                    result['false_positive'] = True
                    result['fp_reason'] = f'Known legitimate domain: {good_domain}'
                    result['is_valid'] = False
                    result['validation_notes'].append(f'Matched known good domain: {good_domain}')
                    return
        
        elif ioc_type == 'url':
            # Extract domain from URL
            domain = self.parser.extract_domain_from_url(ioc_value)
            if domain:
                domain_lower = domain.lower()
                for good_domain in self.parser.KNOWN_GOOD_DOMAINS:
                    if domain_lower == good_domain or domain_lower.endswith('.' + good_domain):
                        result['false_positive'] = True
                        result['fp_reason'] = f'URL contains known legitimate domain: {good_domain}'
                        result['is_valid'] = False
                        result['validation_notes'].append(f'URL domain matched known good: {good_domain}')
                        return
    
    def _check_confidence_threshold(self, ioc_dict, result):
        """Apply confidence threshold rules"""
        if result['false_positive']:
            return
        
        confidence = ioc_dict.get('confidence', 50)
        source_feed = ioc_dict.get('source_feed', '')
        
        if confidence < 30:
            result['validation_notes'].append('Low confidence IOC - tagged as low_priority')
        
        if confidence >= 70:
            result['validation_notes'].append('High confidence IOC - tagged as high_priority')
    
    def _check_cross_feed_validation(self, ioc_dict, result):
        """Check if same IOC appears in multiple feeds"""
        if result['false_positive'] or not self.db:
            return
        
        ioc_value = ioc_dict.get('ioc_value', '')
        current_feed = ioc_dict.get('source_feed', '')
        
        # Query database for same IOC from different feeds
        existing = self.db.get_ioc_by_value(ioc_value)
        if existing and existing.get('source_feed') != current_feed:
            # IOC seen in another feed - boost confidence
            feeds_seen = {current_feed, existing.get('source_feed', '')}
            feed_count = len([f for f in feeds_seen if f])
            
            if feed_count >= 2:
                result['adjusted_confidence'] += 20
                result['validation_notes'].append(f'Cross-feed validation: seen in {feed_count} feeds (+20 confidence)')
            
            if feed_count >= 3:
                result['adjusted_severity'] = 'Critical'
                result['validation_notes'].append('Seen in 3+ feeds: severity upgraded to Critical')
    
    def _check_age_validation(self, ioc_dict, result):
        """Validate IOC based on age"""
        if result['false_positive']:
            return
        
        first_seen = ioc_dict.get('first_seen')
        if not first_seen:
            return
        
        try:
            if isinstance(first_seen, str):
                # Parse ISO timestamp
                first_seen_dt = datetime.fromisoformat(first_seen.replace('Z', '+00:00'))
            else:
                first_seen_dt = first_seen
            
            now = datetime.now(first_seen_dt.tzinfo) if first_seen_dt.tzinfo else datetime.utcnow()
            age_days = (now - first_seen_dt.replace(tzinfo=None)).days
            
            if age_days > 90:
                result['validation_notes'].append(f'IOC is {age_days} days old - marked as expired')
                # Don't mark as false positive, just note it
            elif age_days > 30:
                result['adjusted_confidence'] -= 10
                result['validation_notes'].append(f'IOC is {age_days} days old (-10 confidence)')
        except (ValueError, TypeError):
            pass
    
    def _check_context_validation(self, ioc_dict, parsed, result):
        """Context-based validation"""
        if result['false_positive']:
            return
        
        ioc_type = ioc_dict.get('ioc_type', '')
        
        if ioc_type == 'ip' and parsed:
            port = parsed.get('metadata', {}).get('port')
            
            if port and port in self.SUSPICIOUS_PORTS:
                result['adjusted_confidence'] += 10
                result['validation_notes'].append(f'Suspicious port {port} detected (+10 confidence)')
            elif port and port in self.STANDARD_PORTS:
                # Standard port with no other indicators - slightly reduce severity
                if result['adjusted_severity'] == 'Critical' and len(result['validation_notes']) == 0:
                    result['adjusted_severity'] = 'High'
                    result['validation_notes'].append('Standard port only - severity reduced')
        
        # Check for suspicious TLD in domains
        if ioc_type == 'domain':
            tld = parsed.get('metadata', {}).get('tld', '') if parsed else ''
            if tld in self.parser.SUSPICIOUS_TLDS:
                result['adjusted_confidence'] += 5
                result['validation_notes'].append(f'Suspicious TLD {tld} detected (+5 confidence)')
    
    def validate_batch(self, ioc_list):
        """Validate a batch of IOCs"""
        results = []
        for ioc_dict in ioc_list:
            result = self.validate(ioc_dict)
            results.append(result)
        return results
    
    def is_false_positive(self, ioc_value, ioc_type):
        """Quick check if an IOC is a false positive"""
        result = self.validate({
            'ioc_value': ioc_value,
            'ioc_type': ioc_type,
            'confidence': 50,
            'severity': 'Medium'
        })
        return result['false_positive']
    
    def get_fp_reason(self, ioc_value, ioc_type):
        """Get the false positive reason for an IOC"""
        result = self.validate({
            'ioc_value': ioc_value,
            'ioc_type': ioc_type,
            'confidence': 50,
            'severity': 'Medium'
        })
        return result.get('fp_reason')
