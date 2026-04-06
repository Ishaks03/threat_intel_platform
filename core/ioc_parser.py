"""
IOC Parser - Parse and normalize all IOC types
"""

import re
import ipaddress
from urllib.parse import urlparse


class IOCParser:
    # Known good domains that should be flagged as likely false positives
    KNOWN_GOOD_DOMAINS = {
        'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
        'github.com', 'cloudflare.com', 'windows.com', 'office.com',
        'windowsupdate.com', 'digicert.com', 'letsencrypt.org',
        'akamai.com', 'fastly.com', 'amazonaws.com', 'azure.com',
        'office365.com', 'outlook.com', 'live.com', 'bing.com',
        'linkedin.com', 'facebook.com', 'twitter.com', 'youtube.com'
    }
    
    # Suspicious TLDs that indicate higher risk
    SUSPICIOUS_TLDS = {
        '.xyz', '.top', '.club', '.online', '.site', '.store', 
        '.info', '.biz', '.work', '.click', '.link', '.gq',
        '.ml', '.cf', '.ga', '.tk'
    }
    
    # Free email providers (lower confidence for email IOCs)
    FREE_EMAIL_PROVIDERS = {
        'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
        'protonmail.com', 'tutanota.com', 'aol.com', 'mail.com'
    }
    
    # Private IP ranges
    PRIVATE_RANGES = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('169.254.0.0/16'),
        ipaddress.ip_network('::1/128'),
        ipaddress.ip_network('fc00::/7'),
        ipaddress.ip_network('fe80::/10')
    ]
    
    # Regex patterns
    DOMAIN_PATTERN = re.compile(
        r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$'
    )
    EMAIL_PATTERN = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )
    MD5_PATTERN = re.compile(r'^[a-fA-F0-9]{32}$')
    SHA1_PATTERN = re.compile(r'^[a-fA-F0-9]{40}$')
    SHA256_PATTERN = re.compile(r'^[a-fA-F0-9]{64}$')
    
    def parse(self, value, ioc_type=None):
        """Parse and normalize an IOC value"""
        if not value:
            return None
        
        value = str(value).strip()
        
        # Auto-detect type if not provided
        if not ioc_type:
            ioc_type = self._detect_type(value)
        
        if ioc_type == 'ip':
            return self._parse_ip(value)
        elif ioc_type == 'domain':
            return self._parse_domain(value)
        elif ioc_type == 'url':
            return self._parse_url(value)
        elif ioc_type == 'hash':
            return self._parse_hash(value)
        elif ioc_type == 'email':
            return self._parse_email(value)
        else:
            return {
                'value': value,
                'type': 'unknown',
                'normalized_value': value,
                'display_value': value,
                'subtype': None,
                'fp_risk': 'unknown',
                'fp_reason': 'Unknown IOC type',
                'metadata': {}
            }
    
    def _detect_type(self, value):
        """Auto-detect IOC type from value"""
        # Check for URL first (contains :// )
        if '://' in value:
            return 'url'
        
        # Check for email
        if '@' in value and self.EMAIL_PATTERN.match(value):
            return 'email'
        
        # Check for hash by length and hex chars
        if self.SHA256_PATTERN.match(value):
            return 'hash'
        if self.SHA1_PATTERN.match(value):
            return 'hash'
        if self.MD5_PATTERN.match(value):
            return 'hash'
        
        # Check for IP address
        try:
            # Remove port if present
            ip_part = value.split(':')[0] if ':' in value and not value.startswith('[') else value
            if value.startswith('['):
                ip_part = value.split(']')[0][1:]
            ipaddress.ip_address(ip_part)
            return 'ip'
        except ValueError:
            pass
        
        # Check for domain
        if self.DOMAIN_PATTERN.match(value):
            return 'domain'
        
        return 'unknown'
    
    def _parse_ip(self, value):
        """Parse and validate IP address IOC"""
        result = {
            'value': value,
            'type': 'ip',
            'normalized_value': None,
            'display_value': None,
            'subtype': None,
            'fp_risk': 'low',
            'fp_reason': None,
            'metadata': {'port': None}
        }
        
        # Extract port if present
        port = None
        ip_str = value
        
        if value.startswith('['):
            # IPv6 with port: [::1]:8080
            if ']:' in value:
                parts = value.rsplit(':', 1)
                ip_str = parts[0][1:-1]  # Remove brackets
                port = int(parts[1])
            else:
                ip_str = value.strip('[]')
        elif value.count(':') == 1:
            # IPv4 with port: 1.2.3.4:8080
            parts = value.rsplit(':', 1)
            ip_str = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                pass
        
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            result['normalized_value'] = str(ip_obj)
            result['subtype'] = 'IPv4' if ip_obj.version == 4 else 'IPv6'
            result['metadata']['port'] = port
            
            # Create defanged display version
            if ip_obj.version == 4:
                result['display_value'] = str(ip_obj).replace('.', '[.]')
            else:
                result['display_value'] = str(ip_obj)
            
            # Check for private/reserved ranges
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                result['fp_risk'] = 'high'
                result['fp_reason'] = 'Private or reserved IP range'
            
            # Check against private range networks
            for network in self.PRIVATE_RANGES:
                try:
                    if ip_obj in network:
                        result['fp_risk'] = 'high'
                        result['fp_reason'] = f'IP in private range {network}'
                        break
                except TypeError:
                    continue
                    
        except ValueError as e:
            result['fp_risk'] = 'high'
            result['fp_reason'] = f'Invalid IP address: {str(e)}'
            result['normalized_value'] = value
            result['display_value'] = value
        
        return result
    
    def _parse_domain(self, value):
        """Parse and validate domain IOC"""
        result = {
            'value': value,
            'type': 'domain',
            'normalized_value': value.lower(),
            'display_value': value.replace('.', '[.]'),
            'subtype': None,
            'fp_risk': 'low',
            'fp_reason': None,
            'metadata': {'tld': None}
        }
        
        # Extract TLD
        if '.' in value:
            result['metadata']['tld'] = '.' + value.rsplit('.', 1)[-1].lower()
        
        # Validate domain format
        if not self.DOMAIN_PATTERN.match(value):
            result['fp_risk'] = 'medium'
            result['fp_reason'] = 'Invalid domain format'
            return result
        
        # Check if in known good list
        domain_lower = value.lower()
        for good_domain in self.KNOWN_GOOD_DOMAINS:
            if domain_lower == good_domain or domain_lower.endswith('.' + good_domain):
                result['fp_risk'] = 'high'
                result['fp_reason'] = f'Known legitimate domain: {good_domain}'
                return result
        
        # Check for suspicious TLD
        tld = result['metadata']['tld']
        if tld and tld in self.SUSPICIOUS_TLDS:
            result['fp_risk'] = 'low'
            result['subtype'] = 'suspicious_tld'
        
        return result
    
    def _parse_url(self, value):
        """Parse and validate URL IOC"""
        result = {
            'value': value,
            'type': 'url',
            'normalized_value': value,
            'display_value': None,
            'subtype': None,
            'fp_risk': 'low',
            'fp_reason': None,
            'metadata': {
                'scheme': None,
                'domain': None,
                'path': None,
                'port': None,
                'query': None
            }
        }
        
        try:
            parsed = urlparse(value)
            result['metadata']['scheme'] = parsed.scheme
            result['metadata']['domain'] = parsed.netloc
            result['metadata']['path'] = parsed.path
            result['metadata']['query'] = parsed.query if parsed.query else None
            
            # Extract port from netloc
            if ':' in parsed.netloc:
                host_port = parsed.netloc.rsplit(':', 1)
                try:
                    result['metadata']['port'] = int(host_port[1])
                except ValueError:
                    pass
            
            # Create defanged display version
            defanged_domain = parsed.netloc.replace('.', '[.]')
            result['display_value'] = value.replace(parsed.netloc, defanged_domain)
            
            # Check for suspicious patterns
            suspicious_patterns = []
            
            # IP address in URL
            try:
                host = parsed.netloc.split(':')[0]
                ipaddress.ip_address(host)
                suspicious_patterns.append('IP address used instead of domain')
            except ValueError:
                pass
            
            # Long path
            if len(parsed.path) > 100:
                suspicious_patterns.append('Unusually long path')
            
            # Double extensions
            if re.search(r'\.(pdf|doc|docx|xls|xlsx|ppt)\.(exe|scr|bat|cmd|ps1|vbs)', 
                        parsed.path, re.IGNORECASE):
                suspicious_patterns.append('Double file extension detected')
            
            # Non-standard ports
            port = result['metadata']['port']
            if port and port not in [80, 443, 8080, 8443]:
                suspicious_patterns.append(f'Non-standard port: {port}')
            
            if suspicious_patterns:
                result['subtype'] = 'suspicious_url'
                result['fp_reason'] = '; '.join(suspicious_patterns)
            
        except Exception as e:
            result['fp_risk'] = 'medium'
            result['fp_reason'] = f'URL parse error: {str(e)}'
            result['display_value'] = value
        
        return result
    
    def _parse_hash(self, value):
        """Parse and validate file hash IOC"""
        value = value.lower().strip()
        
        result = {
            'value': value,
            'type': 'hash',
            'normalized_value': value,
            'display_value': value,
            'subtype': None,
            'fp_risk': 'low',
            'fp_reason': None,
            'metadata': {'hash_type': None}
        }
        
        # Determine hash type by length
        if self.SHA256_PATTERN.match(value):
            result['metadata']['hash_type'] = 'SHA256'
            result['subtype'] = 'SHA256'
        elif self.SHA1_PATTERN.match(value):
            result['metadata']['hash_type'] = 'SHA1'
            result['subtype'] = 'SHA1'
        elif self.MD5_PATTERN.match(value):
            result['metadata']['hash_type'] = 'MD5'
            result['subtype'] = 'MD5'
        else:
            result['fp_risk'] = 'high'
            result['fp_reason'] = 'Invalid hash format'
            return result
        
        # Check for all-zeros hash (false positive)
        if all(c == '0' for c in value):
            result['fp_risk'] = 'high'
            result['fp_reason'] = 'All-zeros hash (empty file)'
        
        # Check for empty file SHA256
        if value == 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855':
            result['fp_risk'] = 'high'
            result['fp_reason'] = 'SHA256 of empty file'
        
        return result
    
    def _parse_email(self, value):
        """Parse and validate email address IOC"""
        value = value.lower().strip()
        
        result = {
            'value': value,
            'type': 'email',
            'normalized_value': value,
            'display_value': value.replace('@', '[@]').replace('.', '[.]'),
            'subtype': None,
            'fp_risk': 'low',
            'fp_reason': None,
            'metadata': {'domain': None, 'local_part': None}
        }
        
        # Validate format
        if not self.EMAIL_PATTERN.match(value):
            result['fp_risk'] = 'high'
            result['fp_reason'] = 'Invalid email format'
            return result
        
        # Extract parts
        parts = value.split('@')
        result['metadata']['local_part'] = parts[0]
        result['metadata']['domain'] = parts[1]
        
        # Check for free email providers
        if parts[1] in self.FREE_EMAIL_PROVIDERS:
            result['subtype'] = 'free_provider'
            result['fp_reason'] = 'Free email provider - lower confidence'
        
        return result
    
    def extract_domain_from_url(self, url):
        """Extract domain from a URL"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
            return domain
        except Exception:
            return None
    
    def defang(self, value, ioc_type=None):
        """Defang an IOC value for safe display"""
        if not ioc_type:
            ioc_type = self._detect_type(value)
        
        if ioc_type == 'ip':
            return value.replace('.', '[.]')
        elif ioc_type == 'domain':
            return value.replace('.', '[.]')
        elif ioc_type == 'url':
            # Defang the domain part
            try:
                parsed = urlparse(value)
                defanged_domain = parsed.netloc.replace('.', '[.]')
                return value.replace(parsed.netloc, defanged_domain)
            except Exception:
                return value.replace('.', '[.]')
        elif ioc_type == 'email':
            return value.replace('@', '[@]').replace('.', '[.]')
        else:
            return value
    
    def refang(self, value):
        """Refang a defanged IOC value"""
        return value.replace('[.]', '.').replace('[@]', '@').replace('hxxp', 'http')
