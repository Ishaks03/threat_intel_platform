"""
Threat Scorer - Calculate threat scores for IOC correlations
"""

from datetime import datetime, timedelta


class ThreatScorer:
    # Threat type bonuses
    THREAT_TYPE_BONUS = {
        'c2': 25,
        'command_and_control': 25,
        'ransomware': 25,
        'phishing': 20,
        'botnet': 15,
        'malware': 20,
        'malware_download': 20,
        'trojan': 18,
        'stealer': 22,
        'rat': 20
    }
    
    # Feed reliability bonuses
    FEED_RELIABILITY = {
        'ThreatFox': 5,
        'Feodo': 5,
        'MalwareBazaar': 3,
        'URLhaus': 3,
        'Demo': 0
    }
    
    # Suspicious ports that increase score
    SUSPICIOUS_PORTS = {4444, 1337, 31337, 8888, 6666, 5555, 4443, 9001}
    
    # Suspicious TLDs
    SUSPICIOUS_TLDS = {'.xyz', '.top', '.online', '.club', '.site', '.store'}
    
    def calculate_score(self, ioc, log_entry=None):
        """
        Calculate threat score for an IOC or correlation
        
        Args:
            ioc: IOC dictionary with confidence, threat_type, etc.
            log_entry: Optional log entry for correlation context
        
        Returns:
            Dictionary with score breakdown
        """
        result = {
            'final_score': 0,
            'breakdown': [],
            'threat_level': 'INFORMATIONAL'
        }
        
        total_score = 0
        
        # Base score from IOC confidence (0 to 50 points)
        confidence = ioc.get('confidence', 50)
        base_score = confidence // 2
        total_score += base_score
        result['breakdown'].append({
            'factor': 'Base confidence',
            'points': base_score,
            'detail': f'Confidence {confidence} / 2'
        })
        
        # Threat type bonus
        threat_type = (ioc.get('threat_type') or '').lower()
        threat_bonus = self.THREAT_TYPE_BONUS.get(threat_type, 0)
        if threat_bonus:
            total_score += threat_bonus
            result['breakdown'].append({
                'factor': 'Threat type',
                'points': threat_bonus,
                'detail': f'{threat_type} threat'
            })
        
        # Feed reliability bonus
        source_feed = ioc.get('source_feed', '')
        feed_bonus = self.FEED_RELIABILITY.get(source_feed, 0)
        if feed_bonus:
            total_score += feed_bonus
            result['breakdown'].append({
                'factor': 'Feed reliability',
                'points': feed_bonus,
                'detail': f'From {source_feed}'
            })
        
        # Context bonuses
        total_score = self._add_context_bonuses(ioc, log_entry, total_score, result)
        
        # Deductions
        total_score = self._apply_deductions(ioc, total_score, result)
        
        # Cap score
        total_score = max(0, min(100, total_score))
        result['final_score'] = total_score
        
        # Map to threat level
        result['threat_level'] = self._get_threat_level(total_score)
        
        return result
    
    def _add_context_bonuses(self, ioc, log_entry, total_score, result):
        """Add context-based score bonuses"""
        
        # Check for suspicious port in log entry
        if log_entry:
            port = log_entry.get('dst_port')
            if port and port in self.SUSPICIOUS_PORTS:
                total_score += 10
                result['breakdown'].append({
                    'factor': 'Suspicious port',
                    'points': 10,
                    'detail': f'Port {port} detected'
                })
        
        # Check for suspicious TLD in domain IOCs
        ioc_value = ioc.get('ioc_value', '')
        ioc_type = ioc.get('ioc_type', '')
        
        if ioc_type == 'domain':
            for tld in self.SUSPICIOUS_TLDS:
                if ioc_value.lower().endswith(tld):
                    total_score += 5
                    result['breakdown'].append({
                        'factor': 'Suspicious TLD',
                        'points': 5,
                        'detail': f'TLD: {tld}'
                    })
                    break
        
        # Recency bonus
        first_seen = ioc.get('first_seen')
        if first_seen:
            try:
                if isinstance(first_seen, str):
                    first_seen_dt = datetime.fromisoformat(first_seen.replace('Z', '+00:00'))
                else:
                    first_seen_dt = first_seen
                
                now = datetime.utcnow()
                if first_seen_dt.tzinfo:
                    first_seen_dt = first_seen_dt.replace(tzinfo=None)
                
                age_days = (now - first_seen_dt).days
                
                if age_days <= 1:
                    total_score += 10
                    result['breakdown'].append({
                        'factor': 'Very recent IOC',
                        'points': 10,
                        'detail': 'Seen in last 24 hours'
                    })
                elif age_days <= 7:
                    total_score += 5
                    result['breakdown'].append({
                        'factor': 'Recent IOC',
                        'points': 5,
                        'detail': 'Seen in last 7 days'
                    })
            except (ValueError, TypeError):
                pass
        
        # Malware family bonus for known dangerous families
        malware_family = (ioc.get('malware_family') or '').lower()
        dangerous_families = {
            'cobalt strike': 15,
            'cobaltstrike': 15,
            'emotet': 12,
            'qakbot': 12,
            'lockbit': 20,
            'redline': 10,
            'icedid': 10,
            'trickbot': 12,
            'ryuk': 20,
            'conti': 18,
            'revil': 18
        }
        
        for family, bonus in dangerous_families.items():
            if family in malware_family:
                total_score += bonus
                result['breakdown'].append({
                    'factor': 'Known malware family',
                    'points': bonus,
                    'detail': f'{malware_family}'
                })
                break
        
        return total_score
    
    def _apply_deductions(self, ioc, total_score, result):
        """Apply score deductions"""
        
        confidence = ioc.get('confidence', 50)
        
        # Deduction for low confidence
        if confidence < 50:
            total_score -= 5
            result['breakdown'].append({
                'factor': 'Low confidence',
                'points': -5,
                'detail': f'Confidence below 50: {confidence}'
            })
        
        # Check for single feed source (would need DB access for proper check)
        # For now, apply minor deduction if source is Demo
        if ioc.get('source_feed') == 'Demo':
            total_score -= 3
            result['breakdown'].append({
                'factor': 'Demo data',
                'points': -3,
                'detail': 'From demo dataset only'
            })
        
        return total_score
    
    def _get_threat_level(self, score):
        """Map numeric score to threat level"""
        if score >= 90:
            return 'CRITICAL'
        elif score >= 70:
            return 'HIGH'
        elif score >= 50:
            return 'MEDIUM'
        elif score >= 30:
            return 'LOW'
        else:
            return 'INFORMATIONAL'
    
    def score_correlation(self, correlation, ioc):
        """
        Score a correlation record
        
        Args:
            correlation: Correlation dictionary
            ioc: Associated IOC dictionary
        
        Returns:
            Score result dictionary
        """
        log_entry = correlation.get('log_entry', {})
        if isinstance(log_entry, str):
            import json
            try:
                log_entry = json.loads(log_entry)
            except json.JSONDecodeError:
                log_entry = {}
        
        return self.calculate_score(ioc, log_entry)
    
    def bulk_score(self, iocs):
        """Score multiple IOCs"""
        results = []
        for ioc in iocs:
            result = self.calculate_score(ioc)
            result['ioc_id'] = ioc.get('id')
            result['ioc_value'] = ioc.get('ioc_value')
            results.append(result)
        return results
    
    def get_score_summary(self, scores):
        """Get summary statistics for a list of scores"""
        if not scores:
            return {
                'count': 0,
                'avg_score': 0,
                'max_score': 0,
                'min_score': 0,
                'by_level': {}
            }
        
        score_values = [s.get('final_score', 0) for s in scores]
        
        by_level = {}
        for s in scores:
            level = s.get('threat_level', 'INFORMATIONAL')
            by_level[level] = by_level.get(level, 0) + 1
        
        return {
            'count': len(scores),
            'avg_score': sum(score_values) / len(score_values),
            'max_score': max(score_values),
            'min_score': min(score_values),
            'by_level': by_level
        }
