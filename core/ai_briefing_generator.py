"""
AI Briefing Generator - Generate threat intelligence briefings using Gemini AI
"""

import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()


def get_gemini_model():
    """Initialize and return Gemini model if API key is available"""
    api_key = os.getenv('GEMINI_API_KEY')
    if not api_key:
        return None
    
    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        return genai.GenerativeModel('gemini-1.5-flash')
    except Exception:
        return None


class AIBriefingGenerator:
    def __init__(self, db_manager):
        self.db = db_manager
    
    def generate_briefing(self, briefing_type, data):
        """
        Generate a threat intelligence briefing
        
        Args:
            briefing_type: 'daily', 'ioc_investigation', or 'feed_summary'
            data: Dictionary with relevant data for the briefing
        
        Returns:
            Markdown formatted briefing text
        """
        model = get_gemini_model()
        
        if model is None:
            return self._generate_fallback_briefing(briefing_type, data)
        
        try:
            prompt = self._build_prompt(briefing_type, data)
            response = model.generate_content(prompt)
            return response.text
        except Exception as e:
            return self._generate_fallback_briefing(briefing_type, data)
    
    def _build_prompt(self, briefing_type, data):
        """Build the appropriate prompt for the briefing type"""
        
        if briefing_type == 'daily':
            return self._build_daily_prompt(data)
        elif briefing_type == 'ioc_investigation':
            return self._build_ioc_investigation_prompt(data)
        elif briefing_type == 'feed_summary':
            return self._build_feed_summary_prompt(data)
        else:
            return f"Generate a brief security summary for: {data}"
    
    def _build_daily_prompt(self, data):
        """Build prompt for daily threat briefing"""
        return f"""You are a senior threat intelligence analyst. Generate a professional daily threat intelligence briefing based on the following data. Use markdown formatting.

DATA:
- Date: {data.get('date', datetime.utcnow().strftime('%Y-%m-%d'))}
- Total IOCs tracked: {data.get('total_iocs', 0)}
- New IOCs today: {data.get('new_iocs', 0)}
- Active threats: {data.get('active_threats', 0)}
- Correlations found: {data.get('correlations_found', 0)}
- Confirmed threats: {data.get('confirmed_threats', 0)}
- False positives filtered: {data.get('false_positives', 0)}
- Top threats: {data.get('top_threats', [])}
- Affected internal hosts: {data.get('affected_hosts', [])}
- Affected users: {data.get('affected_users', [])}
- Active malware families: {data.get('malware_families', [])}

Generate the briefing with EXACTLY this structure:

## Threat Intelligence Daily Briefing — {data.get('date', datetime.utcnow().strftime('%Y-%m-%d'))}

### Executive Summary
(2-3 sentences summarizing today's threat landscape and key metrics)

### Top Threats Today
(List each of the top 5 threats with IOC value, type, malware family, threat score, and why it's dangerous)

### Active Attack Campaigns
(Identify any patterns suggesting coordinated campaigns based on shared malware families or timing)

### Affected Internal Assets
(List internal hosts and users that had IOC matches, what was contacted)

### Recommended Immediate Actions
(Prioritized numbered list of response steps based on confirmed threats)

### Threat Outlook
(What to watch for in the next 24-48 hours based on current trends)

Be specific and actionable. Use the actual data provided."""
    
    def _build_ioc_investigation_prompt(self, data):
        """Build prompt for IOC investigation report"""
        return f"""You are a senior threat intelligence analyst. Generate a detailed IOC investigation report based on the following data. Use markdown formatting.

IOC DATA:
- IOC Value: {data.get('ioc_value', 'Unknown')}
- IOC Type: {data.get('ioc_type', 'Unknown')}
- Source Feeds: {data.get('source_feeds', [])}
- Confidence: {data.get('confidence', 0)}
- Severity: {data.get('severity', 'Unknown')}
- Threat Type: {data.get('threat_type', 'Unknown')}
- Malware Family: {data.get('malware_family', 'Unknown')}
- First Seen: {data.get('first_seen', 'Unknown')}
- Last Seen: {data.get('last_seen', 'Unknown')}
- Tags: {data.get('tags', [])}

ENRICHMENT DATA:
- VirusTotal: {data.get('virustotal', 'Not available')}
- AbuseIPDB: {data.get('abuseipdb', 'Not available')}

CORRELATIONS:
{data.get('correlations', 'No correlations found')}

Generate the report with EXACTLY this structure:

## IOC Investigation Report: {data.get('ioc_value', 'Unknown')}

### IOC Profile
(Type, defanged value, sources, confidence level, severity, timeline)

### Threat Context
(What this IOC is used for, known malware family information, attack patterns)

### Internal Impact Assessment
(Which internal hosts contacted this IOC, timeline of contacts, affected users)

### Threat Intelligence Details
(VirusTotal findings, AbuseIPDB findings, detection ratios)

### Recommended Response Actions
(Prioritized steps: block IOC, hunt for lateral movement, check other hosts, etc.)

Be specific and actionable. Use the actual data provided."""
    
    def _build_feed_summary_prompt(self, data):
        """Build prompt for feed summary briefing"""
        return f"""You are a senior threat intelligence analyst. Generate a brief feed health and summary report. Use markdown formatting.

FEED STATUS:
{data.get('feed_status', [])}

IOC STATISTICS:
- Total IOCs: {data.get('total_iocs', 0)}
- IOCs by feed: {data.get('iocs_by_feed', {})}
- New IOCs in last 24h: {data.get('new_iocs_24h', 0)}

Generate a brief 1-page summary covering:
1. Feed health status (which feeds are active/error)
2. New threats entering the platform
3. Feed reliability assessment
4. Recommendations for feed management"""
    
    def _generate_fallback_briefing(self, briefing_type, data):
        """Generate fallback briefing when Gemini is unavailable"""
        
        if briefing_type == 'daily':
            return self._fallback_daily_briefing(data)
        elif briefing_type == 'ioc_investigation':
            return self._fallback_ioc_investigation(data)
        elif briefing_type == 'feed_summary':
            return self._fallback_feed_summary(data)
        else:
            return "## Briefing\n\nUnable to generate AI briefing. Please check API key configuration."
    
    def _fallback_daily_briefing(self, data):
        """Fallback template for daily briefing"""
        date = data.get('date', datetime.utcnow().strftime('%Y-%m-%d'))
        total_iocs = data.get('total_iocs', 0)
        new_iocs = data.get('new_iocs', 0)
        correlations = data.get('correlations_found', 0)
        confirmed = data.get('confirmed_threats', 0)
        affected_hosts = data.get('affected_hosts', [])
        affected_users = data.get('affected_users', [])
        top_threats = data.get('top_threats', [])
        
        briefing = f"""## Threat Intelligence Daily Briefing — {date}

### Executive Summary

Today's threat monitoring identified **{total_iocs}** total IOCs with **{new_iocs}** new indicators added. 
The correlation engine found **{correlations}** matches against internal logs, with **{confirmed}** confirmed as threats requiring immediate attention.

### Top Threats Today

"""
        
        if top_threats:
            for i, threat in enumerate(top_threats[:5], 1):
                ioc_val = threat.get('ioc_value', 'Unknown')
                ioc_type = threat.get('ioc_type', 'unknown')
                malware = threat.get('malware_family', 'Unknown')
                score = threat.get('threat_score', 0)
                briefing += f"{i}. **{ioc_val}** ({ioc_type})\n"
                briefing += f"   - Malware Family: {malware}\n"
                briefing += f"   - Threat Score: {score}/100\n\n"
        else:
            briefing += "No high-priority threats identified today.\n\n"
        
        briefing += """### Active Attack Campaigns

Based on the IOCs observed today, the following potential campaigns have been identified:
- Multiple Cobalt Strike C2 indicators suggest active intrusion attempts
- Emotet loader activity detected in malware distribution URLs
- Credential harvesting phishing pages targeting corporate users

### Affected Internal Assets

"""
        
        if affected_hosts:
            briefing += f"**Hosts with IOC matches:** {', '.join(affected_hosts[:10])}\n\n"
        else:
            briefing += "No internal hosts matched IOC indicators today.\n\n"
        
        if affected_users:
            briefing += f"**Users potentially affected:** {', '.join(affected_users[:10])}\n\n"
        
        briefing += """### Recommended Immediate Actions

1. Block confirmed malicious IPs and domains at perimeter firewalls
2. Investigate workstations with confirmed C2 communication
3. Reset credentials for any users with suspicious activity
4. Update endpoint detection signatures with new hash IOCs
5. Review proxy logs for additional suspicious connections

### Threat Outlook

Monitor for:
- Increased phishing activity following recent campaigns
- Lateral movement attempts from compromised endpoints
- New malware variants from observed families

---
*Generated by ThreatVision Platform (Fallback Mode)*
"""
        
        return briefing
    
    def _fallback_ioc_investigation(self, data):
        """Fallback template for IOC investigation report"""
        ioc_value = data.get('ioc_value', 'Unknown')
        ioc_type = data.get('ioc_type', 'unknown')
        confidence = data.get('confidence', 0)
        severity = data.get('severity', 'Unknown')
        threat_type = data.get('threat_type', 'Unknown')
        malware = data.get('malware_family', 'Unknown')
        first_seen = data.get('first_seen', 'Unknown')
        vt_data = data.get('virustotal', {})
        abuse_data = data.get('abuseipdb', {})
        correlations = data.get('correlations', [])
        
        # Defang the IOC for display
        display_value = ioc_value.replace('.', '[.]')
        
        report = f"""## IOC Investigation Report: {display_value}

### IOC Profile

| Field | Value |
|-------|-------|
| **IOC Value** | `{display_value}` |
| **Type** | {ioc_type} |
| **Confidence** | {confidence}% |
| **Severity** | {severity} |
| **Threat Type** | {threat_type} |
| **Malware Family** | {malware} |
| **First Seen** | {first_seen} |

### Threat Context

This {ioc_type} indicator is associated with **{threat_type}** activity, specifically linked to the **{malware}** malware family. 

"""
        
        if threat_type == 'c2':
            report += "This appears to be Command & Control infrastructure used for remote access and data exfiltration.\n\n"
        elif threat_type == 'phishing':
            report += "This indicator is associated with credential harvesting or phishing campaigns.\n\n"
        elif threat_type == 'malware':
            report += "This indicator is linked to malware distribution or payload delivery.\n\n"
        
        report += "### Internal Impact Assessment\n\n"
        
        if correlations:
            report += f"**{len(correlations)}** internal log matches found:\n\n"
            for corr in correlations[:5]:
                log_entry = corr.get('log_entry', {})
                host = log_entry.get('hostname', 'Unknown')
                user = log_entry.get('user', log_entry.get('username', 'Unknown'))
                timestamp = corr.get('matched_at', 'Unknown')
                report += f"- {host} (User: {user}) at {timestamp}\n"
        else:
            report += "No internal log matches found for this IOC.\n"
        
        report += "\n### Threat Intelligence Details\n\n"
        
        if vt_data:
            detection = vt_data.get('detection_ratio', 'N/A')
            report += f"**VirusTotal:** {detection} engines flagged as malicious\n"
            if vt_data.get('malware_names'):
                report += f"  - Detection names: {', '.join(vt_data['malware_names'][:5])}\n"
        else:
            report += "**VirusTotal:** No data available\n"
        
        if abuse_data:
            score = abuse_data.get('abuse_confidence_score', 0)
            reports = abuse_data.get('total_reports', 0)
            report += f"\n**AbuseIPDB:** Abuse confidence {score}%, {reports} reports\n"
        
        report += """
### Recommended Response Actions

1. **Immediate:** Block this IOC at all network perimeters
2. **Investigation:** Analyze affected hosts for compromise indicators
3. **Containment:** Isolate affected endpoints if C2 communication confirmed
4. **Remediation:** Remove any malware and reset compromised credentials
5. **Recovery:** Monitor for reinfection attempts

---
*Generated by ThreatVision Platform (Fallback Mode)*
"""
        
        return report
    
    def _fallback_feed_summary(self, data):
        """Fallback template for feed summary"""
        feed_status = data.get('feed_status', [])
        total_iocs = data.get('total_iocs', 0)
        iocs_by_feed = data.get('iocs_by_feed', {})
        
        summary = """## Threat Feed Summary Report

### Feed Health Status

"""
        
        for feed in feed_status:
            name = feed.get('feed_name', 'Unknown')
            status = feed.get('status', 'unknown')
            count = feed.get('ioc_count', 0)
            status_icon = '🟢' if status == 'active' else '🔴' if status == 'error' else '⚪'
            summary += f"{status_icon} **{name}**: {status.title()} ({count} IOCs)\n"
        
        summary += f"""
### IOC Statistics

- **Total IOCs:** {total_iocs}
- **Active feeds:** {sum(1 for f in feed_status if f.get('status') == 'active')}

### Recommendations

1. Verify API connectivity for any feeds showing errors
2. Consider increasing refresh frequency during active campaigns
3. Review feed overlap to optimize coverage

---
*Generated by ThreatVision Platform (Fallback Mode)*
"""
        
        return summary
    
    def generate_daily_briefing(self):
        """Generate daily briefing with current data from database"""
        stats = self.db.get_dashboard_stats()
        correlations = self.db.get_correlations({'limit': 10})
        
        # Get affected hosts and users from correlations
        affected_hosts = set()
        affected_users = set()
        for corr in correlations:
            log_entry = corr.get('log_entry', {})
            if log_entry.get('hostname'):
                affected_hosts.add(log_entry['hostname'])
            user = log_entry.get('user') or log_entry.get('username')
            if user:
                affected_users.add(user)
        
        data = {
            'date': datetime.utcnow().strftime('%Y-%m-%d'),
            'total_iocs': stats.get('total_iocs', 0),
            'new_iocs': stats.get('active_iocs', 0),
            'active_threats': stats.get('active_iocs', 0),
            'correlations_found': stats.get('total_correlations', 0),
            'confirmed_threats': stats.get('confirmed_threats', 0),
            'false_positives': stats.get('false_positives', 0),
            'top_threats': stats.get('recent_correlations', []),
            'affected_hosts': list(affected_hosts),
            'affected_users': list(affected_users),
            'malware_families': [f['name'] for f in stats.get('top_malware_families', [])]
        }
        
        return self.generate_briefing('daily', data)
    
    def generate_ioc_report(self, ioc_id):
        """Generate IOC investigation report for a specific IOC"""
        ioc = self.db.get_ioc_by_id(ioc_id)
        if not ioc:
            return "## Error\n\nIOC not found."
        
        correlations = self.db.get_correlations({'ioc_id': ioc_id})
        
        data = {
            'ioc_value': ioc.get('ioc_value'),
            'ioc_type': ioc.get('ioc_type'),
            'source_feeds': [ioc.get('source_feed')],
            'confidence': ioc.get('confidence'),
            'severity': ioc.get('severity'),
            'threat_type': ioc.get('threat_type'),
            'malware_family': ioc.get('malware_family'),
            'first_seen': ioc.get('first_seen'),
            'last_seen': ioc.get('last_seen'),
            'tags': ioc.get('tags', []),
            'virustotal': ioc.get('enrichment_data', {}).get('virustotal') if ioc.get('enrichment_data') else None,
            'abuseipdb': ioc.get('enrichment_data', {}).get('abuseipdb') if ioc.get('enrichment_data') else None,
            'correlations': correlations
        }
        
        return self.generate_briefing('ioc_investigation', data)
