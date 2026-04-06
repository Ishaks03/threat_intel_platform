"""
Report Builder - Build and save comprehensive correlation reports
"""

import os
import json
import uuid
from datetime import datetime


class ReportBuilder:
    def __init__(self, db_manager, data_dir='data'):
        self.db = db_manager
        self.data_dir = data_dir
        self.reports_dir = os.path.join(data_dir, 'reports')
        
        os.makedirs(self.reports_dir, exist_ok=True)
    
    def build_correlation_report(self, ai_briefing=None):
        """Build comprehensive correlation report"""
        now = datetime.utcnow()
        report_id = f"TI-{now.strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        
        # Gather statistics
        stats = self.db.get_dashboard_stats()
        correlations = self.db.get_correlations({})
        feed_status = self.db.get_feed_status()
        
        # Calculate additional stats
        confirmed_threats = sum(1 for c in correlations if c.get('verdict') == 'Confirmed Threat')
        suspicious_matches = sum(1 for c in correlations if c.get('verdict') == 'Suspicious - Needs Review')
        low_confidence = sum(1 for c in correlations if c.get('verdict') == 'Low Confidence Match')
        
        # Get affected hosts
        affected_hosts = set()
        for corr in correlations:
            log_entry = corr.get('log_entry', {})
            if isinstance(log_entry, str):
                try:
                    log_entry = json.loads(log_entry)
                except json.JSONDecodeError:
                    log_entry = {}
            if log_entry.get('hostname'):
                affected_hosts.add(log_entry['hostname'])
        
        # Get unique malware families
        malware_families = set()
        for corr in correlations:
            family = corr.get('malware_family')
            if family:
                malware_families.add(family)
        
        # Sort correlations by threat score
        sorted_correlations = sorted(
            correlations, 
            key=lambda x: x.get('threat_score', 0), 
            reverse=True
        )
        
        report = {
            'report_id': report_id,
            'generated_at': now.isoformat(),
            'report_type': 'correlation',
            'period': 'last_24h',
            'statistics': {
                'total_iocs_tracked': stats.get('total_iocs', 0),
                'active_iocs': stats.get('active_iocs', 0),
                'false_positives_filtered': stats.get('false_positives', 0),
                'correlations_found': len(correlations),
                'confirmed_threats': confirmed_threats,
                'suspicious_matches': suspicious_matches,
                'low_confidence_matches': low_confidence,
                'internal_hosts_affected': len(affected_hosts),
                'unique_malware_families': len(malware_families)
            },
            'top_threats': sorted_correlations[:10],
            'correlations': correlations,
            'feed_summary': feed_status,
            'ai_briefing': ai_briefing
        }
        
        # Save to file
        report_file = os.path.join(self.reports_dir, f'{report_id}.json')
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # Save to database
        self.db.save_report({
            'report_id': report_id,
            'total_iocs': stats.get('total_iocs', 0),
            'total_matches': len(correlations),
            'confirmed_threats': confirmed_threats,
            'false_positives': stats.get('false_positives', 0),
            'report_data': report,
            'ai_briefing': ai_briefing
        })
        
        return report
    
    def export_iocs_csv(self):
        """Export all active non-FP IOCs as CSV"""
        iocs = self.db.get_all_active_iocs()
        
        # CSV header
        columns = [
            'ioc_value', 'ioc_type', 'severity', 'threat_type', 
            'malware_family', 'confidence', 'source_feed', 
            'first_seen', 'last_seen'
        ]
        
        csv_lines = [','.join(columns)]
        
        for ioc in iocs:
            row = []
            for col in columns:
                value = ioc.get(col, '')
                if value is None:
                    value = ''
                # Escape commas and quotes in values
                value = str(value).replace('"', '""')
                if ',' in value or '"' in value:
                    value = f'"{value}"'
                row.append(value)
            csv_lines.append(','.join(row))
        
        return '\n'.join(csv_lines)
    
    def export_iocs_txt(self):
        """Export all active IOC values as plain text (one per line)"""
        iocs = self.db.get_all_active_iocs()
        
        lines = [ioc.get('ioc_value', '') for ioc in iocs if ioc.get('ioc_value')]
        
        return '\n'.join(lines)
    
    def export_iocs_json(self):
        """Export all active IOCs as JSON"""
        iocs = self.db.get_all_active_iocs()
        return json.dumps(iocs, indent=2, default=str)
    
    def get_report_summary(self, report_id):
        """Get summary of a saved report"""
        report = self.db.get_report_by_id(report_id)
        if not report:
            return None
        
        return {
            'report_id': report.get('report_id'),
            'generated_at': report.get('generated_at'),
            'total_iocs': report.get('total_iocs'),
            'total_matches': report.get('total_matches'),
            'confirmed_threats': report.get('confirmed_threats'),
            'false_positives': report.get('false_positives')
        }
    
    def get_all_reports(self):
        """Get list of all saved reports"""
        return self.db.get_reports()
    
    def get_full_report(self, report_id):
        """Get full report data"""
        report = self.db.get_report_by_id(report_id)
        
        if not report:
            # Try loading from file
            report_file = os.path.join(self.reports_dir, f'{report_id}.json')
            if os.path.exists(report_file):
                with open(report_file, 'r') as f:
                    return json.load(f)
            return None
        
        return report
    
    def build_executive_summary(self):
        """Build an executive-level summary"""
        stats = self.db.get_dashboard_stats()
        
        summary = {
            'generated_at': datetime.utcnow().isoformat(),
            'threat_posture': self._calculate_threat_posture(stats),
            'key_metrics': {
                'total_iocs': stats.get('total_iocs', 0),
                'active_threats': stats.get('active_iocs', 0),
                'confirmed_incidents': stats.get('confirmed_threats', 0),
                'false_positive_rate': self._calculate_fp_rate(stats)
            },
            'top_threat_types': self._get_top_threat_types(),
            'trend': self._calculate_trend(stats)
        }
        
        return summary
    
    def _calculate_threat_posture(self, stats):
        """Calculate overall threat posture"""
        confirmed = stats.get('confirmed_threats', 0)
        total = stats.get('total_correlations', 1) or 1
        
        ratio = confirmed / total
        
        if ratio >= 0.5:
            return 'CRITICAL'
        elif ratio >= 0.3:
            return 'HIGH'
        elif ratio >= 0.1:
            return 'ELEVATED'
        else:
            return 'NORMAL'
    
    def _calculate_fp_rate(self, stats):
        """Calculate false positive rate"""
        fp = stats.get('false_positives', 0)
        total = stats.get('total_iocs', 1) or 1
        
        return round((fp / total) * 100, 2)
    
    def _get_top_threat_types(self):
        """Get distribution of threat types"""
        iocs = self.db.get_all_active_iocs()
        
        types = {}
        for ioc in iocs:
            threat_type = ioc.get('threat_type', 'unknown')
            types[threat_type] = types.get(threat_type, 0) + 1
        
        # Sort by count
        sorted_types = sorted(types.items(), key=lambda x: x[1], reverse=True)
        
        return sorted_types[:5]
    
    def _calculate_trend(self, stats):
        """Calculate threat trend (placeholder - would need historical data)"""
        timeline = stats.get('timeline_data', [])
        
        if len(timeline) < 2:
            return 'STABLE'
        
        recent = sum(d.get('count', 0) for d in timeline[-3:])
        older = sum(d.get('count', 0) for d in timeline[:-3])
        
        if recent > older * 1.2:
            return 'INCREASING'
        elif recent < older * 0.8:
            return 'DECREASING'
        else:
            return 'STABLE'
    
    def save_report_to_file(self, report, filename=None):
        """Save a report dictionary to a JSON file"""
        if not filename:
            report_id = report.get('report_id', f"report-{uuid.uuid4().hex[:8]}")
            filename = f'{report_id}.json'
        
        filepath = os.path.join(self.reports_dir, filename)
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        return filepath
