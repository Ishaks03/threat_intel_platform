"""
Threat Intelligence Correlation and IOC Validation Platform
Flask main application entry point
"""

import os
import json
from datetime import datetime
from flask import Flask, request, jsonify, render_template, Response
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import modules
from database.db_manager import DatabaseManager
from core.feed_manager import FeedManager
from core.ioc_parser import IOCParser
from core.ioc_validator import IOCValidator
from core.log_correlator import LogCorrelator
from core.threat_scorer import ThreatScorer
from core.enrichment_engine import EnrichmentEngine
from core.ai_briefing_generator import AIBriefingGenerator
from core.report_builder import ReportBuilder
from scheduler import init_scheduler

# Initialize Flask app
app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

# Get base directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Initialize database
db = DatabaseManager(os.path.join(BASE_DIR, 'threat_intel.db'))

# Initialize core modules
feed_manager = FeedManager(db, os.path.join(BASE_DIR, 'data'))
ioc_parser = IOCParser()
ioc_validator = IOCValidator(db)
log_correlator = LogCorrelator(db, os.path.join(BASE_DIR, 'data'))
threat_scorer = ThreatScorer()
enrichment_engine = EnrichmentEngine(db)
briefing_generator = AIBriefingGenerator(db)
report_builder = ReportBuilder(db, os.path.join(BASE_DIR, 'data'))

# Initialize scheduler
scheduler = init_scheduler(db, feed_manager, log_correlator, briefing_generator)


# ═══════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════

@app.route('/')
def index():
    """Serve the main dashboard"""
    return render_template('index.html')


# ─── Feed Routes ───────────────────────────────

@app.route('/api/feeds/refresh', methods=['POST'])
def refresh_feeds():
    """Trigger manual refresh of all threat intel feeds"""
    try:
        feed_name = request.json.get('feed_name') if request.json else None
        
        if feed_name:
            result = feed_manager.refresh_single_feed(feed_name)
            return jsonify(result)
        else:
            result = feed_manager.refresh_all_feeds()
            return jsonify({
                'feeds_updated': result.get('feeds_updated', 0),
                'new_iocs_added': result.get('total_new_iocs', 0),
                'feed_status_list': result.get('feed_results', [])
            })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/feeds/status', methods=['GET'])
def get_feed_status():
    """Get current status of all configured feeds"""
    try:
        status = feed_manager.get_feed_status()
        return jsonify({'feeds': status})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── IOC Routes ────────────────────────────────

@app.route('/api/iocs', methods=['GET'])
def get_iocs():
    """Get paginated list of IOCs with filters"""
    try:
        filters = {
            'type': request.args.get('type'),
            'severity': request.args.get('severity'),
            'feed': request.args.get('feed'),
            'threat_type': request.args.get('threat_type'),
            'search': request.args.get('search'),
            'page': int(request.args.get('page', 1)),
            'limit': int(request.args.get('limit', 50)),
            'active_only': request.args.get('active_only', 'true').lower() == 'true'
        }
        
        result = db.get_iocs_paginated(filters)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/iocs/<int:ioc_id>', methods=['GET'])
def get_ioc(ioc_id):
    """Get a specific IOC by ID"""
    try:
        ioc = db.get_ioc_by_id(ioc_id)
        if not ioc:
            return jsonify({'error': 'IOC not found'}), 404
        
        # Get correlations for this IOC
        correlations = db.get_correlations({'ioc_id': ioc_id})
        ioc['correlations'] = correlations
        
        return jsonify(ioc)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/iocs/search', methods=['POST'])
def search_ioc():
    """Search for specific IOC"""
    try:
        data = request.json
        value = data.get('value', '')
        
        if not value:
            return jsonify({'error': 'Value is required'}), 400
        
        ioc = db.get_ioc_by_value(value)
        
        if not ioc:
            return jsonify({'found': False, 'message': 'IOC not found'})
        
        # Get correlations
        correlations = db.get_correlations({'ioc_id': ioc.get('id')})
        ioc['correlations'] = correlations
        
        return jsonify({'found': True, 'ioc': ioc})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/iocs/manual', methods=['POST'])
def add_manual_ioc():
    """Add a manually submitted IOC"""
    try:
        data = request.json
        
        required = ['ioc_value', 'ioc_type']
        for field in required:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        # Parse and validate
        parsed = ioc_parser.parse(data['ioc_value'], data['ioc_type'])
        
        if not parsed or parsed.get('fp_risk') == 'high':
            if parsed and parsed.get('fp_reason'):
                return jsonify({'error': f'Invalid IOC: {parsed["fp_reason"]}'}), 400
            return jsonify({'error': 'Invalid IOC format'}), 400
        
        # Build IOC record
        ioc_record = {
            'ioc_value': parsed['normalized_value'] or data['ioc_value'],
            'ioc_type': data['ioc_type'],
            'source_feed': 'Manual',
            'threat_type': data.get('threat_type', 'unknown'),
            'malware_family': data.get('malware_family'),
            'confidence': data.get('confidence', 70),
            'severity': data.get('severity', 'Medium'),
            'first_seen': datetime.utcnow().isoformat(),
            'last_seen': datetime.utcnow().isoformat(),
            'tags': json.dumps(data.get('tags', ['manual'])),
            'is_active': 1,
            'false_positive': 0
        }
        
        # Validate
        validation = ioc_validator.validate(ioc_record)
        if validation['false_positive']:
            return jsonify({
                'error': f'IOC flagged as false positive: {validation["fp_reason"]}'
            }), 400
        
        # Insert
        ioc_id = db.insert_ioc(ioc_record)
        ioc_record['id'] = ioc_id
        
        return jsonify({'success': True, 'ioc': ioc_record}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/iocs/<int:ioc_id>/fp', methods=['POST'])
def mark_false_positive(ioc_id):
    """Mark an IOC as false positive"""
    try:
        db.update_ioc(ioc_id, {'false_positive': 1, 'is_active': 0})
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── Correlation Routes ────────────────────────

@app.route('/api/correlations', methods=['GET'])
def get_correlations():
    """Get paginated correlation results"""
    try:
        filters = {
            'verdict': request.args.get('verdict'),
            'date_from': request.args.get('date_from'),
            'date_to': request.args.get('date_to'),
            'host': request.args.get('host'),
            'page': int(request.args.get('page', 1)),
            'limit': int(request.args.get('limit', 50))
        }
        
        result = db.get_correlations_paginated(filters)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/correlate', methods=['POST'])
def run_correlation():
    """Trigger manual correlation run"""
    try:
        result = log_correlator.run_correlation()
        
        # Count by verdict
        correlations = result.get('correlations', [])
        confirmed = sum(1 for c in correlations if c.get('verdict') == 'Confirmed Threat')
        suspicious = sum(1 for c in correlations if c.get('verdict') == 'Suspicious - Needs Review')
        
        return jsonify({
            'new_correlations_count': result.get('new_correlations', 0),
            'confirmed_threats': confirmed,
            'suspicious_matches': suspicious,
            'summary': f"Found {result.get('new_correlations', 0)} correlations: "
                      f"{confirmed} confirmed, {suspicious} suspicious"
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/correlations/<int:corr_id>/reviewed', methods=['POST'])
def mark_reviewed(corr_id):
    """Mark a correlation as reviewed"""
    try:
        reviewed = request.json.get('reviewed', True)
        db.update_correlation_reviewed(corr_id, reviewed)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── Enrichment Routes ─────────────────────────

@app.route('/api/enrich', methods=['POST'])
def enrich_iocs():
    """Enrich IOCs with VT and AbuseIPDB"""
    try:
        data = request.json or {}
        ioc_ids = data.get('ioc_ids', [])
        enrich_all = data.get('enrich_all', False)
        
        results = enrichment_engine.enrich_batch(ioc_ids, enrich_all, max_count=5)
        
        return jsonify({
            'enriched_count': sum(1 for r in results if r.get('enriched')),
            'results': results
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/enrich/status', methods=['GET'])
def get_enrichment_status():
    """Get enrichment status and statistics"""
    try:
        status = enrichment_engine.get_enrichment_status()
        return jsonify(status)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── Dashboard Routes ──────────────────────────

@app.route('/api/dashboard', methods=['GET'])
def get_dashboard():
    """Get all data for dashboard home tab"""
    try:
        stats = db.get_dashboard_stats()
        feed_status = feed_manager.get_feed_status()
        
        return jsonify({
            'total_iocs': stats.get('total_iocs', 0),
            'active_iocs': stats.get('active_iocs', 0),
            'false_positives': stats.get('false_positives', 0),
            'confirmed_threats': stats.get('confirmed_threats', 0),
            'total_correlations': stats.get('total_correlations', 0),
            'suspicious_matches': stats.get('suspicious_matches', 0),
            'feed_status_list': feed_status,
            'recent_correlations': stats.get('recent_correlations', []),
            'threat_level_distribution': stats.get('threat_level_distribution', {}),
            'top_malware_families': stats.get('top_malware_families', []),
            'iocs_by_type': stats.get('iocs_by_type', {}),
            'timeline_data': stats.get('timeline_data', [])
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── Briefing Routes ───────────────────────────

@app.route('/api/briefing/daily', methods=['POST'])
def generate_daily_briefing():
    """Generate daily threat briefing"""
    try:
        briefing = briefing_generator.generate_daily_briefing()
        
        # Save report with briefing
        report = report_builder.build_correlation_report(ai_briefing=briefing)
        
        return jsonify({
            'briefing': briefing,
            'report_id': report.get('report_id'),
            'generated_at': datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/briefing/ioc', methods=['POST'])
def generate_ioc_briefing():
    """Generate IOC investigation report"""
    try:
        data = request.json or {}
        ioc_id = data.get('ioc_id')
        
        if not ioc_id:
            return jsonify({'error': 'ioc_id is required'}), 400
        
        briefing = briefing_generator.generate_ioc_report(ioc_id)
        
        return jsonify({
            'briefing': briefing,
            'generated_at': datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── Export Routes ─────────────────────────────

@app.route('/api/export/csv', methods=['GET'])
def export_csv():
    """Export IOCs as CSV"""
    try:
        csv_data = report_builder.export_iocs_csv()
        
        return Response(
            csv_data,
            mimetype='text/csv',
            headers={
                'Content-Disposition': 'attachment; filename=iocs_export.csv'
            }
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/export/txt', methods=['GET'])
def export_txt():
    """Export IOC values as plain text"""
    try:
        txt_data = report_builder.export_iocs_txt()
        
        return Response(
            txt_data,
            mimetype='text/plain',
            headers={
                'Content-Disposition': 'attachment; filename=iocs.txt'
            }
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── Report Routes ─────────────────────────────

@app.route('/api/reports', methods=['GET'])
def get_reports():
    """Get list of all saved reports"""
    try:
        reports = report_builder.get_all_reports()
        return jsonify({'reports': reports})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/reports/<report_id>', methods=['GET'])
def get_report(report_id):
    """Get full report by ID"""
    try:
        report = report_builder.get_full_report(report_id)
        if not report:
            return jsonify({'error': 'Report not found'}), 404
        return jsonify(report)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── Demo Routes ───────────────────────────────

@app.route('/api/demo/load', methods=['GET'])
def load_demo():
    """Load demo IOC dataset and run correlation"""
    try:
        # Load demo IOCs
        demo_result = feed_manager.load_demo_feed()
        
        # Run correlation
        corr_result = log_correlator.run_correlation()
        
        # Generate briefing
        briefing = briefing_generator.generate_daily_briefing()
        
        # Build report
        report = report_builder.build_correlation_report(ai_briefing=briefing)
        
        return jsonify({
            'demo_loaded': True,
            'iocs_loaded': demo_result.get('new_iocs_added', 0),
            'correlations_found': corr_result.get('new_correlations', 0),
            'report': report
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/demo/reset', methods=['GET'])
def reset_demo():
    """Clear all data and reload fresh demo dataset"""
    try:
        # Clear database
        db.clear_all_data()
        
        # Reload demo
        demo_result = feed_manager.load_demo_feed()
        
        # Run correlation
        corr_result = log_correlator.run_correlation()
        
        return jsonify({
            'reset': True,
            'iocs_loaded': demo_result.get('new_iocs_added', 0),
            'correlations_found': corr_result.get('new_correlations', 0)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── Scheduler Routes ──────────────────────────

@app.route('/api/scheduler/status', methods=['GET'])
def get_scheduler_status():
    """Get scheduler status and job information"""
    try:
        status = scheduler.get_job_status()
        return jsonify(status)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scheduler/run/<job_name>', methods=['POST'])
def run_scheduler_job(job_name):
    """Manually trigger a scheduler job"""
    try:
        result = scheduler.run_job_now(job_name)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── Utility Routes ────────────────────────────

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0'
    })


@app.route('/api/config', methods=['GET'])
def get_config():
    """Get platform configuration status"""
    return jsonify({
        'gemini_configured': bool(os.getenv('GEMINI_API_KEY')),
        'virustotal_configured': bool(os.getenv('VIRUSTOTAL_API_KEY')),
        'abuseipdb_configured': bool(os.getenv('ABUSEIPDB_API_KEY')),
        'demo_mode': not any([
            os.getenv('GEMINI_API_KEY'),
            os.getenv('VIRUSTOTAL_API_KEY'),
            os.getenv('ABUSEIPDB_API_KEY')
        ])
    })


# ═══════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════

if __name__ == '__main__':
    # Start scheduler
    scheduler.start()
    
    # Run Flask app
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    )
