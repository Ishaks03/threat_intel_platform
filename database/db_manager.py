"""
Database Manager for Threat Intelligence Platform
SQLite database operations with retry logic and connection management
"""

import sqlite3
import json
import os
from datetime import datetime
from functools import wraps
import time


def retry_on_locked(max_retries=3, delay_ms=100):
    """Decorator that retries on sqlite3.OperationalError database locked"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_error = None
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except sqlite3.OperationalError as e:
                    if "database is locked" in str(e):
                        last_error = e
                        time.sleep(delay_ms / 1000.0)
                    else:
                        raise
            raise last_error
        return wrapper
    return decorator


class DatabaseManager:
    def __init__(self, db_path="threat_intel.db"):
        self.db_path = db_path
        self._init_database()

    def _init_database(self):
        """Initialize database and create tables from schema"""
        db_exists = os.path.exists(self.db_path)
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        
        schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
        if os.path.exists(schema_path):
            with open(schema_path, 'r') as f:
                schema = f.read()
            conn.executescript(schema)
        
        conn.commit()
        conn.close()

    def _get_connection(self):
        """Get a database connection with row factory"""
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

    @retry_on_locked()
    def insert_ioc(self, ioc_dict):
        """Insert a new IOC and return its ID"""
        now = datetime.utcnow().isoformat()
        ioc_dict['created_at'] = now
        ioc_dict['updated_at'] = now
        
        if 'tags' in ioc_dict and isinstance(ioc_dict['tags'], list):
            ioc_dict['tags'] = json.dumps(ioc_dict['tags'])
        if 'enrichment_data' in ioc_dict and isinstance(ioc_dict['enrichment_data'], dict):
            ioc_dict['enrichment_data'] = json.dumps(ioc_dict['enrichment_data'])
        
        columns = ', '.join(ioc_dict.keys())
        placeholders = ', '.join(['?' for _ in ioc_dict])
        
        with self._get_connection() as conn:
            try:
                cursor = conn.execute(
                    f"INSERT INTO iocs ({columns}) VALUES ({placeholders})",
                    list(ioc_dict.values())
                )
                conn.commit()
                return cursor.lastrowid
            except sqlite3.IntegrityError:
                existing = conn.execute(
                    "SELECT id FROM iocs WHERE ioc_value = ? AND ioc_type = ?",
                    (ioc_dict.get('ioc_value'), ioc_dict.get('ioc_type'))
                ).fetchone()
                if existing:
                    self.update_ioc(existing['id'], {'updated_at': now, 'last_seen': now})
                    return existing['id']
                return None

    @retry_on_locked()
    def get_ioc_by_value(self, value):
        """Get IOC by its value"""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM iocs WHERE ioc_value = ?", (value,)
            ).fetchone()
            if row:
                return self._row_to_dict(row)
            return None

    @retry_on_locked()
    def get_ioc_by_id(self, ioc_id):
        """Get IOC by its ID"""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM iocs WHERE id = ?", (ioc_id,)
            ).fetchone()
            if row:
                return self._row_to_dict(row)
            return None

    @retry_on_locked()
    def get_all_active_iocs(self, filters=None):
        """Get all active non-FP IOCs with optional filters"""
        filters = filters or {}
        query = "SELECT * FROM iocs WHERE is_active = 1 AND false_positive = 0"
        params = []
        
        if filters.get('type'):
            query += " AND ioc_type = ?"
            params.append(filters['type'])
        if filters.get('severity'):
            query += " AND severity = ?"
            params.append(filters['severity'])
        if filters.get('feed'):
            query += " AND source_feed = ?"
            params.append(filters['feed'])
        if filters.get('threat_type'):
            query += " AND threat_type = ?"
            params.append(filters['threat_type'])
        
        query += " ORDER BY created_at DESC"
        
        if filters.get('limit'):
            query += " LIMIT ?"
            params.append(filters['limit'])
            if filters.get('offset'):
                query += " OFFSET ?"
                params.append(filters['offset'])
        
        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_dict(row) for row in rows]

    @retry_on_locked()
    def get_iocs_paginated(self, filters=None):
        """Get IOCs with pagination and total count"""
        filters = filters or {}
        page = filters.get('page', 1)
        limit = filters.get('limit', 50)
        offset = (page - 1) * limit
        
        base_query = "FROM iocs WHERE 1=1"
        params = []
        
        if filters.get('active_only', True):
            base_query += " AND is_active = 1 AND false_positive = 0"
        if filters.get('type'):
            base_query += " AND ioc_type = ?"
            params.append(filters['type'])
        if filters.get('severity'):
            base_query += " AND severity = ?"
            params.append(filters['severity'])
        if filters.get('feed'):
            base_query += " AND source_feed = ?"
            params.append(filters['feed'])
        if filters.get('threat_type'):
            base_query += " AND threat_type = ?"
            params.append(filters['threat_type'])
        if filters.get('search'):
            base_query += " AND ioc_value LIKE ?"
            params.append(f"%{filters['search']}%")
        
        with self._get_connection() as conn:
            count_row = conn.execute(f"SELECT COUNT(*) as total {base_query}", params).fetchone()
            total = count_row['total']
            
            data_params = params + [limit, offset]
            rows = conn.execute(
                f"SELECT * {base_query} ORDER BY created_at DESC LIMIT ? OFFSET ?",
                data_params
            ).fetchall()
            
            return {
                'iocs': [self._row_to_dict(row) for row in rows],
                'total': total,
                'page': page,
                'limit': limit,
                'pages': (total + limit - 1) // limit
            }

    @retry_on_locked()
    def update_ioc(self, ioc_id, update_dict):
        """Update an IOC by ID"""
        update_dict['updated_at'] = datetime.utcnow().isoformat()
        
        if 'tags' in update_dict and isinstance(update_dict['tags'], list):
            update_dict['tags'] = json.dumps(update_dict['tags'])
        if 'enrichment_data' in update_dict and isinstance(update_dict['enrichment_data'], dict):
            update_dict['enrichment_data'] = json.dumps(update_dict['enrichment_data'])
        
        set_clause = ', '.join([f"{k} = ?" for k in update_dict.keys()])
        params = list(update_dict.values()) + [ioc_id]
        
        with self._get_connection() as conn:
            conn.execute(f"UPDATE iocs SET {set_clause} WHERE id = ?", params)
            conn.commit()
            return True

    @retry_on_locked()
    def insert_correlation(self, correlation_dict):
        """Insert a new correlation and return its ID"""
        now = datetime.utcnow().isoformat()
        correlation_dict['created_at'] = now
        
        if 'log_entry' in correlation_dict and isinstance(correlation_dict['log_entry'], dict):
            correlation_dict['log_entry'] = json.dumps(correlation_dict['log_entry'])
        
        columns = ', '.join(correlation_dict.keys())
        placeholders = ', '.join(['?' for _ in correlation_dict])
        
        with self._get_connection() as conn:
            try:
                cursor = conn.execute(
                    f"INSERT INTO correlations ({columns}) VALUES ({placeholders})",
                    list(correlation_dict.values())
                )
                conn.commit()
                return cursor.lastrowid
            except sqlite3.IntegrityError:
                return None

    @retry_on_locked()
    def get_correlations(self, filters=None):
        """Get correlations with optional filters"""
        filters = filters or {}
        query = """
            SELECT c.*, i.ioc_value, i.ioc_type, i.threat_type, i.malware_family, i.severity
            FROM correlations c
            LEFT JOIN iocs i ON c.ioc_id = i.id
            WHERE 1=1
        """
        params = []
        
        if filters.get('verdict'):
            query += " AND c.verdict = ?"
            params.append(filters['verdict'])
        if filters.get('date_from'):
            query += " AND c.matched_at >= ?"
            params.append(filters['date_from'])
        if filters.get('date_to'):
            query += " AND c.matched_at <= ?"
            params.append(filters['date_to'])
        if filters.get('host'):
            query += " AND c.log_entry LIKE ?"
            params.append(f'%"hostname":"{filters["host"]}"%')
        if filters.get('ioc_id'):
            query += " AND c.ioc_id = ?"
            params.append(filters['ioc_id'])
        
        query += " ORDER BY c.matched_at DESC"
        
        if filters.get('limit'):
            query += " LIMIT ?"
            params.append(filters['limit'])
            if filters.get('offset'):
                query += " OFFSET ?"
                params.append(filters['offset'])
        
        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_dict(row) for row in rows]

    @retry_on_locked()
    def get_correlations_paginated(self, filters=None):
        """Get correlations with pagination"""
        filters = filters or {}
        page = filters.get('page', 1)
        limit = filters.get('limit', 50)
        offset = (page - 1) * limit
        
        base_query = """
            FROM correlations c
            LEFT JOIN iocs i ON c.ioc_id = i.id
            WHERE 1=1
        """
        params = []
        
        if filters.get('verdict'):
            base_query += " AND c.verdict = ?"
            params.append(filters['verdict'])
        if filters.get('date_from'):
            base_query += " AND c.matched_at >= ?"
            params.append(filters['date_from'])
        if filters.get('date_to'):
            base_query += " AND c.matched_at <= ?"
            params.append(filters['date_to'])
        
        with self._get_connection() as conn:
            count_row = conn.execute(f"SELECT COUNT(*) as total {base_query}", params).fetchone()
            total = count_row['total']
            
            select_query = f"""
                SELECT c.*, i.ioc_value, i.ioc_type, i.threat_type, i.malware_family, i.severity
                {base_query}
                ORDER BY c.matched_at DESC LIMIT ? OFFSET ?
            """
            data_params = params + [limit, offset]
            rows = conn.execute(select_query, data_params).fetchall()
            
            return {
                'correlations': [self._row_to_dict(row) for row in rows],
                'total': total,
                'page': page,
                'limit': limit,
                'pages': (total + limit - 1) // limit
            }

    @retry_on_locked()
    def update_correlation_reviewed(self, correlation_id, reviewed):
        """Mark a correlation as reviewed"""
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE correlations SET reviewed = ? WHERE id = ?",
                (1 if reviewed else 0, correlation_id)
            )
            conn.commit()
            return True

    @retry_on_locked()
    def get_dashboard_stats(self):
        """Get all KPI numbers for dashboard"""
        with self._get_connection() as conn:
            stats = {}
            
            stats['total_iocs'] = conn.execute(
                "SELECT COUNT(*) FROM iocs"
            ).fetchone()[0]
            
            stats['active_iocs'] = conn.execute(
                "SELECT COUNT(*) FROM iocs WHERE is_active = 1 AND false_positive = 0"
            ).fetchone()[0]
            
            stats['false_positives'] = conn.execute(
                "SELECT COUNT(*) FROM iocs WHERE false_positive = 1"
            ).fetchone()[0]
            
            stats['total_correlations'] = conn.execute(
                "SELECT COUNT(*) FROM correlations"
            ).fetchone()[0]
            
            stats['confirmed_threats'] = conn.execute(
                "SELECT COUNT(*) FROM correlations WHERE verdict = 'Confirmed Threat'"
            ).fetchone()[0]
            
            stats['suspicious_matches'] = conn.execute(
                "SELECT COUNT(*) FROM correlations WHERE verdict = 'Suspicious - Needs Review'"
            ).fetchone()[0]
            
            iocs_by_type = conn.execute(
                "SELECT ioc_type, COUNT(*) as count FROM iocs WHERE is_active = 1 GROUP BY ioc_type"
            ).fetchall()
            stats['iocs_by_type'] = {row['ioc_type']: row['count'] for row in iocs_by_type}
            
            severity_dist = conn.execute(
                "SELECT severity, COUNT(*) as count FROM iocs WHERE is_active = 1 GROUP BY severity"
            ).fetchall()
            stats['threat_level_distribution'] = {row['severity']: row['count'] for row in severity_dist}
            
            malware_families = conn.execute(
                """SELECT malware_family, COUNT(*) as count FROM iocs 
                   WHERE is_active = 1 AND malware_family IS NOT NULL AND malware_family != ''
                   GROUP BY malware_family ORDER BY count DESC LIMIT 5"""
            ).fetchall()
            stats['top_malware_families'] = [
                {'name': row['malware_family'], 'count': row['count']} for row in malware_families
            ]
            
            recent_correlations = conn.execute(
                """SELECT c.*, i.ioc_value, i.ioc_type, i.threat_type, i.malware_family, i.severity
                   FROM correlations c
                   LEFT JOIN iocs i ON c.ioc_id = i.id
                   ORDER BY c.matched_at DESC LIMIT 10"""
            ).fetchall()
            stats['recent_correlations'] = [self._row_to_dict(row) for row in recent_correlations]
            
            timeline = conn.execute(
                """SELECT DATE(created_at) as date, COUNT(*) as count 
                   FROM iocs 
                   WHERE created_at >= DATE('now', '-7 days')
                   GROUP BY DATE(created_at) 
                   ORDER BY date"""
            ).fetchall()
            stats['timeline_data'] = [{'date': row['date'], 'count': row['count']} for row in timeline]
            
            return stats

    @retry_on_locked()
    def update_feed_status(self, feed_name, status_dict):
        """Update or insert feed status"""
        now = datetime.utcnow().isoformat()
        status_dict['last_updated'] = now
        
        with self._get_connection() as conn:
            existing = conn.execute(
                "SELECT id FROM feed_status WHERE feed_name = ?", (feed_name,)
            ).fetchone()
            
            if existing:
                set_clause = ', '.join([f"{k} = ?" for k in status_dict.keys()])
                params = list(status_dict.values()) + [feed_name]
                conn.execute(
                    f"UPDATE feed_status SET {set_clause} WHERE feed_name = ?",
                    params
                )
            else:
                status_dict['feed_name'] = feed_name
                columns = ', '.join(status_dict.keys())
                placeholders = ', '.join(['?' for _ in status_dict])
                conn.execute(
                    f"INSERT INTO feed_status ({columns}) VALUES ({placeholders})",
                    list(status_dict.values())
                )
            
            conn.commit()
            return True

    @retry_on_locked()
    def get_feed_status(self):
        """Get status of all feeds"""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM feed_status ORDER BY feed_name").fetchall()
            return [self._row_to_dict(row) for row in rows]

    @retry_on_locked()
    def save_report(self, report_dict):
        """Save a report and return its ID"""
        now = datetime.utcnow().isoformat()
        report_dict['generated_at'] = now
        
        if 'report_data' in report_dict and isinstance(report_dict['report_data'], dict):
            report_dict['report_data'] = json.dumps(report_dict['report_data'])
        
        columns = ', '.join(report_dict.keys())
        placeholders = ', '.join(['?' for _ in report_dict])
        
        with self._get_connection() as conn:
            try:
                conn.execute(
                    f"INSERT INTO reports ({columns}) VALUES ({placeholders})",
                    list(report_dict.values())
                )
                conn.commit()
                return report_dict.get('report_id')
            except sqlite3.IntegrityError:
                return None

    @retry_on_locked()
    def get_reports(self):
        """Get list of all reports with summary fields"""
        with self._get_connection() as conn:
            rows = conn.execute(
                """SELECT report_id, generated_at, total_iocs, total_matches, 
                   confirmed_threats, false_positives FROM reports 
                   ORDER BY generated_at DESC"""
            ).fetchall()
            return [self._row_to_dict(row) for row in rows]

    @retry_on_locked()
    def get_report_by_id(self, report_id):
        """Get full report by ID"""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM reports WHERE report_id = ?", (report_id,)
            ).fetchone()
            if row:
                result = self._row_to_dict(row)
                if result.get('report_data'):
                    try:
                        result['report_data'] = json.loads(result['report_data'])
                    except json.JSONDecodeError:
                        pass
                return result
            return None

    @retry_on_locked()
    def clear_all_data(self):
        """Clear all data from database (for demo reset)"""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM correlations")
            conn.execute("DELETE FROM iocs")
            conn.execute("DELETE FROM reports")
            conn.execute("DELETE FROM feed_status")
            conn.commit()
            return True

    @retry_on_locked()
    def get_ioc_count_by_feed(self, feed_name):
        """Get count of IOCs from a specific feed"""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) as count FROM iocs WHERE source_feed = ?",
                (feed_name,)
            ).fetchone()
            return row['count'] if row else 0

    @retry_on_locked()
    def mark_old_iocs_inactive(self, days=90):
        """Mark IOCs older than specified days as inactive"""
        with self._get_connection() as conn:
            cursor = conn.execute(
                f"""UPDATE iocs SET is_active = 0 
                    WHERE first_seen < DATE('now', '-{days} days') 
                    AND is_active = 1"""
            )
            conn.commit()
            return cursor.rowcount

    def _row_to_dict(self, row):
        """Convert sqlite3.Row to dictionary with JSON parsing"""
        if row is None:
            return None
        d = dict(row)
        
        if 'tags' in d and d['tags']:
            try:
                d['tags'] = json.loads(d['tags'])
            except (json.JSONDecodeError, TypeError):
                d['tags'] = []
        
        if 'enrichment_data' in d and d['enrichment_data']:
            try:
                d['enrichment_data'] = json.loads(d['enrichment_data'])
            except (json.JSONDecodeError, TypeError):
                d['enrichment_data'] = {}
        
        if 'log_entry' in d and d['log_entry']:
            try:
                d['log_entry'] = json.loads(d['log_entry'])
            except (json.JSONDecodeError, TypeError):
                pass
        
        return d

    def close(self):
        """Close database connection (no-op with context managers)"""
        pass
