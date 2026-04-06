"""
Scheduler - Background jobs using APScheduler
"""

import logging
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('scheduler')


class ThreatIntelScheduler:
    def __init__(self, db_manager, feed_manager, log_correlator, briefing_generator):
        self.db = db_manager
        self.feed_manager = feed_manager
        self.log_correlator = log_correlator
        self.briefing_generator = briefing_generator
        self.scheduler = BackgroundScheduler()
        self.job_status = {}
    
    def start(self):
        """Start the scheduler with all jobs"""
        
        # Job 1: Refresh feeds every 6 hours
        self.scheduler.add_job(
            func=self._refresh_feeds_job,
            trigger=IntervalTrigger(hours=6),
            id='refresh_feeds',
            name='Refresh Threat Feeds',
            replace_existing=True
        )
        
        # Job 2: Run correlation every hour
        self.scheduler.add_job(
            func=self._correlate_job,
            trigger=IntervalTrigger(hours=1),
            id='correlate',
            name='Run Correlation',
            replace_existing=True
        )
        
        # Job 3: Cleanup expired IOCs daily at 02:00 UTC
        self.scheduler.add_job(
            func=self._cleanup_expired_iocs_job,
            trigger=CronTrigger(hour=2, minute=0),
            id='cleanup_expired',
            name='Cleanup Expired IOCs',
            replace_existing=True
        )
        
        # Job 4: Generate daily briefing at 08:00 UTC
        self.scheduler.add_job(
            func=self._daily_briefing_job,
            trigger=CronTrigger(hour=8, minute=0),
            id='daily_briefing',
            name='Generate Daily Briefing',
            replace_existing=True
        )
        
        self.scheduler.start()
        logger.info(f"[{datetime.utcnow().isoformat()}] Scheduler started with 4 jobs")
    
    def stop(self):
        """Stop the scheduler"""
        self.scheduler.shutdown()
        logger.info(f"[{datetime.utcnow().isoformat()}] Scheduler stopped")
    
    def _refresh_feeds_job(self):
        """Job: Refresh all threat intelligence feeds"""
        try:
            logger.info(f"[{datetime.utcnow().isoformat()}] Starting feed refresh job")
            result = self.feed_manager.refresh_all_feeds()
            
            self.job_status['refresh_feeds'] = {
                'last_run': datetime.utcnow().isoformat(),
                'status': 'success',
                'feeds_updated': result.get('feeds_updated', 0),
                'new_iocs': result.get('total_new_iocs', 0)
            }
            
            logger.info(
                f"[{datetime.utcnow().isoformat()}] Feed refresh complete: "
                f"{result.get('feeds_updated')} feeds updated, "
                f"{result.get('total_new_iocs')} new IOCs"
            )
        except Exception as e:
            logger.error(f"[{datetime.utcnow().isoformat()}] Feed refresh job failed: {str(e)}")
            self.job_status['refresh_feeds'] = {
                'last_run': datetime.utcnow().isoformat(),
                'status': 'error',
                'error': str(e)
            }
    
    def _correlate_job(self):
        """Job: Run IOC correlation against logs"""
        try:
            logger.info(f"[{datetime.utcnow().isoformat()}] Starting correlation job")
            result = self.log_correlator.run_correlation()
            
            self.job_status['correlate'] = {
                'last_run': datetime.utcnow().isoformat(),
                'status': 'success',
                'new_correlations': result.get('new_correlations', 0)
            }
            
            logger.info(
                f"[{datetime.utcnow().isoformat()}] Correlation complete: "
                f"{result.get('new_correlations')} new correlations"
            )
        except Exception as e:
            logger.error(f"[{datetime.utcnow().isoformat()}] Correlation job failed: {str(e)}")
            self.job_status['correlate'] = {
                'last_run': datetime.utcnow().isoformat(),
                'status': 'error',
                'error': str(e)
            }
    
    def _cleanup_expired_iocs_job(self):
        """Job: Mark IOCs older than 90 days as inactive"""
        try:
            logger.info(f"[{datetime.utcnow().isoformat()}] Starting cleanup job")
            count = self.db.mark_old_iocs_inactive(days=90)
            
            self.job_status['cleanup_expired'] = {
                'last_run': datetime.utcnow().isoformat(),
                'status': 'success',
                'iocs_deactivated': count
            }
            
            logger.info(
                f"[{datetime.utcnow().isoformat()}] Cleanup complete: "
                f"{count} IOCs marked as inactive"
            )
        except Exception as e:
            logger.error(f"[{datetime.utcnow().isoformat()}] Cleanup job failed: {str(e)}")
            self.job_status['cleanup_expired'] = {
                'last_run': datetime.utcnow().isoformat(),
                'status': 'error',
                'error': str(e)
            }
    
    def _daily_briefing_job(self):
        """Job: Generate daily threat briefing"""
        try:
            logger.info(f"[{datetime.utcnow().isoformat()}] Starting daily briefing job")
            briefing = self.briefing_generator.generate_daily_briefing()
            
            # Determine if AI or fallback was used
            used_ai = 'Generated by ThreatVision Platform (Fallback Mode)' not in briefing
            
            self.job_status['daily_briefing'] = {
                'last_run': datetime.utcnow().isoformat(),
                'status': 'success',
                'used_ai': used_ai
            }
            
            logger.info(
                f"[{datetime.utcnow().isoformat()}] Daily briefing generated "
                f"({'AI' if used_ai else 'Fallback'})"
            )
        except Exception as e:
            logger.error(f"[{datetime.utcnow().isoformat()}] Daily briefing job failed: {str(e)}")
            self.job_status['daily_briefing'] = {
                'last_run': datetime.utcnow().isoformat(),
                'status': 'error',
                'error': str(e)
            }
    
    def run_job_now(self, job_name):
        """Manually trigger a specific job"""
        job_map = {
            'refresh_feeds': self._refresh_feeds_job,
            'correlate': self._correlate_job,
            'cleanup_expired': self._cleanup_expired_iocs_job,
            'daily_briefing': self._daily_briefing_job
        }
        
        if job_name not in job_map:
            return {'error': f'Unknown job: {job_name}'}
        
        try:
            job_map[job_name]()
            return self.job_status.get(job_name, {'status': 'completed'})
        except Exception as e:
            return {'error': str(e)}
    
    def get_job_status(self):
        """Get status of all scheduled jobs"""
        jobs = []
        
        for job in self.scheduler.get_jobs():
            job_info = {
                'id': job.id,
                'name': job.name,
                'next_run': job.next_run_time.isoformat() if job.next_run_time else None,
                'last_status': self.job_status.get(job.id, {})
            }
            jobs.append(job_info)
        
        return {
            'scheduler_running': self.scheduler.running,
            'jobs': jobs
        }
    
    def get_next_runs(self):
        """Get next scheduled run times for all jobs"""
        return {
            job.id: job.next_run_time.isoformat() if job.next_run_time else None
            for job in self.scheduler.get_jobs()
        }


# Global scheduler instance (initialized in app.py)
threat_scheduler = None


def init_scheduler(db_manager, feed_manager, log_correlator, briefing_generator):
    """Initialize and return the scheduler"""
    global threat_scheduler
    threat_scheduler = ThreatIntelScheduler(
        db_manager, feed_manager, log_correlator, briefing_generator
    )
    return threat_scheduler
