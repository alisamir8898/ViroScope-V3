"""
dynamic_analysis_manager.py
----------------------------
Enhanced manager for dynamic analysis with live capturing capabilities.
Integrates with database for persistence and realtime event tracking.
"""

import os
import json
import time
import logging
from datetime import datetime, timezone
from dynamic_analysis import DynamicAnalyzer
from malware_types import MalwareTypeDetector
import database

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(os.path.dirname(__file__), 'dynamic_analysis_manager.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('DynamicAnalysisManager')


class DynamicAnalysisManager:
    """Manager for dynamic analysis sessions with live event capture"""
    
    def __init__(self):
        self.analyzer = DynamicAnalyzer(timeout=60, max_memory_mb=500)
        self.malware_detector = MalwareTypeDetector()
        self.active_sessions = {}
        
    def run_analysis(self, file_path, scan_id=None, original_name=None):
        """
        Run complete dynamic analysis on a file
        
        Args:
            file_path: Path to the file to analyze
            scan_id: Optional scan ID to link with static analysis
            original_name: The original name of the file
            
        Returns:
            dict: Analysis results with session ID
        """
        logger.info(f"Starting dynamic analysis for: {file_path}")
        
        try:
            # Run the dynamic analysis
            analysis_result = self.analyzer.analyze_file(file_path)
            
            if 'error' in analysis_result:
                logger.error(f"Analysis error: {analysis_result['error']}")
                return {'success': False, 'error': analysis_result['error']}
            
            # Extract key information
            file_name = original_name if original_name else os.path.basename(file_path)
            file_hash = analysis_result.get('file_hash', '')
            file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
            execution_time = analysis_result.get('execution_info', {}).get('execution_time', 0)
            exit_code = analysis_result.get('execution_info', {}).get('exit_code')
            risk_score = analysis_result.get('risk_score', {}).get('score', 0) / 100.0
            malware_type = analysis_result.get('malware_type_indicators', {}).get('detected_type', 'Unknown')
            
            # Save to database
            session_id = database.save_dynamic_session(
                file_name=file_name,
                file_hash=file_hash,
                file_size=file_size,
                execution_time=execution_time,
                exit_code=exit_code,
                risk_score=risk_score,
                malware_type=malware_type,
                behavioral_indicators=analysis_result.get('behavioral_indicators', []),
                network_activity=analysis_result.get('network_activity', []),
                file_changes=analysis_result.get('file_changes', {}),
                process_info=analysis_result.get('created_processes', []),
                evasion_techniques=analysis_result.get('evasion_techniques', {}),
                scan_id=scan_id
            )
            
            # Save live capture events
            self._save_live_captures(session_id, analysis_result)
            
            logger.info(f"Dynamic analysis completed. Session ID: {session_id}")
            
            return {
                'success': True,
                'session_id': session_id,
                'file_name': file_name,
                'file_hash': file_hash,
                'risk_score': risk_score,
                'malware_type': malware_type,
                'execution_time': execution_time,
                'network_activity_count': len(analysis_result.get('network_activity', [])),
                'file_changes_count': len(analysis_result.get('file_changes', {}).get('created', [])) + 
                                    len(analysis_result.get('file_changes', {}).get('modified', [])),
                'process_count': len(analysis_result.get('created_processes', []))
            }
            
        except Exception as e:
            logger.error(f"Exception during analysis: {str(e)}", exc_info=True)
            return {'success': False, 'error': str(e)}
    
    def _save_live_captures(self, session_id, analysis_result):
        """Save live capture events from analysis results"""
        
        # Network activity events
        for net_activity in analysis_result.get('network_activity', []):
            severity = self._determine_severity(net_activity)
            database.save_live_capture(
                session_id=session_id,
                event_type='network_connection',
                event_category='network',
                severity=severity,
                source_pid=net_activity.get('pid'),
                source_process=f"PID: {net_activity.get('pid')}",
                target_resource=net_activity.get('remote_address', 'Unknown'),
                event_data=net_activity,
                timestamp=time.time()
            )
        
        # File changes events
        file_changes = analysis_result.get('file_changes', {})
        
        # Created files
        for created_file in file_changes.get('created', []):
            database.save_live_capture(
                session_id=session_id,
                event_type='file_created',
                event_category='file_system',
                severity='medium',
                source_pid=analysis_result.get('execution_info', {}).get('pid'),
                source_process='Analyzed Process',
                target_resource=created_file,
                event_data={'action': 'created', 'path': created_file},
                timestamp=time.time()
            )
        
        # Modified files
        for modified_file in file_changes.get('modified', []):
            database.save_live_capture(
                session_id=session_id,
                event_type='file_modified',
                event_category='file_system',
                severity='medium',
                source_pid=analysis_result.get('execution_info', {}).get('pid'),
                source_process='Analyzed Process',
                target_resource=modified_file,
                event_data={'action': 'modified', 'path': modified_file},
                timestamp=time.time()
            )
        
        # Behavioral indicators as events
        for indicator in analysis_result.get('behavioral_indicators', []):
            severity = self._get_indicator_severity(indicator)
            database.save_live_capture(
                session_id=session_id,
                event_type='behavioral_indicator',
                event_category='behavior',
                severity=severity,
                source_pid=analysis_result.get('execution_info', {}).get('pid'),
                source_process='Analyzed Process',
                target_resource='System',
                event_data={'indicator': indicator},
                timestamp=time.time()
            )
        
        # Process creation events
        for process in analysis_result.get('created_processes', []):
            database.save_live_capture(
                session_id=session_id,
                event_type='process_created',
                event_category='process',
                severity='high',
                source_pid=process.get('pid'),
                source_process=process.get('name', 'Unknown'),
                target_resource=process.get('exe', 'Unknown'),
                event_data=process,
                timestamp=time.time()
            )
    
    def _determine_severity(self, network_activity):
        """Determine severity of network activity"""
        remote_addr = network_activity.get('remote_address', '')
        
        # Check for suspicious ports
        suspicious_ports = [25, 53, 135, 139, 445, 1433, 3306, 3389, 5432, 8080, 8443]
        try:
            if ':' in remote_addr:
                port = int(remote_addr.split(':')[1])
                if port in suspicious_ports:
                    return 'critical'
        except:
            pass
        
        # Check for private IPs (potential lateral movement)
        if any(remote_addr.startswith(prefix) for prefix in ['192.168', '10.', '172.']):
            return 'high'
        
        return 'medium'
    
    def _get_indicator_severity(self, indicator):
        """Get severity level for behavioral indicator"""
        critical_keywords = ['ransomware', 'encryption', 'delete', 'wipe', 'steal', 'exfiltrate']
        high_keywords = ['inject', 'hook', 'registry', 'startup', 'persistence']
        
        indicator_lower = indicator.lower()
        
        for keyword in critical_keywords:
            if keyword in indicator_lower:
                return 'critical'
        
        for keyword in high_keywords:
            if keyword in indicator_lower:
                return 'high'
        
        return 'medium'
    
    def get_session_details(self, session_id):
        """Get detailed information about a session"""
        session = database.get_dynamic_session_by_id(session_id)
        if not session:
            return None
        
        # Get live captures for this session
        captures = database.get_live_captures(session_id)
        
        return {
            'session': session,
            'captures': captures,
            'capture_summary': self._summarize_captures(captures)
        }
    
    def _summarize_captures(self, captures):
        """Summarize live captures by category"""
        summary = {
            'network': {'count': 0, 'severity_distribution': {}},
            'file_system': {'count': 0, 'severity_distribution': {}},
            'process': {'count': 0, 'severity_distribution': {}},
            'behavior': {'count': 0, 'severity_distribution': {}}
        }
        
        for capture in captures:
            category = capture.get('event_category', 'unknown')
            severity = capture.get('severity', 'unknown')
            
            if category in summary:
                summary[category]['count'] += 1
                if severity not in summary[category]['severity_distribution']:
                    summary[category]['severity_distribution'][severity] = 0
                summary[category]['severity_distribution'][severity] += 1
        
        return summary
    
    def get_filtered_captures(self, session_id, event_type=None, severity=None, limit=500):
        """Get filtered live captures"""
        return database.get_live_captures(
            session_id=session_id,
            limit=limit,
            event_type_filter=event_type,
            severity_filter=severity
        )
    
    def get_sessions_list(self, risk_filter=None, malware_type_filter=None, limit=100):
        """Get list of dynamic analysis sessions"""
        return database.get_dynamic_sessions(
            limit=limit,
            risk_filter=risk_filter,
            malware_type_filter=malware_type_filter
        )
    
    def get_statistics(self):
        """Get statistics about all dynamic analysis sessions"""
        return database.get_dynamic_stats()


# Global manager instance
_manager = None


def get_manager():
    """Get or create the global manager instance"""
    global _manager
    if _manager is None:
        _manager = DynamicAnalysisManager()
    return _manager
