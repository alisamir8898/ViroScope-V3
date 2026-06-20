import os
import time
import psutil
import threading
import logging
import sqlite3
from datetime import datetime
from malware_types import MalwareTypeDetector
import database

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('RealTimeMonitor')

class RealTimeMonitor:
    def __init__(self):
        self.detector = MalwareTypeDetector()
        self.is_running = False
        self.monitor_thread = None
        self.known_pids = set()
        self.lock = threading.Lock()
        # OPTIMIZATION: Reduce memory usage by limiting event logging
        self.max_events_per_session = 1000

    def start(self):
        """Start the background monitoring thread"""
        with self.lock:
            if not self.is_running:
                self.is_running = True
                self.known_pids = {p.pid for p in psutil.process_iter()}
                self.monitor_thread = threading.Thread(target=self._run_monitor, daemon=True)
                self.monitor_thread.start()
                logger.info("Real-time Intelligence Monitor started.")

    def stop(self):
        """Stop the monitoring thread"""
        with self.lock:
            self.is_running = False
            logger.info("Real-time Intelligence Monitor stopped.")

    def _log_event(self, process_name, pid, file_path, event_type, details, threat_level, detected_type):
        """Save a detected event to the database for the UI to display"""
        try:
            conn = database.get_connection()
            conn.execute("""
                INSERT INTO monitor_events 
                (process_name, process_pid, file_path, event_type, details, threat_level, detected_type, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (process_name, pid, file_path, event_type, details, threat_level, detected_type, datetime.now().isoformat()))
            conn.commit()
            conn.close()
            
            # Clear stats cache so UI updates immediately
            from api_monitor import clear_monitor_stats_cache
            clear_monitor_stats_cache()
        except Exception as e:
            logger.error(f"Failed to log monitor event: {e}")

    def _analyze_process(self, proc):
        """Perform real-time analysis on a process"""
        try:
            with proc.oneshot():
                pid = proc.pid
                name = proc.name()
                exe = proc.exe()
                cmdline = " ".join(proc.cmdline())
                
                # 1. Check if executable is suspicious using MalwareTypeDetector
                if exe and os.path.exists(exe):
                    analysis = self.detector.detect_malware_type(exe)
                    if analysis['detected_type'] != "Unknown" and analysis['confidence'] > 40:
                        self._log_event(
                            name, pid, exe, 'process', 
                            f"Suspicious process execution: {cmdline}",
                            'High' if analysis['confidence'] > 70 else 'Medium',
                            analysis['detected_type']
                        )
                
                # 2. Check for suspicious behavior (e.g., process hollowing or unusual parent)
                # This is a simplified check for demonstration
                suspicious_names = ['powershell.exe', 'cmd.exe', 'schtasks.exe', 'reg.exe', 'vssadmin.exe']
                if name.lower() in suspicious_names:
                    # Check for suspicious flags in command line
                    suspicious_flags = ['-enc', '-encodedcommand', 'bypass', 'hidden', 'delete shadows']
                    if any(flag in cmdline.lower() for flag in suspicious_flags):
                        self._log_event(
                            name, pid, exe, 'process',
                            f"Suspicious system utility usage: {cmdline}",
                            'Critical',
                            'Trojan/Ransomware'
                        )

                # 3. Monitor Network connections of the process
                # OPTIMIZATION: Skip network monitoring to reduce CPU usage
                # Network monitoring can be expensive and is causing slowdowns
                # Uncomment if needed for specific analysis
                """
                try:
                    connections = proc.net_connections(kind='inet')
                    for conn in connections:
                        if conn.status == 'ESTABLISHED':
                            remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "Unknown"
                            # Log external connections from non-browser processes
                            browsers = ['chrome.exe', 'firefox.exe', 'msedge.exe', 'brave.exe']
                            if name.lower() not in browsers:
                                self._log_event(
                                    name, pid, exe, 'network',
                                    f"Active network connection to {remote}",
                                    'Low',
                                    'Network Hook'
                                )
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                """

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    def _run_monitor(self):
        """Main monitor loop"""
        while self.is_running:
            try:
                for proc in psutil.process_iter(['pid', 'name']):
                    pid = proc.info['pid']
                    if pid not in self.known_pids:
                        self._analyze_process(proc)
                        self.known_pids.add(pid)
                
                # Clean up finished processes from known_pids to save memory
                active_pids = {p.pid for p in psutil.process_iter()}
                self.known_pids &= active_pids
                
                # OPTIMIZATION: Increased polling interval from 5s to 15s for local dev environment
                # Background monitoring is heavy and shouldn't impact UI responsiveness
                time.sleep(15)
            except Exception as e:
                logger.error(f"Error in monitor loop: {e}")
                time.sleep(15)

# Global instance
monitor_instance = RealTimeMonitor()
