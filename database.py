"""
database.py
-----------
Minimal SQLite persistence layer for scan history. No ORM needed for this
scope, just a small set of focused helper functions.
"""

import os
import json
import sqlite3
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "instance", "viroscope.db")


def get_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_name TEXT NOT NULL,
            sha256 TEXT,
            file_size INTEGER,
            verdict TEXT,
            confidence REAL,
            ml_success INTEGER,
            ml_error TEXT,
            vt_malicious INTEGER,
            vt_total INTEGER,
            vt_permalink TEXT,
            vt_checked INTEGER DEFAULT 0,
            batch_id TEXT,
            raw_result TEXT,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_batch_id ON scans(batch_id)")
    
    # Dynamic Analysis Sessions Table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS dynamic_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            session_hash TEXT UNIQUE,
            file_name TEXT NOT NULL,
            file_hash TEXT,
            file_size INTEGER,
            execution_time REAL,
            exit_code INTEGER,
            risk_score REAL,
            malware_type TEXT,
            behavioral_indicators TEXT,
            network_activity TEXT,
            file_changes TEXT,
            process_info TEXT,
            evasion_techniques TEXT,
            status TEXT DEFAULT 'completed',
            created_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_dynamic_sessions_created_at ON dynamic_sessions(created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_dynamic_sessions_scan_id ON dynamic_sessions(scan_id)")
    
    # Live Captures Table (Real-time Events)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS live_captures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER,
            event_type TEXT NOT NULL,
            event_category TEXT,
            severity TEXT,
            source_pid INTEGER,
            source_process TEXT,
            target_resource TEXT,
            event_data TEXT,
            timestamp REAL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (session_id) REFERENCES dynamic_sessions(id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_live_captures_session_id ON live_captures(session_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_live_captures_event_type ON live_captures(event_type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_live_captures_severity ON live_captures(severity)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_live_captures_created_at ON live_captures(created_at)")
    
    # Realtime Monitor Events
    conn.execute("""
        CREATE TABLE IF NOT EXISTS monitor_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            monitor_session_id TEXT,
            event_type TEXT,
            file_path TEXT,
            file_hash TEXT,
            detected_type TEXT,
            confidence REAL,
            process_name TEXT,
            process_pid INTEGER,
            cpu_usage REAL,
            memory_usage REAL,
            threat_level TEXT,
            details TEXT,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_monitor_events_created_at ON monitor_events(created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_monitor_events_monitor_session_id ON monitor_events(monitor_session_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_monitor_events_threat_level ON monitor_events(threat_level)")
    
    conn.commit()
    conn.close()


def save_scan(file_name, sha256, file_size, ml_result, vt_result=None, batch_id=None):
    """Persist one scan result. ml_result and vt_result are the dicts produced
    by predictor.predict_file() and vt_scanner.scan_file() respectively."""
    conn = get_connection()

    verdict = ml_result.get("verdict") if ml_result.get("success") else "Error"
    confidence = ml_result.get("confidence")
    vt_malicious = vt_result.get("malicious") if vt_result and vt_result.get("found") else None
    vt_total = vt_result.get("total_engines") if vt_result and vt_result.get("found") else None
    vt_permalink = vt_result.get("permalink") if vt_result and vt_result.get("found") else None

    conn.execute(
        """INSERT INTO scans
           (file_name, sha256, file_size, verdict, confidence, ml_success, ml_error,
            vt_malicious, vt_total, vt_permalink, vt_checked, batch_id, raw_result, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            file_name,
            sha256,
            file_size,
            verdict,
            confidence,
            1 if ml_result.get("success") else 0,
            ml_result.get("error"),
            vt_malicious,
            vt_total,
            vt_permalink,
            1 if vt_result is not None else 0,
            batch_id,
            json.dumps({"ml": ml_result, "vt": vt_result}, default=str),
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    conn.commit()
    scan_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    return scan_id


def get_history(limit=100, offset=0, verdict_filter=None, search=None):
    conn = get_connection()
    query = "SELECT * FROM scans WHERE 1=1"
    params = []

    if verdict_filter and verdict_filter != "all":
        query += " AND verdict = ?"
        params.append(verdict_filter)

    if search:
        query += " AND (file_name LIKE ? OR sha256 LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%"])

    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_scan_by_id(scan_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    if row is None:
        return None
    result = dict(row)
    try:
        result["raw_result"] = json.loads(result["raw_result"])
    except (TypeError, json.JSONDecodeError):
        pass
    return result


def get_batch(batch_id):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM scans WHERE batch_id = ? ORDER BY id ASC", (batch_id,)
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_stats():
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    malicious = conn.execute("SELECT COUNT(*) FROM scans WHERE verdict = 'Malicious'").fetchone()[0]
    benign = conn.execute("SELECT COUNT(*) FROM scans WHERE verdict = 'Benign'").fetchone()[0]
    errors = conn.execute("SELECT COUNT(*) FROM scans WHERE verdict = 'Error'").fetchone()[0]
    conn.close()
    return {"total": total, "malicious": malicious, "benign": benign, "errors": errors}


def clear_history():
    conn = get_connection()
    conn.execute("DELETE FROM scans")
    conn.commit()
    conn.close()


def delete_scan(scan_id):
    conn = get_connection()
    conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    conn.close()


# ============ Dynamic Analysis Functions ============

def save_dynamic_session(file_name, file_hash, file_size, execution_time, exit_code, 
                        risk_score, malware_type, behavioral_indicators, network_activity, 
                        file_changes, process_info, evasion_techniques, scan_id=None):
    """Save a dynamic analysis session"""
    conn = get_connection()
    session_hash = f"{file_hash}_{datetime.now(timezone.utc).timestamp()}"
    
    conn.execute(
        """INSERT INTO dynamic_sessions
           (scan_id, session_hash, file_name, file_hash, file_size, execution_time, exit_code,
            risk_score, malware_type, behavioral_indicators, network_activity, file_changes,
            process_info, evasion_techniques, status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            scan_id,
            session_hash,
            file_name,
            file_hash,
            file_size,
            execution_time,
            exit_code,
            risk_score,
            malware_type,
            json.dumps(behavioral_indicators, default=str),
            json.dumps(network_activity, default=str),
            json.dumps(file_changes, default=str),
            json.dumps(process_info, default=str),
            json.dumps(evasion_techniques, default=str),
            'completed',
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    conn.commit()
    session_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    return session_id


def save_live_capture(session_id, event_type, event_category, severity, source_pid, 
                      source_process, target_resource, event_data, timestamp):
    """Save a live capture event"""
    conn = get_connection()
    conn.execute(
        """INSERT INTO live_captures
           (session_id, event_type, event_category, severity, source_pid, source_process,
            target_resource, event_data, timestamp, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            session_id,
            event_type,
            event_category,
            severity,
            source_pid,
            source_process,
            target_resource,
            json.dumps(event_data, default=str),
            timestamp,
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    conn.commit()
    conn.close()


def get_dynamic_sessions(limit=100, offset=0, risk_filter=None, malware_type_filter=None):
    """Get dynamic analysis sessions with optional filters"""
    conn = get_connection()
    query = "SELECT * FROM dynamic_sessions WHERE 1=1"
    params = []
    
    if risk_filter and risk_filter != "all":
        if risk_filter == "critical":
            query += " AND risk_score >= 0.8"
        elif risk_filter == "high":
            query += " AND risk_score >= 0.6 AND risk_score < 0.8"
        elif risk_filter == "medium":
            query += " AND risk_score >= 0.4 AND risk_score < 0.6"
        elif risk_filter == "low":
            query += " AND risk_score < 0.4"
    
    if malware_type_filter and malware_type_filter != "all":
        query += " AND malware_type = ?"
        params.append(malware_type_filter)
    
    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_dynamic_session_by_id(session_id):
    """Get a specific dynamic analysis session"""
    conn = get_connection()
    row = conn.execute("SELECT * FROM dynamic_sessions WHERE id = ?", (session_id,)).fetchone()
    conn.close()
    if row is None:
        return None
    result = dict(row)
    # Parse JSON fields
    for field in ['behavioral_indicators', 'network_activity', 'file_changes', 'process_info', 'evasion_techniques']:
        try:
            result[field] = json.loads(result[field]) if result[field] else {}
        except (TypeError, json.JSONDecodeError):
            result[field] = {}
    return result


def get_live_captures(session_id, limit=500, event_type_filter=None, severity_filter=None):
    """Get live capture events for a session"""
    conn = get_connection()
    query = "SELECT * FROM live_captures WHERE session_id = ?"
    params = [session_id]
    
    if event_type_filter and event_type_filter != "all":
        query += " AND event_type = ?"
        params.append(event_type_filter)
    
    if severity_filter and severity_filter != "all":
        query += " AND severity = ?"
        params.append(severity_filter)
    
    query += " ORDER BY timestamp ASC LIMIT ?"
    params.append(limit)
    
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_dynamic_stats():
    """Get statistics about dynamic analysis sessions"""
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) FROM dynamic_sessions").fetchone()[0]
    critical = conn.execute("SELECT COUNT(*) FROM dynamic_sessions WHERE risk_score >= 0.8").fetchone()[0]
    high = conn.execute("SELECT COUNT(*) FROM dynamic_sessions WHERE risk_score >= 0.6 AND risk_score < 0.8").fetchone()[0]
    medium = conn.execute("SELECT COUNT(*) FROM dynamic_sessions WHERE risk_score >= 0.4 AND risk_score < 0.6").fetchone()[0]
    low = conn.execute("SELECT COUNT(*) FROM dynamic_sessions WHERE risk_score < 0.4").fetchone()[0]
    conn.close()
    return {
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low
    }


# ============ Realtime Monitor Functions ============

def save_monitor_event(monitor_session_id, event_type, file_path, file_hash, detected_type, 
                       confidence, process_name, process_pid, cpu_usage, memory_usage, 
                       threat_level, details):
    """Save a realtime monitor event"""
    conn = get_connection()
    conn.execute(
        """INSERT INTO monitor_events
           (monitor_session_id, event_type, file_path, file_hash, detected_type, confidence,
            process_name, process_pid, cpu_usage, memory_usage, threat_level, details, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            monitor_session_id,
            event_type,
            file_path,
            file_hash,
            detected_type,
            confidence,
            process_name,
            process_pid,
            cpu_usage,
            memory_usage,
            threat_level,
            json.dumps(details, default=str),
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    conn.commit()
    conn.close()


def get_monitor_events(limit=200, threat_level_filter=None, event_type_filter=None):
    """Get realtime monitor events"""
    conn = get_connection()
    query = "SELECT * FROM monitor_events WHERE 1=1"
    params = []
    
    if threat_level_filter and threat_level_filter != "all":
        query += " AND threat_level = ?"
        params.append(threat_level_filter)
    
    if event_type_filter and event_type_filter != "all":
        query += " AND event_type = ?"
        params.append(event_type_filter)
    
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_monitor_stats():
    """Get statistics about monitor events"""
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) FROM monitor_events").fetchone()[0]
    critical = conn.execute("SELECT COUNT(*) FROM monitor_events WHERE threat_level = 'critical'").fetchone()[0]
    high = conn.execute("SELECT COUNT(*) FROM monitor_events WHERE threat_level = 'high'").fetchone()[0]
    medium = conn.execute("SELECT COUNT(*) FROM monitor_events WHERE threat_level = 'medium'").fetchone()[0]
    low = conn.execute("SELECT COUNT(*) FROM monitor_events WHERE threat_level = 'low'").fetchone()[0]
    conn.close()
    return {
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low
    }
