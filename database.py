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
