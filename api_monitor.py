"""
Optimized API endpoints for real-time monitoring
Designed for fast, efficient data retrieval with caching
"""

from flask import jsonify, request
from database import get_connection
import time
from functools import lru_cache

# Cache for statistics (invalidated every 5 seconds)
_stats_cache = {"data": None, "timestamp": 0}
_stats_cache_ttl = 5

def get_monitor_events(limit=50, offset=0, threat_level="all", event_type="all", search=None):
    """
    Fetch monitor events with optional filtering
    Optimized for fast retrieval with minimal database overhead
    """
    conn = get_connection()
    
    query = "SELECT id, created_at, threat_level, process_name, process_pid, file_path, details, detected_type FROM monitor_events WHERE 1=1"
    params = []
    
    if threat_level != "all":
        query += " AND threat_level = ?"
        params.append(threat_level)
    
    if event_type != "all":
        query += " AND detected_type = ?"
        params.append(event_type)
    
    if search:
        query += " AND (process_name LIKE ? OR file_path LIKE ? OR details LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
    
    # Get total count for pagination
    count_query = query.replace(
        "SELECT id, created_at, threat_level, process_name, process_pid, file_path, details, detected_type",
        "SELECT COUNT(*) as count"
    )
    total_count = conn.execute(count_query, params).fetchone()["count"]
    
    # Fetch paginated results
    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    rows = conn.execute(query, params).fetchall()
    conn.close()
    
    return {
        "events": [dict(r) for r in rows],
        "total": total_count,
        "limit": limit,
        "offset": offset
    }

def get_monitor_stats():
    """
    Get cached statistics for monitor events
    Cache is invalidated every 5 seconds to balance freshness and performance
    """
    global _stats_cache
    
    current_time = time.time()
    if _stats_cache["data"] and (current_time - _stats_cache["timestamp"]) < _stats_cache_ttl:
        return _stats_cache["data"]
    
    conn = get_connection()
    
    total = conn.execute("SELECT COUNT(*) as count FROM monitor_events").fetchone()["count"]
    critical = conn.execute("SELECT COUNT(*) as count FROM monitor_events WHERE threat_level = 'Critical'").fetchone()["count"]
    high = conn.execute("SELECT COUNT(*) as count FROM monitor_events WHERE threat_level = 'High'").fetchone()["count"]
    medium = conn.execute("SELECT COUNT(*) as count FROM monitor_events WHERE threat_level = 'Medium'").fetchone()["count"]
    low = conn.execute("SELECT COUNT(*) as count FROM monitor_events WHERE threat_level = 'Low'").fetchone()["count"]
    
    conn.close()
    
    stats = {
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low
    }
    
    _stats_cache["data"] = stats
    _stats_cache["timestamp"] = current_time
    
    return stats

def clear_monitor_stats_cache():
    """Clear the statistics cache when data is modified"""
    global _stats_cache
    _stats_cache["data"] = None
    _stats_cache["timestamp"] = 0
