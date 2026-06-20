# ViroScope Dynamic Analysis - Implementation Guide

## Overview

This document describes the new **Dynamic Analysis** and **Live Capturing** features added to ViroScope-V3. These features enable real-time behavioral monitoring and event capture during malware execution.

## New Features

### 1. Dynamic Analysis Module
- **File**: `dynamic_analysis_manager.py`
- **Purpose**: Manages dynamic analysis sessions with live event capture
- **Key Functions**:
  - `run_analysis()`: Execute complete dynamic analysis on a file
  - `get_session_details()`: Retrieve detailed session information
  - `get_filtered_captures()`: Get live captures with filtering
  - `get_sessions_list()`: List all sessions with filtering options
  - `get_statistics()`: Get aggregate statistics

### 2. Database Schema Updates
- **File**: `database.py` (updated)
- **New Tables**:
  - `dynamic_sessions`: Stores dynamic analysis session metadata
  - `live_captures`: Stores real-time events captured during execution
  - `monitor_events`: Stores realtime monitor events

### 3. Web Interface Components

#### Dynamic Analysis Dashboard
- **Route**: `/dynamic_analysis`
- **Template**: `dynamic_analysis.html`
- **Features**:
  - Statistics cards (total, critical, high, medium, low risk)
  - Filterable session table
  - Risk level filtering
  - Malware type filtering
  - Search functionality
  - Session management

#### Session Details Page
- **Route**: `/dynamic_analysis/<session_id>`
- **Template**: `dynamic_detail.html`
- **Features**:
  - Comprehensive session information
  - Behavioral indicators
  - Network activity
  - File system changes (created, modified, deleted)
  - Process information
  - Evasion techniques detected

#### Live Captures/Events Page
- **Route**: `/live_captures/<session_id>`
- **Template**: `live_captures.html`
- **Features**:
  - Timeline view of captured events
  - Event filtering by type and severity
  - Detailed event information
  - Event categorization (network, file system, process, behavior)
  - Severity levels (critical, high, medium, low)

### 4. Navigation Updates
- Added "Dynamic Analysis" link to main navigation in `base.html`
- Dashboard updated with dynamic analysis statistics widget

## Database Schema

### dynamic_sessions Table
```sql
CREATE TABLE dynamic_sessions (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER,
    session_hash TEXT UNIQUE,
    file_name TEXT,
    file_hash TEXT,
    file_size INTEGER,
    execution_time REAL,
    exit_code INTEGER,
    risk_score REAL,
    malware_type TEXT,
    behavioral_indicators TEXT (JSON),
    network_activity TEXT (JSON),
    file_changes TEXT (JSON),
    process_info TEXT (JSON),
    evasion_techniques TEXT (JSON),
    status TEXT,
    created_at TEXT
)
```

### live_captures Table
```sql
CREATE TABLE live_captures (
    id INTEGER PRIMARY KEY,
    session_id INTEGER,
    event_type TEXT,
    event_category TEXT,
    severity TEXT,
    source_pid INTEGER,
    source_process TEXT,
    target_resource TEXT,
    event_data TEXT (JSON),
    timestamp REAL,
    created_at TEXT
)
```

### monitor_events Table
```sql
CREATE TABLE monitor_events (
    id INTEGER PRIMARY KEY,
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
    details TEXT (JSON),
    created_at TEXT
)
```

## API Routes

### Dynamic Analysis Routes

#### GET /dynamic_analysis
List all dynamic analysis sessions with optional filters
- Query Parameters:
  - `risk`: Filter by risk level (all, critical, high, medium, low)
  - `type`: Filter by malware type
  - `search`: Search by file name or hash

#### GET /dynamic_analysis/<session_id>
Get detailed information about a specific session

#### GET /live_captures/<session_id>
View live capture events for a session
- Query Parameters:
  - `event_type`: Filter by event type
  - `severity`: Filter by severity level

#### POST /api/dynamic/clear
Clear all dynamic analysis sessions and events

## Event Types

### Network Events
- `network_connection`: Network connection established
- Severity: Based on target port and address

### File System Events
- `file_created`: File created during execution
- `file_modified`: File modified during execution
- `file_deleted`: File deleted during execution

### Process Events
- `process_created`: New process spawned
- Severity: High (indicates potential process injection)

### Behavioral Events
- `behavioral_indicator`: Detected behavioral pattern
- Severity: Based on indicator type

## Severity Levels

- **Critical**: Ransomware-like behavior, encryption, data exfiltration
- **High**: Process injection, registry modification, persistence mechanisms
- **Medium**: Suspicious network connections, file modifications
- **Low**: Normal system activity, benign operations

## Integration with Existing Features

### Static Analysis Integration
- Dynamic analysis can be linked to static analysis scans via `scan_id`
- Dashboard shows combined statistics from both analysis types
- History page can be extended to show dynamic analysis results

### VirusTotal Integration
- Network connections are logged for later VirusTotal lookups
- Behavioral indicators can inform VirusTotal queries

## Usage Example

```python
from dynamic_analysis_manager import get_manager

# Get the manager instance
manager = get_manager()

# Run analysis on a file
result = manager.run_analysis('/path/to/file.exe', scan_id=123)

# Get session details
details = manager.get_session_details(session_id=1)

# Get filtered captures
captures = manager.get_filtered_captures(
    session_id=1,
    event_type='network_connection',
    severity='critical'
)

# Get statistics
stats = manager.get_statistics()
```

## Performance Considerations

1. **Database Indexing**: Indexes are created on frequently queried columns
2. **Event Pagination**: Live captures are limited to 500 events per query
3. **Session Cleanup**: Old sessions can be cleared via API
4. **Memory Management**: Dynamic analyzer has configurable memory limits

## Future Enhancements

1. **Real-time Streaming**: WebSocket support for live event streaming
2. **Advanced Filtering**: More sophisticated filtering options
3. **Report Generation**: PDF/HTML report generation for sessions
4. **Comparison**: Compare multiple analysis sessions
5. **Machine Learning**: Use behavioral data for improved detection
6. **Integration**: Integrate with external threat intelligence feeds

## Troubleshooting

### No sessions appearing
- Ensure database has been initialized: `database.init_db()`
- Check that dynamic analysis has been run on at least one file

### Events not showing
- Verify that the session_id is correct
- Check database for live_captures entries

### Performance issues
- Clear old sessions: `POST /api/dynamic/clear`
- Check database size and consider archiving old data

## Files Modified/Created

### New Files
- `dynamic_analysis_manager.py`: Manager for dynamic analysis
- `templates/dynamic_analysis.html`: Main dashboard
- `templates/dynamic_detail.html`: Session details
- `templates/live_captures.html`: Event viewer
- `DYNAMIC_ANALYSIS_GUIDE.md`: This file

### Modified Files
- `app.py`: Added routes for dynamic analysis
- `database.py`: Added new tables and functions
- `templates/base.html`: Added navigation link
- `templates/dashboard.html`: Added statistics widget

## Security Notes

1. **Sandbox Execution**: Dynamic analysis should only be run in isolated environments
2. **File Cleanup**: Temporary files are cleaned up after analysis
3. **Data Privacy**: Sensitive data in captures should be handled carefully
4. **Access Control**: Consider implementing authentication for sensitive analysis data

## Support and Feedback

For issues or feature requests related to dynamic analysis, please refer to the main ViroScope documentation.
