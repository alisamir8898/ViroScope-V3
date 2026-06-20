
import database
from datetime import datetime
import json

def verify():
    print("Connecting to database...")
    conn = database.get_connection()
    
    # 1. Insert a test event
    test_process = "ManusTestProcess"
    print(f"Inserting test event for {test_process}...")
    conn.execute("""
        INSERT INTO monitor_events 
        (process_name, process_pid, file_path, event_type, details, threat_level, detected_type, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (test_process, 1234, "C:\\test_path\\malware.exe", "process", "Simulated threat for UI test", "Critical", "Ransomware", datetime.now().isoformat()))
    conn.commit()
    
    # 2. Check if it's there
    print("Verifying insertion...")
    row = conn.execute("SELECT * FROM monitor_events WHERE process_name = ?", (test_process,)).fetchone()
    if row:
        print(f"SUCCESS: Found event in database: {dict(row)}")
    else:
        print("FAILURE: Event not found in database.")
        return

    # 3. Check stats
    print("Checking monitor stats...")
    stats_row = conn.execute("SELECT COUNT(*) as count FROM monitor_events").fetchone()
    print(f"Total events in DB: {stats_row['count']}")
    
    conn.close()
    print("Verification script finished.")

if __name__ == "__main__":
    verify()
