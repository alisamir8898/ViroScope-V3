"""
app.py
------
ViroScope: a local malware-triage web app.

Routes:
  GET  /                      Dashboard (stats + quick upload)
  GET  /scan                  Single-file scan page
  POST /scan                  Run a single-file scan
  GET  /batch                 Batch scan page
  POST /batch                 Run a batch scan (multiple files)
  GET  /history                Scan history page
  GET  /api/history            JSON history (filterable)
  GET  /api/scan/<id>          JSON detail for one past scan
  POST /api/history/clear      Clear all history
  GET  /api/vt-status          Check VirusTotal API key status
  GET  /health                 Liveness check
"""

import os
import uuid
import logging
from datetime import datetime

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

import database
from predictor import predict_file, model_is_ready, load_model
from vt_scanner import VirusTotalScanner
from dynamic_analysis_manager import get_manager as get_analysis_manager
from realtime_monitor import monitor_instance
from api_monitor import get_monitor_events, get_monitor_stats, clear_monitor_stats_cache
from performance_config import apply_performance_config, optimize_database

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXTENSIONS = {"exe", "dll", "sys", "ocx", "scr", "cpl", "drv"}
MAX_CONTENT_LENGTH = 64 * 1024 * 1024  # 64 MB per file

os.makedirs(UPLOAD_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.WARNING,  # Reduced from INFO to WARNING for better performance
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(os.path.join(BASE_DIR, "viroscope.log")), logging.StreamHandler()],
)
logger = logging.getLogger("viroscope.app")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-key-change-me")
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

# Apply performance optimizations
apply_performance_config(app)

vt_scanner = VirusTotalScanner()

database.init_db()
optimize_database()  # Optimize SQLite for performance
load_model()  # warm the model cache at startup so the first request isn't slow


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def save_upload(file_storage):
    """Save an uploaded file under a unique name, return (saved_path, original_name)."""
    original_name = secure_filename(file_storage.filename)
    unique_name = f"{uuid.uuid4().hex}_{original_name}"
    saved_path = os.path.join(UPLOAD_DIR, unique_name)
    file_storage.save(saved_path)
    return saved_path, original_name


def run_full_analysis(saved_path, original_name, check_vt=True, run_dynamic=False, batch_id=None):
    """ML prediction + optional VirusTotal lookup + history persistence + optional dynamic analysis."""
    ml_result = predict_file(saved_path)

    file_size = os.path.getsize(saved_path) if os.path.exists(saved_path) else None
    sha256 = VirusTotalScanner.sha256_of(saved_path) if os.path.exists(saved_path) else None

    vt_result = None
    if check_vt and vt_scanner.enabled and sha256:
        vt_result = vt_scanner.lookup_hash(sha256)

    scan_id = database.save_scan(
        file_name=original_name,
        sha256=sha256,
        file_size=file_size,
        ml_result=ml_result,
        vt_result=vt_result,
        batch_id=batch_id,
    )

    dynamic_result = None
    if run_dynamic:
        try:
            manager = get_analysis_manager()
            dynamic_result = manager.run_analysis(saved_path, scan_id=scan_id, original_name=original_name)
            
            # INTEGRATION: Override ML verdict if dynamic analysis shows high risk
            if dynamic_result.get('success'):
                risk_score = dynamic_result.get('risk_score', 0)
                if risk_score >= 0.6: # If risk is High or Critical
                    new_verdict = "Malicious"
                    # If ML was wrong, update the database to reflect dynamic findings
                    if ml_result.get('verdict') != "Malicious":
                        database.update_scan_verdict(scan_id, "Malicious", confidence=risk_score)
                        # Update local dict for the immediate response
                        ml_result['verdict'] = "Malicious"
                        ml_result['confidence'] = risk_score
                        ml_result['is_malware'] = True
        except Exception as e:
            logger.error(f"Error running dynamic analysis: {e}")
            dynamic_result = {"error": str(e)}

    return {
        "id": scan_id,
        "file_name": original_name,
        "sha256": sha256,
        "file_size": file_size,
        "ml": ml_result,
        "vt": vt_result,
        "dynamic": dynamic_result,
        "timestamp": datetime.now().isoformat(),
    }


@app.context_processor
def inject_globals():
    return {
        "model_ready": model_is_ready(),
        "vt_enabled": vt_scanner.enabled,
    }


@app.route("/")
def dashboard():
    stats = database.get_stats()
    recent = database.get_history(limit=8)
    
    # Get dynamic analysis stats
    try:
        manager = get_analysis_manager()
        dynamic_stats = manager.get_statistics()
    except:
        dynamic_stats = None
    
    return render_template("dashboard.html", stats=stats, recent=recent, dynamic_stats=dynamic_stats)


@app.route("/scan", methods=["GET", "POST"])
def scan():
    if request.method == "GET":
        return render_template("scan.html")

    if "file" not in request.files or request.files["file"].filename == "":
        flash("اختار ملف للفحص الأول.", "error")
        return redirect(url_for("scan"))

    file = request.files["file"]
    if not allowed_file(file.filename):
        flash("نوع الملف غير مدعوم. ViroScope يفحص ملفات تنفيذية فقط (.exe, .dll, .sys, ...).", "error")
        return redirect(url_for("scan"))

    saved_path, original_name = save_upload(file)
    # Use get(key) and check if it's exactly '1' (value of checked checkbox)
    # Checkboxes only send their value if they are checked
    check_vt = request.form.get("check_vt") == "1"
    run_dynamic = request.form.get("run_dynamic") == "1"

    try:
        result = run_full_analysis(saved_path, original_name, check_vt=check_vt, run_dynamic=run_dynamic)
    finally:
        if os.path.exists(saved_path):
            os.remove(saved_path)

    return render_template("scan_result.html", result=result)


@app.route("/batch", methods=["GET", "POST"])
def batch():
    if request.method == "GET":
        return render_template("batch.html")

    files = request.files.getlist("files")
    files = [f for f in files if f and f.filename]

    if not files:
        flash("اختار ملف واحد على الأقل للفحص.", "error")
        return redirect(url_for("batch"))

    check_vt = request.form.get("check_vt", "1") == "1"
    run_dynamic = request.form.get("run_dynamic") == "1"
    batch_id = uuid.uuid4().hex
    results = []

    for file in files:
        if not allowed_file(file.filename):
            results.append({
                "file_name": file.filename,
                "ml": {"success": False, "error": "نوع ملف غير مدعوم", "file_name": file.filename},
                "vt": None,
            })
            continue

        saved_path, original_name = save_upload(file)
        try:
            result = run_full_analysis(
                saved_path, 
                original_name, 
                check_vt=check_vt, 
                run_dynamic=run_dynamic, 
                batch_id=batch_id
            )
            results.append(result)
        finally:
            if os.path.exists(saved_path):
                os.remove(saved_path)

    summary = {
        "total": len(results),
        "malicious": sum(1 for r in results if r["ml"].get("success") and r["ml"].get("is_malware")),
        "benign": sum(1 for r in results if r["ml"].get("success") and not r["ml"].get("is_malware")),
        "errors": sum(1 for r in results if not r["ml"].get("success")),
    }

    return render_template("batch_result.html", results=results, summary=summary, batch_id=batch_id)


@app.route("/history")
def history():
    verdict_filter = request.args.get("verdict", "all")
    search = request.args.get("q", "").strip() or None
    records = database.get_history(limit=200, verdict_filter=verdict_filter, search=search)
    stats = database.get_stats()
    return render_template("history.html", records=records, stats=stats, verdict_filter=verdict_filter, search=search or "")


@app.route("/history/<int:scan_id>")
def history_detail(scan_id):
    record = database.get_scan_by_id(scan_id)
    if record is None:
        flash("الفحص ده غير موجود.", "error")
        return redirect(url_for("history"))
    return render_template("history_detail.html", record=record)


@app.route("/api/history")
def api_history():
    verdict_filter = request.args.get("verdict", "all")
    search = request.args.get("q") or None
    limit = min(int(request.args.get("limit", 100)), 500)
    records = database.get_history(limit=limit, verdict_filter=verdict_filter, search=search)
    return jsonify({"results": records, "count": len(records)})


@app.route("/api/scan/<int:scan_id>")
def api_scan_detail(scan_id):
    record = database.get_scan_by_id(scan_id)
    if record is None:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(record)


@app.route("/api/history/clear", methods=["POST"])
def api_clear_history():
    database.clear_history()
    flash("تم حذف كل السجل التاريخي.", "success")
    return redirect(url_for("history"))


@app.route("/api/history/<int:scan_id>/delete", methods=["POST"])
def api_delete_scan(scan_id):
    database.delete_scan(scan_id)
    return redirect(url_for("history"))


@app.route("/api/vt-status")
def api_vt_status():
    return jsonify(vt_scanner.get_status())


@app.route("/dynamic_analysis")
def dynamic_analysis():
    """Dynamic analysis sessions page"""
    risk_filter = request.args.get("risk", "all")
    malware_type_filter = request.args.get("type", "all")
    search = request.args.get("search", "").strip() or None
    
    manager = get_analysis_manager()
    sessions = manager.get_sessions_list(risk_filter=risk_filter, malware_type_filter=malware_type_filter)
    
    # Filter by search if provided
    if search:
        sessions = [s for s in sessions if search.lower() in s.get('file_name', '').lower() or 
                   search.lower() in s.get('file_hash', '').lower()]
    
    stats = manager.get_statistics()
    return render_template("dynamic_analysis.html", sessions=sessions, stats=stats)


@app.route("/dynamic_analysis/<int:session_id>")
def dynamic_detail(session_id):
    """Dynamic analysis session details"""
    manager = get_analysis_manager()
    details = manager.get_session_details(session_id)
    
    if not details:
        flash("Session not found.", "error")
        return redirect(url_for("dynamic_analysis"))
    
    return render_template("dynamic_detail.html", session=details['session'])


@app.route("/monitor")
def monitor():
    """Real-time monitoring logs page"""
    threat_filter = request.args.get("threat_level", "all")
    event_type = request.args.get("event_type", "all")
    search = request.args.get("search", "").strip() or None
    
    conn = database.get_connection()
    query = "SELECT * FROM monitor_events WHERE 1=1"
    params = []
    
    if threat_filter != "all":
        query += " AND threat_level = ?"
        params.append(threat_filter)
    
    if event_type != "all":
        query += " AND event_type = ?"
        params.append(event_type)
    
    if search:
        query += " AND (process_name LIKE ? OR file_path LIKE ? OR details LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
        
    query += " ORDER BY created_at DESC LIMIT 500"
    
    rows = conn.execute(query, params).fetchall()
    conn.close()
    
    return render_template("monitor.html", events=[dict(r) for r in rows], threat_filter=threat_filter, search=search or "")

@app.route("/api/monitor/events", methods=["GET"])
def api_monitor_events():
    """Fetch monitor events with optional filtering - optimized for real-time updates"""
    limit = min(int(request.args.get("limit", 50)), 200)
    offset = int(request.args.get("offset", 0))
    threat_level = request.args.get("threat_level", "all")
    event_type = request.args.get("event_type", "all")
    search = request.args.get("search", "").strip() or None
    
    result = get_monitor_events(limit=limit, offset=offset, threat_level=threat_level, 
                               event_type=event_type, search=search)
    return jsonify(result)

@app.route("/api/monitor/stats", methods=["GET"])
def api_monitor_stats():
    """Get cached monitor statistics - fast endpoint for real-time dashboard"""
    stats = get_monitor_stats()
    return jsonify(stats)

@app.route("/api/monitor/clear", methods=["POST"])
def api_clear_monitor():
    conn = database.get_connection()
    conn.execute("DELETE FROM monitor_events")
    conn.commit()
    conn.close()
    clear_monitor_stats_cache()
    return jsonify({"success": True})

@app.route("/live_captures/<int:session_id>")
def live_captures(session_id):
    """Live capture events for a session"""
    event_type_filter = request.args.get("event_type", "all")
    severity_filter = request.args.get("severity", "all")
    
    manager = get_analysis_manager()
    details = manager.get_session_details(session_id)
    
    if not details:
        flash("Session not found.", "error")
        return redirect(url_for("dynamic_analysis"))
    
    captures = manager.get_filtered_captures(
        session_id,
        event_type=event_type_filter if event_type_filter != "all" else None,
        severity=severity_filter if severity_filter != "all" else None
    )
    
    return render_template(
        "live_captures.html",
        session=details['session'],
        captures=captures,
        summary=details['capture_summary']
    )


@app.route("/api/dynamic/clear", methods=["POST"])
def api_clear_dynamic():
    """Clear all dynamic analysis sessions"""
    try:
        conn = database.get_connection()
        conn.execute("DELETE FROM live_captures")
        conn.execute("DELETE FROM dynamic_sessions")
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"Error clearing dynamic sessions: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "model_ready": model_is_ready(),
        "vt_enabled": vt_scanner.enabled,
    })


@app.errorhandler(413)
def too_large(e):
    flash("الملف كبير جدًا (الحد الأقصى 64 ميجا).", "error")
    return redirect(request.referrer or url_for("dashboard"))


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


if __name__ == "__main__":
    print("=" * 60)
    print("  ViroScope — Malware Triage Console")
    print("  Running locally at http://127.0.0.1:5000")
    print("=" * 60)
    
    # System-wide monitor is enabled
    monitor_instance.start()
    
    # Clear old general logs to start fresh with targeted monitoring
    try:
        database.clear_monitor_events()
    except:
        pass
        
    try:
        # OPTIMIZATION: Disable auto-reloader and watchdog to prevent constant restarts
        # This significantly improves performance when running in development mode
        app.run(
            host="127.0.0.1", 
            port=5000, 
            debug=False,  # Changed from True to False
            use_reloader=False,  # Disable auto-reloader
            threaded=True  # Ensure threaded mode for better responsiveness
        )
    finally:
        monitor_instance.stop()
