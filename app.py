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

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXTENSIONS = {"exe", "dll", "sys", "ocx", "scr", "cpl", "drv"}
MAX_CONTENT_LENGTH = 64 * 1024 * 1024  # 64 MB per file

os.makedirs(UPLOAD_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(os.path.join(BASE_DIR, "viroscope.log")), logging.StreamHandler()],
)
logger = logging.getLogger("viroscope.app")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-key-change-me")
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

vt_scanner = VirusTotalScanner()

database.init_db()
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


def run_full_analysis(saved_path, original_name, check_vt=True):
    """ML prediction + optional VirusTotal lookup + history persistence."""
    ml_result = predict_file(saved_path)

    file_size = os.path.getsize(saved_path) if os.path.exists(saved_path) else None
    sha256 = VirusTotalScanner.sha256_of(saved_path) if os.path.exists(saved_path) else None

    vt_result = None
    if check_vt and vt_scanner.enabled and sha256:
        vt_result = vt_scanner.lookup_hash(sha256)

    database.save_scan(
        file_name=original_name,
        sha256=sha256,
        file_size=file_size,
        ml_result=ml_result,
        vt_result=vt_result,
    )

    return {
        "file_name": original_name,
        "sha256": sha256,
        "file_size": file_size,
        "ml": ml_result,
        "vt": vt_result,
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
    return render_template("dashboard.html", stats=stats, recent=recent)


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
    check_vt = request.form.get("check_vt", "1") == "1"

    try:
        result = run_full_analysis(saved_path, original_name, check_vt=check_vt)
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
            ml_result = predict_file(saved_path)
            file_size = os.path.getsize(saved_path) if os.path.exists(saved_path) else None
            sha256 = VirusTotalScanner.sha256_of(saved_path) if os.path.exists(saved_path) else None

            vt_result = None
            if check_vt and vt_scanner.enabled and sha256:
                vt_result = vt_scanner.lookup_hash(sha256)

            database.save_scan(
                file_name=original_name,
                sha256=sha256,
                file_size=file_size,
                ml_result=ml_result,
                vt_result=vt_result,
                batch_id=batch_id,
            )

            results.append({
                "file_name": original_name,
                "sha256": sha256,
                "file_size": file_size,
                "ml": ml_result,
                "vt": vt_result,
            })
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
    app.run(host="127.0.0.1", port=5000, debug=True)
