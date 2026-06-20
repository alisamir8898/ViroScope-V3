"""
vt_scanner.py
-------------
Clean integration with the VirusTotal API v3. Looks up a file by its
SHA-256 hash first (instant, no upload needed) and only uploads the file
if VirusTotal has never seen it before.
"""

import os
import time
import hashlib
import logging

import requests

logger = logging.getLogger("viroscope.vt")

VT_API_URL = "https://www.virustotal.com/api/v3"


class VirusTotalScanner:
    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.environ.get("VT_API_KEY", "").strip()
        self.enabled = bool(self.api_key)
        self.headers = {"x-apikey": self.api_key, "Accept": "application/json"}
        if not self.enabled:
            logger.warning("VirusTotal API key not configured; VT lookups disabled.")

    @staticmethod
    def sha256_of(file_path: str) -> str:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def get_status(self) -> dict:
        """Lightweight check that the configured API key actually works."""
        if not self.enabled:
            return {"enabled": False, "status": "disabled", "message": "No API key configured."}

        try:
            resp = requests.get(f"{VT_API_URL}/users/current", headers=self.headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                quotas = data.get("quotas", {})
                return {"enabled": True, "status": "operational", "quotas": quotas}
            if resp.status_code == 401:
                return {"enabled": True, "status": "error", "message": "Invalid API key."}
            return {"enabled": True, "status": "error", "message": f"API error {resp.status_code}"}
        except requests.RequestException as exc:
            return {"enabled": True, "status": "error", "message": str(exc)}

    def lookup_hash(self, file_hash: str) -> dict:
        """Check if VirusTotal already has a report for this hash."""
        if not self.enabled:
            return {"found": False, "error": "VirusTotal API key not configured"}

        try:
            resp = requests.get(f"{VT_API_URL}/files/{file_hash}", headers=self.headers, timeout=15)
            if resp.status_code == 200:
                return self._format_report(resp.json())
            if resp.status_code == 404:
                return {"found": False}
            logger.error("VT lookup error %s: %s", resp.status_code, resp.text[:300])
            return {"found": False, "error": f"VirusTotal API error {resp.status_code}"}
        except requests.RequestException as exc:
            logger.error("VT lookup request failed: %s", exc)
            return {"found": False, "error": str(exc)}

    def scan_file(self, file_path: str, wait_for_result: bool = True, max_wait: int = 60) -> dict:
        """
        Scan a file with VirusTotal. Checks the hash first; only uploads
        the file if VirusTotal has no existing report for it.
        """
        if not self.enabled:
            return {"error": "VirusTotal API key not configured"}

        file_hash = self.sha256_of(file_path)
        existing = self.lookup_hash(file_hash)

        if existing.get("found"):
            return existing

        upload_result = self._upload_file(file_path)
        if "error" in upload_result:
            return upload_result

        if not wait_for_result:
            return {"found": False, "pending": True, "sha256": file_hash}

        return self._poll_for_report(file_hash, max_wait=max_wait)

    def _upload_file(self, file_path: str) -> dict:
        try:
            with open(file_path, "rb") as f:
                files = {"file": (os.path.basename(file_path), f)}
                resp = requests.post(f"{VT_API_URL}/files", headers=self.headers, files=files, timeout=60)
            if resp.status_code == 200:
                return resp.json()
            logger.error("VT upload error %s: %s", resp.status_code, resp.text[:300])
            return {"error": f"Upload failed with status {resp.status_code}"}
        except requests.RequestException as exc:
            logger.error("VT upload request failed: %s", exc)
            return {"error": str(exc)}

    def _poll_for_report(self, file_hash: str, max_wait: int = 60, interval: int = 5) -> dict:
        elapsed = 0
        while elapsed < max_wait:
            result = self.lookup_hash(file_hash)
            if result.get("found"):
                return result
            time.sleep(interval)
            elapsed += interval
        return {"found": False, "pending": True, "sha256": file_hash, "message": "Analysis still in progress on VirusTotal."}

    @staticmethod
    def _format_report(vt_response: dict) -> dict:
        data = vt_response.get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        results = attributes.get("last_analysis_results", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0

        engines = []
        for engine_name, result in sorted(results.items()):
            engines.append({
                "engine": engine_name,
                "category": result.get("category", "undetected"),
                "result": result.get("result"),
            })

        return {
            "found": True,
            "sha256": attributes.get("sha256", ""),
            "md5": attributes.get("md5", ""),
            "scan_date": attributes.get("last_analysis_date"),
            "total_engines": total,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "detection_ratio": f"{malicious + suspicious}/{total}" if total else "0/0",
            "permalink": f"https://www.virustotal.com/gui/file/{attributes.get('sha256', '')}",
            "engines": engines,
        }
