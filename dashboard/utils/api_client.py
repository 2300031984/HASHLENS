"""
HashLens Dashboard API Client
Provides communication with HashLens FastAPI REST backend.
The dashboard operates strictly as an HTTP client of the backend API.
No direct database sessions, models, or backend database services are instantiated here.
"""

import os
import requests
from typing import Any, Dict, List, Optional
from backend.app.core.config import settings


class HashLensClient:
    """Client for HashLens backend REST API."""

    def __init__(self, base_url: Optional[str] = None):
        api_v1_prefix = getattr(settings, "API_V1_PREFIX", "/api/v1") if "settings" in globals() else "/api/v1"
        api_port = getattr(settings, "API_PORT", 8000) if "settings" in globals() else 8000

        api_url_env = (
            os.getenv("API_BASE_URL")
            or os.getenv("API_URL")
            or os.getenv("BACKEND_URL")
            or getattr(settings, "API_URL", None)
        )
        if api_url_env:
            url = api_url_env.rstrip("/")
            if not url.startswith("http://") and not url.startswith("https://"):
                url = f"https://{url}"
            if not url.endswith(api_v1_prefix):
                url = f"{url}{api_v1_prefix}"
            self.base_url = base_url or url
        else:
            host = os.getenv("API_HOST", "127.0.0.1")
            if host == "0.0.0.0":
                host = "127.0.0.1"
            self.base_url = base_url or f"http://{host}:{api_port}{api_v1_prefix}"
        self.auth_token: Optional[str] = None

    def _get_headers(self, token: Optional[str] = None) -> Dict[str, str]:
        headers = {}
        t = token or self.auth_token
        if t:
            headers["Authorization"] = f"Bearer {t}"
        return headers

    def register(self, email: str, username: str, password: str) -> Dict[str, Any]:
        """Register a new user account."""
        try:
            resp = requests.post(
                f"{self.base_url}/auth/register",
                json={"email": email, "username": username, "password": password},
                timeout=5,
            )
            if resp.status_code == 201:
                return resp.json()
            if resp.status_code in (400, 422):
                detail = resp.json().get("detail", "Registration failed.")
                if isinstance(detail, list):
                    detail = detail[0].get("msg", "Validation error")
                return {"error": detail}
        except Exception as e:
            return {"error": f"Registration request failed: {str(e)}"}
        return {"error": "Registration failed."}

    def login(self, login: str, password: str) -> Dict[str, Any]:
        """Authenticate user login and retrieve JWT access token."""
        try:
            resp = requests.post(
                f"{self.base_url}/auth/login",
                json={"login": login, "password": password},
                timeout=5,
            )
            if resp.status_code == 200:
                data = resp.json()
                self.auth_token = data.get("access_token")
                return data
            if resp.status_code in (400, 401, 422):
                detail = resp.json().get("detail", "Invalid credentials.")
                if isinstance(detail, list):
                    detail = detail[0].get("msg", "Validation error")
                return {"error": detail}
        except Exception as e:
            return {"error": f"Login request failed: {str(e)}"}
        return {"error": "Authentication failed."}

    def get_current_user(self, token: Optional[str] = None) -> Dict[str, Any]:
        """Fetch current user profile using JWT token."""
        headers = self._get_headers(token)
        try:
            resp = requests.get(f"{self.base_url}/auth/me", headers=headers, timeout=5)
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code == 401:
                return {"error": resp.json().get("detail", "Unauthorized")}
        except Exception as e:
            return {"error": f"Get current user request failed: {str(e)}"}
        return {"error": "Failed to fetch user profile."}

    def logout(self, token: Optional[str] = None) -> Dict[str, Any]:
        """Logout user session."""
        headers = self._get_headers(token)
        try:
            requests.post(f"{self.base_url}/auth/logout", headers=headers, timeout=3)
        except Exception:
            pass
        self.auth_token = None
        return {"message": "Successfully logged out"}

    @property
    def is_production(self) -> bool:
        """Return True if running under production environment settings."""
        env = os.getenv("APP_ENV", getattr(settings, "APP_ENV", "development"))
        return env.lower() == "production"

    def get_health(self) -> Dict[str, Any]:
        """Fetch platform health strictly via REST API HTTP endpoint GET /api/v1/health."""
        try:
            resp = requests.get(f"{self.base_url}/health", timeout=3)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass

        return {
            "status": "BACKEND_UNAVAILABLE",
            "app": getattr(settings, "APP_NAME", "HashLens"),
            "version": getattr(settings, "APP_VERSION", "1.0.0"),
            "environment": getattr(settings, "APP_ENV", "production" if self.is_production else "development"),
            "uptime_seconds": 0.0,
            "database": "UNAVAILABLE",
            "chain_health": "CHAIN_UNREACHABLE",
            "error": "Backend REST API is unreachable.",
        }

    def get_algorithms(self) -> Dict[str, Any]:
        """Fetch supported algorithms and security metadata."""
        try:
            resp = requests.get(f"{self.base_url}/algorithms", timeout=2)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass

        return {
            "supported_algorithms": ["sha256", "sha512", "sha1", "md5"],
            "metadata": {
                "sha256": {"bits": 256, "security": "SECURE", "use_case": "Primary Forensic Standard"},
                "sha512": {"bits": 512, "security": "SECURE", "use_case": "High-Security Verification"},
                "sha1": {"bits": 160, "security": "WEAK", "use_case": "Legacy Baseline Compatibility"},
                "md5": {"bits": 128, "security": "DEPRECATED", "use_case": "Legacy Checksum (Collision Vulnerable)"},
            },
        }

    def hash_text(self, text: str, algorithms: Optional[List[str]] = None) -> Dict[str, Any]:
        """Hash string of text."""
        try:
            resp = requests.post(
                f"{self.base_url}/hash/text",
                json={"text": text, "algorithms": algorithms},
                timeout=5,
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass

        import hashlib
        algs = algorithms or ["sha256", "sha512", "sha1", "md5"]
        b = text.encode("utf-8")
        digests = {}
        for a in algs:
            if hasattr(hashlib, a):
                digests[a] = getattr(hashlib, a)(b).hexdigest()
        return {
            "input_length_chars": len(text),
            "input_length_bytes": len(b),
            "hashes": digests,
            "algorithms_used": list(digests.keys()),
        }

    def hash_file(self, file_bytes: bytes, filename: str, chunk_size: int = 1048576) -> Dict[str, Any]:
        """Hash uploaded file bytes."""
        try:
            files = {"file": (filename, file_bytes, "application/octet-stream")}
            data = {"chunk_size": str(chunk_size)}
            resp = requests.post(f"{self.base_url}/hash/file", files=files, data=data, timeout=30)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass

        import hashlib
        b_len = len(file_bytes)
        hashes = {
            "sha256": hashlib.sha256(file_bytes).hexdigest(),
            "sha512": hashlib.sha512(file_bytes).hexdigest(),
            "sha1": hashlib.sha1(file_bytes).hexdigest(),
            "md5": hashlib.md5(file_bytes).hexdigest(),
        }
        return {
            "filename": filename,
            "size_bytes": b_len,
            "size_human": f"{b_len / 1024:.2f} KB",
            "mime_type": "application/octet-stream",
            "file_category": "binary",
            "extension": f".{filename.split('.')[-1]}" if "." in filename else "",
            "chunk_size": chunk_size,
            "chunk_count": (b_len + chunk_size - 1) // chunk_size if chunk_size > 0 else 1,
            "hashes": hashes,
            "metadata_fingerprint": hashlib.sha256(f"{filename}:{b_len}".encode()).hexdigest(),
        }

    def calculate_avalanche(self, text1: str, text2: str, algorithm: str = "sha256") -> Dict[str, Any]:
        """Compute bit-flip avalanche metrics."""
        try:
            resp = requests.post(
                f"{self.base_url}/avalanche",
                json={"text1": text1, "text2": text2, "algorithm": algorithm},
                timeout=5,
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass

        import hashlib
        h1 = getattr(hashlib, algorithm)(text1.encode()).hexdigest()
        h2 = getattr(hashlib, algorithm)(text2.encode()).hexdigest()
        b1 = bytes.fromhex(h1)
        b2 = bytes.fromhex(h2)
        total_bits = len(b1) * 8
        flipped = sum(bin(byte1 ^ byte2).count("1") for byte1, byte2 in zip(b1, b2))
        return {
            "algorithm": algorithm,
            "digest1": h1,
            "digest2": h2,
            "total_bits": total_bits,
            "flipped_bits": flipped,
            "identical_bits": total_bits - flipped,
            "flip_percentage": round((flipped / total_bits) * 100, 2) if total_bits else 0,
        }

    def compare_fingerprints(self, fp_a: Dict[str, Any], fp_b: Dict[str, Any]) -> Dict[str, Any]:
        """Forensically compare two fingerprints."""
        try:
            resp = requests.post(
                f"{self.base_url}/compare",
                json={"fingerprint_a": fp_a, "fingerprint_b": fp_b},
                timeout=10,
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass

        match = fp_a.get("hashes", {}).get("sha256") == fp_b.get("hashes", {}).get("sha256")
        return {
            "identical": match,
            "overall_status": "IDENTICAL" if match else "MODIFIED",
            "assessment": {
                "classification": "MATCH" if match else "TAMPERED",
                "summary": "Fingerprints match." if match else "Cryptographic hashes differ.",
            },
        }

    def track_file(self, fingerprint: Dict[str, Any]) -> Dict[str, Any]:
        """Commit fingerprint into version history and chain via backend API."""
        try:
            resp = requests.post(
                f"{self.base_url}/files/track",
                json=fingerprint,
                headers=self._get_headers(),
                timeout=10,
            )
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code in (400, 401, 422):
                return {"error": resp.json().get("detail", "File tracking failed.")}
        except Exception:
            pass

        return {"error": "File tracking API call failed (backend unreachable)."}

    def get_tracked_files(self) -> List[Dict[str, Any]]:
        """List all tracked files via backend API."""
        try:
            resp = requests.get(f"{self.base_url}/files", headers=self._get_headers(), timeout=5)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass

        return []

    def get_timeline(self, file_id: str) -> Dict[str, Any]:
        """Get chronological version timeline for a file via backend API."""
        try:
            resp = requests.get(f"{self.base_url}/files/{file_id}/timeline", headers=self._get_headers(), timeout=5)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass

        return {"error": f"Timeline API call failed for file '{file_id}' (backend unreachable)."}

    def verify_chain(self) -> Dict[str, Any]:
        """Perform audit of the tamper-evident chain via backend API."""
        try:
            resp = requests.post(f"{self.base_url}/chain/verify", headers=self._get_headers(), timeout=10)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass

        return {
            "status": "CHAIN_UNREACHABLE",
            "valid": False,
            "error": "Chain audit API call failed (backend unreachable).",
        }

    def get_chain_records(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent chain records via backend API."""
        try:
            resp = requests.get(f"{self.base_url}/chain/records?limit={limit}", headers=self._get_headers(), timeout=5)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass

        return []

    def simulate_tamper(self, record_id: str) -> Dict[str, Any]:
        """Simulate tampering with a chain block via backend API."""
        if self.is_production:
            return {"error": "Tamper simulation is disabled in production mode."}

        try:
            resp = requests.post(f"{self.base_url}/chain/simulate-tamper?record_id={record_id}", headers=self._get_headers(), timeout=5)
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code in (403, 400):
                return resp.json()
        except Exception:
            pass

        return {"error": "Tamper simulation API call failed (backend unreachable)."}

    def generate_evidence(
        self,
        fingerprint: Dict[str, Any],
        comparison_result: Optional[Dict[str, Any]] = None,
        version_num: int = 1,
        notes: str = "",
    ) -> Dict[str, Any]:
        """Generate Evidence Report via backend API."""
        try:
            resp = requests.post(
                f"{self.base_url}/evidence/generate",
                json={
                    "fingerprint": fingerprint,
                    "comparison_result": comparison_result,
                    "version_num": version_num,
                    "analyst_notes": notes,
                },
                headers=self._get_headers(),
                timeout=10,
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass

        return {"error": "Evidence generation API call failed (backend unreachable)."}

    def render_html_report(self, report_data: Dict[str, Any]) -> str:
        """Render printable forensic HTML certificate from report dictionary."""
        meta = report_data.get("file_metadata", {})
        hashes = report_data.get("cryptographic_hashes", {})
        comp = report_data.get("comparison_analysis") or {}
        chain = report_data.get("chain_audit_status", {})
        assessment = comp.get("assessment", {})

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>HashLens Forensic Evidence Report - {report_data.get("report_id")}</title>
    <style>
        body {{
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
            background-color: #0b0f19;
            color: #e2e8f0;
            margin: 0;
            padding: 40px 20px;
        }}
        .report-card {{
            max-width: 900px;
            margin: 0 auto;
            background: #131b2e;
            border: 1px solid #1e293b;
            border-radius: 12px;
            padding: 36px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            border-bottom: 2px solid #00f0ff;
            padding-bottom: 20px;
            margin-bottom: 25px;
        }}
        .title {{
            font-size: 24px;
            font-weight: 700;
            color: #f8fafc;
            letter-spacing: 0.05em;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .badge-valid {{
            background-color: rgba(16, 185, 129, 0.2);
            color: #10b981;
            border: 1px solid #10b981;
        }}
        .hash-display {{
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 13px;
            background: #090d16;
            padding: 10px 14px;
            border-radius: 6px;
            border: 1px solid #1e293b;
            word-break: break-all;
            color: #38bdf8;
            margin: 6px 0 16px 0;
        }}
        .evidence-hash-box {{
            background: #0f172a;
            border: 1px solid #00f0ff;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 30px;
        }}
        .evidence-label {{
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            color: #94a3b8;
        }}
        .section-title {{
            font-size: 16px;
            font-weight: 600;
            color: #38bdf8;
            margin-top: 25px;
            margin-bottom: 12px;
            border-bottom: 1px solid #1e293b;
            padding-bottom: 6px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        th, td {{
            text-align: left;
            padding: 10px 14px;
            font-size: 13px;
            border-bottom: 1px solid #1e293b;
        }}
        th {{
            color: #94a3b8;
            font-weight: 600;
            background: #0f172a;
        }}
        .footer {{
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #1e293b;
            font-size: 12px;
            color: #64748b;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="report-card">
        <div class="header">
            <div>
                <div class="title">🛡️ HASHLENS FORENSIC EVIDENCE REPORT</div>
                <div style="color: #94a3b8; font-size: 13px; margin-top: 4px;">Report ID: {report_data.get("report_id")}</div>
            </div>
            <div style="text-align: right;">
                <span class="badge badge-valid">AUTHENTIC EVIDENCE</span>
                <div style="color: #64748b; font-size: 12px; margin-top: 6px;">Generated: {report_data.get("generated_at")}</div>
            </div>
        </div>

        <div class="evidence-hash-box">
            <div class="evidence-label">EVIDENCE REPORT HASH (SHA-256 INTEGRITY DIGEST)</div>
            <div class="hash-display" style="color: #00f0ff; font-weight: bold;">
                {report_data.get("evidence_report_hash")}
            </div>
        </div>

        <div class="section-title">FILE IDENTITY & METADATA</div>
        <table>
            <tr><th>Filename</th><td>{meta.get("filename")}</td><th>Version</th><td>V{meta.get("version_number", 1)}</td></tr>
            <tr><th>File Size</th><td>{meta.get("size_bytes")} bytes ({meta.get("size_human")})</td><th>Detected MIME</th><td>{meta.get("mime_type")}</td></tr>
        </table>

        <div class="section-title">CRYPTOGRAPHIC DIGESTS</div>
        <div class="evidence-label">SHA-256 (Primary Integrity Digest)</div>
        <div class="hash-display">{hashes.get("sha256")}</div>

        <div class="section-title">TAMPER-EVIDENT HASH CHAIN AUDIT STATUS</div>
        <table>
            <tr><th>Chain Status</th><td><strong>{chain.get("status")}</strong></td></tr>
            <tr><th>Integrity Valid</th><td>{"✓ Intact" if chain.get("valid") else "✗ Broken"}</td></tr>
        </table>

        <div class="footer">
            Generated by {report_data.get("tool_name", "HashLens")} | Timestamp: {report_data.get("generated_at")}
        </div>
    </div>
</body>
</html>
"""


api_client = HashLensClient()
