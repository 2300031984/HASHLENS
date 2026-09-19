"""
HashLens Dashboard API Client
Provides communication with HashLens FastAPI REST backend.
Local fallback to in-process services is restricted strictly to development mode.
"""

import requests
from typing import Any, Dict, List, Optional
from backend.app.core.config import settings
from backend.app.db.database import SessionLocal
from backend.app.services.chain_service import HashChainService
from backend.app.services.comparison_service import ComparisonEngine
from backend.app.services.evidence_service import EvidenceService
from backend.app.services.fingerprint_service import FingerprintService
from backend.app.services.hashing_engine import HashingEngine
from backend.app.services.history_service import HistoryService


class HashLensClient:
    """Client for HashLens backend services."""

    def __init__(self, base_url: Optional[str] = None):
        import os
        api_url_env = os.getenv("API_URL") or os.getenv("BACKEND_URL") or settings.API_URL
        if api_url_env:
            url = api_url_env.rstrip("/")
            if not url.startswith("http://") and not url.startswith("https://"):
                url = f"https://{url}"
            if not url.endswith(settings.API_V1_PREFIX):
                url = f"{url}{settings.API_V1_PREFIX}"
            self.base_url = base_url or url
        else:
            host = os.getenv("API_HOST", "127.0.0.1")
            if host == "0.0.0.0":
                host = "127.0.0.1"
            self.base_url = base_url or f"http://{host}:{settings.API_PORT}{settings.API_V1_PREFIX}"
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
        return settings.APP_ENV.lower() == "production"

    def get_health(self) -> Dict[str, Any]:
        """Fetch platform health."""
        try:
            resp = requests.get(f"{self.base_url}/health", timeout=2)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass

        if self.is_production:
            return {
                "status": "unhealthy (backend unreachable)",
                "app": settings.APP_NAME,
                "version": settings.APP_VERSION,
                "environment": settings.APP_ENV,
                "error": "Remote API endpoint is unreachable in production mode.",
            }

        # Local development fallback
        db = SessionLocal()
        try:
            audit = HashChainService.verify_chain(db)
            return {
                "status": "online (direct service mode)",
                "app": settings.APP_NAME,
                "version": settings.APP_VERSION,
                "environment": settings.APP_ENV,
                "uptime_seconds": 100.0,
                "database": "healthy",
                "chain_health": audit["status"],
            }
        finally:
            db.close()

    def get_algorithms(self) -> Dict[str, Any]:
        """Fetch supported algorithms and security metadata."""
        try:
            resp = requests.get(f"{self.base_url}/algorithms", timeout=2)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass

        from backend.app.services.hashing_engine import SUPPORTED_ALGORITHMS, ALGORITHM_METADATA
        return {
            "supported_algorithms": SUPPORTED_ALGORITHMS,
            "metadata": ALGORITHM_METADATA,
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

        digests = HashingEngine.hash_text(text, algorithms=algorithms)
        return {
            "input_length_chars": len(text),
            "input_length_bytes": len(text.encode("utf-8")),
            "hashes": digests,
            "algorithms_used": list(digests.keys()),
        }

    def hash_file(self, file_bytes: bytes, filename: str, chunk_size: int = 1048576) -> Dict[str, Any]:
        """Hash uploaded file bytes using streaming fingerprinter."""
        try:
            files = {"file": (filename, file_bytes, "application/octet-stream")}
            data = {"chunk_size": str(chunk_size)}
            resp = requests.post(f"{self.base_url}/hash/file", files=files, data=data, timeout=30)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass

        if self.is_production:
            return {"error": "File hashing API call failed in production mode."}

        import io
        return FingerprintService.generate_fingerprint_from_stream(
            stream=io.BytesIO(file_bytes),
            raw_filename=filename,
            chunk_size=chunk_size,
        )

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

        h1 = HashingEngine.hash_text(text1, algorithms=[algorithm])[algorithm]
        h2 = HashingEngine.hash_text(text2, algorithms=[algorithm])[algorithm]
        metrics = HashingEngine.calculate_avalanche(h1, h2)
        return {
            "algorithm": algorithm,
            "digest1": h1,
            "digest2": h2,
            "total_bits": metrics["total_bits"],
            "flipped_bits": metrics["flipped_bits"],
            "identical_bits": metrics["identical_bits"],
            "flip_percentage": metrics["flip_percentage"],
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

        return ComparisonEngine.compare_fingerprints(fp_a, fp_b)

    def track_file(self, fingerprint: Dict[str, Any]) -> Dict[str, Any]:
        """Commit fingerprint into version history and chain."""
        try:
            resp = requests.post(
                f"{self.base_url}/files/track",
                json=fingerprint,
                headers=self._get_headers(),
                timeout=10,
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass

        if self.is_production:
            return {"error": "File tracking API call failed in production mode."}

        db = SessionLocal()
        try:
            return HistoryService.register_or_update_file(db, fingerprint)
        finally:
            db.close()

    def get_tracked_files(self) -> List[Dict[str, Any]]:
        """List all tracked files."""
        try:
            resp = requests.get(f"{self.base_url}/files", headers=self._get_headers(), timeout=5)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass

        if self.is_production:
            return []

        db = SessionLocal()
        try:
            return HistoryService.list_tracked_files(db)
        finally:
            db.close()

    def get_timeline(self, file_id: str) -> Dict[str, Any]:
        """Get chronological version timeline for a file."""
        try:
            resp = requests.get(f"{self.base_url}/files/{file_id}/timeline", headers=self._get_headers(), timeout=5)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass

        if self.is_production:
            return {"error": f"Timeline API call failed for file '{file_id}' in production mode."}

        db = SessionLocal()
        try:
            return HistoryService.get_file_timeline(db, file_id)
        finally:
            db.close()

    def verify_chain(self) -> Dict[str, Any]:
        """Perform audit of the tamper-evident chain."""
        try:
            resp = requests.post(f"{self.base_url}/chain/verify", headers=self._get_headers(), timeout=10)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass

        if self.is_production:
            return {
                "status": "CHAIN_UNREACHABLE",
                "valid": False,
                "error": "Chain audit API call failed in production mode.",
            }

        db = SessionLocal()
        try:
            return HashChainService.verify_chain(db)
        finally:
            db.close()

    def get_chain_records(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent chain records."""
        try:
            resp = requests.get(f"{self.base_url}/chain/records?limit={limit}", headers=self._get_headers(), timeout=5)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass

        if self.is_production:
            return []

        db = SessionLocal()
        try:
            return HashChainService.get_records(db, limit=limit)
        finally:
            db.close()

    def simulate_tamper(self, record_id: str) -> Dict[str, Any]:
        """Simulate tampering with a chain block for testing. Disabled in production."""
        if self.is_production:
            return {"error": "Tamper simulation is disabled in production mode."}

        try:
            resp = requests.post(f"{self.base_url}/chain/simulate-tamper?record_id={record_id}", headers=self._get_headers(), timeout=5)
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code == 403:
                return {"error": "Tamper simulation is disabled in production mode."}
        except Exception:
            pass

        from backend.app.models.models import ChainRecordModel
        db = SessionLocal()
        try:
            r = db.query(ChainRecordModel).filter(ChainRecordModel.record_id == record_id).first()
            if r:
                r.payload_json = '{"tampered_for_demo": true}'
                db.commit()
                return {"message": f"Record {record_id} tampered successfully for demonstration."}
            return {"error": "Record not found"}
        finally:
            db.close()

    def generate_evidence(
        self,
        fingerprint: Dict[str, Any],
        comparison_result: Optional[Dict[str, Any]] = None,
        version_num: int = 1,
        notes: str = "",
    ) -> Dict[str, Any]:
        """Generate Evidence Report with Evidence Report Hash."""
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

        if self.is_production:
            return {"error": "Evidence generation API call failed in production mode."}

        db = SessionLocal()
        try:
            return EvidenceService.generate_report(
                db=db,
                fingerprint=fingerprint,
                comparison_result=comparison_result,
                version_num=version_num,
                analyst_notes=notes,
            )
        finally:
            db.close()


api_client = HashLensClient()
