"""
HashLens Security Middleware & Defenses
Implements rate limiting, security headers, correlation IDs,
and controlled structured error handling.
"""

import time
import uuid
from collections import defaultdict
from typing import Dict, List, Tuple
from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from backend.app.core.config import settings
from backend.app.core.logging import logger


class InMemoryRateLimiter:
    """
    Sliding-window in-memory rate limiter keyed by client IP address.
    Keeps track of request timestamps within configured sliding window.
    """

    def __init__(self, max_requests: int = 120, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, List[float]] = defaultdict(list)

    def is_allowed(self, client_ip: str) -> Tuple[bool, int]:
        """
        Returns (is_allowed, remaining_requests).
        Cleans expired timestamps outside window and purges empty IP records.
        """
        now = time.time()
        window_start = now - self.window_seconds

        # Prune old timestamps
        timestamps = [t for t in self.requests[client_ip] if t > window_start]
        
        # Periodic cleanup of stale IPs to prevent unbounded dict growth
        if len(self.requests) > 1000:
            stale_ips = [ip for ip, ts in self.requests.items() if not ts or max(ts) <= window_start]
            for stale_ip in stale_ips:
                del self.requests[stale_ip]

        self.requests[client_ip] = timestamps

        if len(timestamps) >= self.max_requests:
            return False, 0

        self.requests[client_ip].append(now)
        remaining = self.max_requests - len(self.requests[client_ip])
        return True, remaining


rate_limiter = InMemoryRateLimiter(
    max_requests=settings.RATE_LIMIT_REQUESTS,
    window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS,
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Injects defensive HTTP headers: CSP, anti-clickjacking, HSTS,
    anti-MIME-sniffing, and request correlation IDs.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Correlation ID
        request_id = request.headers.get("X-Request-ID", uuid.uuid4().hex)
        request.state.request_id = request_id

        # Rate Limiting Check
        client_ip = request.client.host if request.client else "unknown"
        allowed, remaining = rate_limiter.is_allowed(client_ip)

        if not allowed:
            logger.warning(
                f"Rate limit exceeded for IP {client_ip}",
                extra={"request_id": request_id, "client_ip": client_ip, "event_type": "RATE_LIMIT_EXCEEDED"},
            )
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "Rate limit exceeded.",
                    "detail": f"Maximum {settings.RATE_LIMIT_REQUESTS} requests per {settings.RATE_LIMIT_WINDOW_SECONDS} seconds allowed.",
                    "request_id": request_id,
                },
                headers={"Retry-After": str(settings.RATE_LIMIT_WINDOW_SECONDS)},
            )

        start_time = time.time()
        try:
            response = await call_next(request)
        except Exception as exc:
            # Controlled structured error response (avoids leaking stack traces)
            logger.error(
                f"Unhandled internal exception on {request.method} {request.url.path}: {str(exc)}",
                exc_info=True,
                extra={"request_id": request_id, "client_ip": client_ip},
            )
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={
                    "error": "An internal server error occurred.",
                    "detail": "The incident has been securely logged for investigation.",
                    "request_id": request_id,
                },
            )

        duration_ms = round((time.time() - start_time) * 1000, 2)

        # Append defensive security headers
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
        )
        if settings.ENABLE_HSTS:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-RateLimit-Limit"] = str(settings.RATE_LIMIT_REQUESTS)
        response.headers["X-RateLimit-Remaining"] = str(remaining)

        return response
