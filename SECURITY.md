# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Security Scope & Intended Usage

HASHLENS is designed as a local-first file integrity monitoring and cryptographic hash forensics platform.

> [!IMPORTANT]
> **Data Processing Notice:** HASHLENS is designed for local analysis of authorized files, system artifacts, and forensic logs. Operators should only upload and analyze files they have explicit authorization to inspect.

## Vulnerability Reporting

If you discover a security vulnerability or security bug in HASHLENS, please report it via the GitHub Repository Issues interface using the confidential reporting option or by opening a security advisory issue on the repository:

Repository: [https://github.com/2300031984/HASHLENS](https://github.com/2300031984/HASHLENS)

### Responsible Disclosure Guidelines
- Provide detailed steps to reproduce the issue.
- Allow reasonable time to address the issue before public disclosure.
- Do not exploit identified vulnerabilities beyond proof-of-concept verification.

## Validated Security Controls

HASHLENS incorporates the following defense-in-depth security controls:
- **Path Traversal Protection:** Input filenames are sanitized using `Path(filename).name` boundary enforcement.
- **Upload Limits:** Streamed file uploads are capped at 100 MB (`MAX_UPLOAD_SIZE`).
- **Temporary Storage Cleanup:** Temporary byte streams are automatically removed after hashing.
- **Strict Execution Isolation:** Files are stored as inert data blobs without execution privileges.
- **In-Memory Rate Limiting:** Sliding-window rate limiter prevents endpoint denial-of-service.
- **Security Headers:** Response middleware emits `CSP`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Referrer-Policy`.
- **Environment-Controlled HSTS:** `ENABLE_HSTS` flag controls HSTS header emission to protect HTTPS production deployments while preserving plain HTTP local development.
