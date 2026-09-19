# HashLens Platform Architecture

HashLens is a security-focused file integrity monitoring and cryptographic forensics platform designed for enterprise threat response, code auditing, and digital evidence certification.

---

## 1. High-Level System Architecture

```mermaid
graph TD
    User([Forensic Analyst / User]) --> Dashboard[Streamlit SOC Dashboard :8501]
    CLI([Terminal / HashLens CLI]) --> Services
    SIEM([SIEM / SOAR / CI Pipeline]) --> REST_API[FastAPI REST API :8000]
    
    Dashboard --> REST_API
    REST_API --> SecMiddleware[Defensive Security Middleware]
    SecMiddleware --> Services[Core Business Logic Services]

    subgraph Core Engines [Core Forensic & Cryptographic Engines]
        HashingEngine[Streaming Hashing Engine: MD5, SHA-1, SHA-256, SHA-512]
        FileService[Safe File Handler & Advisory Signature Sniffer]
        FingerprintService[Multi-Chunk Block Mapper]
        ComparisonEngine[Forensic Diff & 'Why Hash Changed' Classifier]
        HistoryService[Version Tracking & Asset Lifecycles]
        ChainService[Tamper-Evident Hash Chain Engine]
        EvidenceService[Evidence Report Generator & Report Digest]
    end

    Services --> Core Engines
    Core Engines --> SafeTemp[Ephemeral Streaming Buffer]
    CoreEngines --> DB[(SQLAlchemy Persistence: SQLite / PostgreSQL)]
    DB --> Alembic[Alembic Database Migration Framework]
```

---

## 1.1 Persistence & Dual Database Architecture

HASHLENS supports dual persistence engine options configured seamlessly via `DATABASE_URL`:
- **SQLite Development Mode** (`sqlite:///./data/hashlens.db`): Zero-dependency local persistence for fast unit testing, local execution, and standalone demonstrations.
- **PostgreSQL Production Mode** (`postgresql+psycopg://USER:PASSWORD@HOST:5432/DATABASE`): Production-grade database persistence utilizing the modern `psycopg3` driver with pre-ping connection pooling (`pool_pre_ping=True`, `pool_size=5`, `max_overflow=10`).
- **Alembic Database Migrations**: Versioned database migration framework (`alembic/`) providing controlled schema initialization, foreign key integrity, and zero-downtime updates without destructive table drops.

---

## 2. Component Responsibilities

| Component | Directory / File | Core Responsibility |
| :--- | :--- | :--- |
| **API Layer** | `backend/app/api/` | Exposes versioned `/api/v1` REST endpoints with strict Pydantic validation, error masking, and OpenAPI generation. |
| **Auth & Security** | `backend/app/core/auth_security.py` | Enforces Argon2id password hashing, JWT access token generation/decoding, and application-level per-user data isolation. |
| **Security Layer** | `backend/app/core/security.py` | Enforces sliding-window rate limiting, security headers (CSP, HSTS, X-Frame-Options), and correlation IDs. |
| **Hashing Engine** | `backend/app/services/hashing_engine.py` | Multi-algorithm streaming engine with constant-time verification and avalanche effect metrics. |
| **Safe File Service** | `backend/app/services/file_service.py` | Neutralizes directory traversal attacks, strips null bytes, and provides advisory magic byte sniffing. |
| **Fingerprint Service** | `backend/app/services/fingerprint_service.py` | Slices files into sequential chunks, computing individual chunk SHA-256 digests and metadata fingerprints. |
| **Comparison Engine** | `backend/app/services/comparison_service.py` | Computes chunk-by-chunk diff maps and evaluates the deterministic "Why Did My Hash Change?" rules engine. |
| **Tamper-Evident Chain** | `backend/app/services/chain_service.py` | Cryptographically links audit events ($H_n = \text{SHA256}(\text{Record}_n + H_{n-1})$) per user and provides $O(N)$ audit verification. |
| **Evidence Service** | `backend/app/services/evidence_service.py` | Compiles canonical evidence reports and seals them with an immutable **Evidence Report Hash** owned by the generating user. |
| **SOC Dashboard** | `dashboard/` | Security Operations Center inspired interactive web dashboard for analysts with authenticated per-user session isolation. |
| **CLI Tool** | `backend/app/cli.py` | Standalone terminal utility calling core services directly for shell integration. |

---

## 3. Data & Execution Flows

### 3.1 Streaming File Processing & Chunk Fingerprinting Flow

```mermaid
sequenceDiagram
    autonumber
    actor Analyst
    participant API as FastAPI Upload Handler
    participant SafeFile as SafeFileService
    participant Engine as FingerprintService
    participant Hasher as HashingEngine

    Analyst->>API: POST /api/v1/hash/file (multipart stream)
    API->>SafeFile: sanitize_filename(raw_filename)
    SafeFile-->>API: clean_filename (traversals & null bytes stripped)
    API->>Engine: generate_fingerprint_from_stream(stream, chunk_size)
    loop Every Chunk (default 1MB)
        Engine->>Engine: Stream chunk into memory buffer
        Engine->>Hasher: Update MD5, SHA-1, SHA-256, SHA-512 states
        Engine->>Hasher: Compute individual chunk SHA-256
        Engine->>Engine: Record {index, offset, length, sha256}
    end
    Engine->>SafeFile: Sniff magic bytes from initial chunk
    Engine->>Engine: Build canonical metadata & compute Metadata Fingerprint
    Engine-->>API: Full Forensic Fingerprint Object
    API-->>Analyst: JSON Response (Memory buffer cleaned)
```

### 3.2 "Why Did My Hash Change?" Diagnostic Flow

```mermaid
flowchart TD
    Start([Input: Fingerprint A & Fingerprint B]) --> WholeCheck{Whole-File SHA-256 Match?}
    
    WholeCheck -- YES --> MetaCheck{Metadata or Name Differ?}
    MetaCheck -- YES --> ClassMeta[METADATA_CHANGE: Content identical, metadata differed]
    MetaCheck -- NO --> ClassNone[NO_CHANGE: Bitwise identical]

    WholeCheck -- NO --> OverlapCheck{Matching Chunk Count > 0?}
    
    OverlapCheck -- NO --> TypeCheck{Magic Type Changed?}
    TypeCheck -- YES --> ClassType[FILE_TYPE_CHANGE: Header signature altered]
    TypeCheck -- NO --> ShiftCheck{Chunks Match Out-Of-Order?}
    ShiftCheck -- YES --> ClassStruct[STRUCTURAL_CHANGE: Block shift or insertion]
    ShiftCheck -- NO --> ClassReplace[MAJOR_REPLACEMENT: 0% chunk resemblance]

    OverlapCheck -- YES --> TailCheck{Only Last Chunk Extended / Appended?}
    TailCheck -- YES --> ClassSize[SIZE_CHANGE: Prefix intact, data appended/truncated]
    TailCheck -- NO --> ClassMod[CONTENT_MODIFICATION: Targeted byte edits in specific chunks]
```

### 3.3 Tamper-Evident Hash Chain Linking Flow

```mermaid
graph LR
    subgraph Genesis Block
        H0[Genesis: 0x00...00]
    end
    subgraph Block 1
        R1[Record 1 Data] --> C1[Canonical JSON + H0]
        C1 --> H1[Current Hash H1]
    end
    subgraph Block 2
        R2[Record 2 Data] --> C2[Canonical JSON + H1]
        C2 --> H2[Current Hash H2]
    end
    subgraph Block 3
        R3[Record 3 Data] --> C3[Canonical JSON + H2]
        C3 --> H3[Current Hash H3]
    end

    H0 --> C1
    H1 --> C2
    H2 --> C3
```
