"""
HashLens Core Hashing Engine
Deterministic, streaming cryptographic hashing engine supporting MD5, SHA-1, SHA-256, and SHA-512.
Includes algorithm metadata, avalanche effect analysis, and streaming chunk-level computation.
"""

import hashlib
import hmac
from enum import Enum
from pathlib import Path
from typing import Any, BinaryIO, Dict, Iterable, List, Optional, Set, Tuple


class HashAlgorithm(str, Enum):
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"


SUPPORTED_ALGORITHMS: List[str] = [alg.value for alg in HashAlgorithm]

# Comprehensive educational & security metadata for algorithms
ALGORITHM_METADATA: Dict[str, Dict] = {
    HashAlgorithm.MD5.value: {
        "name": "MD5 (Message Digest 5)",
        "digest_bits": 128,
        "digest_bytes": 16,
        "block_size_bytes": 64,
        "security_status": "CRYPTOGRAPHICALLY_BROKEN",
        "collision_resistant": False,
        "preimage_resistant": "Weakened (Theoretical)",
        "recommended_for_integrity": False,
        "recommended_for_passwords": False,
        "password_alternative": "Argon2id, bcrypt, or PBKDF2",
        "historical_context": (
            "Published by Ron Rivest in 1992. Practical collision attacks demonstrated in 2004 by Wang et al. "
            "Colliding certificates and Flame malware exploited MD5 collisions. "
            "Only acceptable for non-cryptographic checksums or backward-compatibility verification."
        ),
        "caution_note": (
            "Collision attacks allow attackers to craft two distinct inputs producing the identical MD5 digest. "
            "MD5 does NOT suffer from easy mathematical 'reversal', but lack of collision resistance renders it "
            "unfit for security-sensitive integrity or digital signatures."
        ),
    },
    HashAlgorithm.SHA1.value: {
        "name": "SHA-1 (Secure Hash Algorithm 1)",
        "digest_bits": 160,
        "digest_bytes": 20,
        "block_size_bytes": 64,
        "security_status": "CRYPTOGRAPHICALLY_BROKEN",
        "collision_resistant": False,
        "preimage_resistant": "Weakened",
        "recommended_for_integrity": False,
        "recommended_for_passwords": False,
        "password_alternative": "Argon2id, bcrypt, or PBKDF2",
        "historical_context": (
            "Designed by the NSA and published by NIST in 1995. In 2017, CWI Amsterdam and Google announced "
            "the SHAttered attack, proving a practical collision between two distinct PDF documents."
        ),
        "caution_note": (
            "SHA-1 should not be relied upon for digital certificates, signatures, or forensic non-repudiation. "
            "Legacy protocols and git historical repositories continue transitioning to SHA-256."
        ),
    },
    HashAlgorithm.SHA256.value: {
        "name": "SHA-256 (Secure Hash Algorithm 2 - 256 bits)",
        "digest_bits": 256,
        "digest_bytes": 32,
        "block_size_bytes": 64,
        "security_status": "SECURE_STANDARD",
        "collision_resistant": True,
        "preimage_resistant": True,
        "recommended_for_integrity": True,
        "recommended_for_passwords": False,
        "password_alternative": "Argon2id, bcrypt, or scrypt",
        "historical_context": (
            "Part of the SHA-2 family published by NIST in 2001 (FIPS 180-2). Remains the gold standard for "
            "TLS certificates, code signing, forensic baseline hashing, and distributed ledgers."
        ),
        "caution_note": (
            "Although secure for file integrity and message authentication (HMAC-SHA-256), SHA-256 is fast on GPUs "
            "and ASICs, making raw SHA-256 vulnerable to dictionary attacks when misapplied to passwords."
        ),
    },
    HashAlgorithm.SHA512.value: {
        "name": "SHA-512 (Secure Hash Algorithm 2 - 512 bits)",
        "digest_bits": 512,
        "digest_bytes": 64,
        "block_size_bytes": 128,
        "security_status": "HIGH_SECURITY_STANDARD",
        "collision_resistant": True,
        "preimage_resistant": True,
        "recommended_for_integrity": True,
        "recommended_for_passwords": False,
        "password_alternative": "Argon2id, bcrypt, or scrypt",
        "historical_context": (
            "64-bit word architecture variant of SHA-2 published by NIST in 2001. Provides massive 512-bit digest "
            "space offering superior collision resistance margin and resistance to quantum length-extension attacks (in truncated modes)."
        ),
        "caution_note": (
            "Optimal performance on modern 64-bit processors. Like SHA-256, must never be used alone for password "
            "storage without adaptive memory-hard Key Derivation Functions (KDFs)."
        ),
    },
}


class HashingEngine:
    """
    Cryptographic hashing engine supporting multiple standard algorithms simultaneously
    with streaming chunk processing, deterministic outputs, and timing-safe verification.
    """

    DEFAULT_ALGORITHMS: List[str] = [
        HashAlgorithm.MD5.value,
        HashAlgorithm.SHA1.value,
        HashAlgorithm.SHA256.value,
        HashAlgorithm.SHA512.value,
    ]

    @staticmethod
    def _resolve_algorithms(algorithms: Optional[Iterable[str]] = None) -> List[str]:
        """Validate and resolve requested algorithm names."""
        if not algorithms:
            return list(HashingEngine.DEFAULT_ALGORITHMS)

        resolved: List[str] = []
        for alg in algorithms:
            alg_lower = alg.strip().lower()
            if alg_lower not in SUPPORTED_ALGORITHMS:
                raise ValueError(
                    f"Unsupported algorithm: '{alg}'. Supported algorithms are: {', '.join(SUPPORTED_ALGORITHMS)}"
                )
            if alg_lower not in resolved:
                resolved.append(alg_lower)
        return resolved

    @staticmethod
    def _create_hashers(algorithms: Iterable[str]) -> Dict[str, Any]:
        """Instantiate hashlib objects for requested algorithms."""
        hashers: Dict[str, Any] = {}
        for alg in algorithms:
            if alg == HashAlgorithm.MD5.value:
                hashers[alg] = hashlib.md5()
            elif alg == HashAlgorithm.SHA1.value:
                hashers[alg] = hashlib.sha1()
            elif alg == HashAlgorithm.SHA256.value:
                hashers[alg] = hashlib.sha256()
            elif alg == HashAlgorithm.SHA512.value:
                hashers[alg] = hashlib.sha512()
        return hashers

    @classmethod
    def hash_bytes(
        cls,
        data: bytes,
        algorithms: Optional[Iterable[str]] = None,
    ) -> Dict[str, str]:
        """Compute cryptographic digests for raw byte array."""
        target_algs = cls._resolve_algorithms(algorithms)
        hashers = cls._create_hashers(target_algs)
        for h in hashers.values():
            h.update(data)
        return {alg: h.hexdigest() for alg, h in hashers.items()}

    @classmethod
    def hash_text(
        cls,
        text: str,
        encoding: str = "utf-8",
        algorithms: Optional[Iterable[str]] = None,
    ) -> Dict[str, str]:
        """Compute cryptographic digests for string with specified encoding."""
        encoded = text.encode(encoding)
        return cls.hash_bytes(encoded, algorithms=algorithms)

    @classmethod
    def hash_stream(
        cls,
        stream: BinaryIO,
        chunk_size: int = 1048576,  # 1 MiB
        algorithms: Optional[Iterable[str]] = None,
    ) -> Tuple[Dict[str, str], int]:
        """
        Stream a binary stream through hashing algorithms in fixed chunk sizes.
        Returns a tuple of (digests_dict, total_bytes_read).
        Does NOT load the entire stream into memory.
        """
        if chunk_size <= 0:
            raise ValueError(f"chunk_size must be positive, got {chunk_size}")

        target_algs = cls._resolve_algorithms(algorithms)
        hashers = cls._create_hashers(target_algs)
        total_bytes = 0

        while True:
            chunk = stream.read(chunk_size)
            if not chunk:
                break
            total_bytes += len(chunk)
            for h in hashers.values():
                h.update(chunk)

        return {alg: h.hexdigest() for alg, h in hashers.items()}, total_bytes

    @classmethod
    def hash_file(
        cls,
        file_path: Path | str,
        chunk_size: int = 1048576,
        algorithms: Optional[Iterable[str]] = None,
    ) -> Tuple[Dict[str, str], int]:
        """
        Hash file on disk using streaming reads to prevent unbounded memory usage.
        Returns a tuple of (digests_dict, file_size_in_bytes).
        """
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(path, "rb") as f:
            return cls.hash_stream(f, chunk_size=chunk_size, algorithms=algorithms)

    @staticmethod
    def verify_digest(computed_hash: str, expected_hash: str) -> bool:
        """
        Timing-attack-resistant constant-time digest comparison using hmac.compare_digest.
        """
        return hmac.compare_digest(computed_hash.lower().strip(), expected_hash.lower().strip())

    @staticmethod
    def calculate_avalanche(digest_a_hex: str, digest_b_hex: str) -> Dict[str, float | int]:
        """
        Calculates bitwise difference between two digests of the same algorithm
        to demonstrate cryptographic avalanche effect (should hover near ~50% bit flip).
        """
        if len(digest_a_hex) != len(digest_b_hex):
            raise ValueError("Digests must be of identical length to compute avalanche metrics.")

        bytes_a = bytes.fromhex(digest_a_hex)
        bytes_b = bytes.fromhex(digest_b_hex)

        total_bits = len(bytes_a) * 8
        flipped_bits = 0

        for b1, b2 in zip(bytes_a, bytes_b):
            xor_val = b1 ^ b2
            flipped_bits += bin(xor_val).count("1")

        flip_percentage = round((flipped_bits / total_bits) * 100, 2)
        return {
            "total_bits": total_bits,
            "flipped_bits": flipped_bits,
            "identical_bits": total_bits - flipped_bits,
            "flip_percentage": flip_percentage,
        }
