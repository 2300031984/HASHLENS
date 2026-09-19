"""
Tests for HashLens Core Hashing Engine.
Verifies deterministic cryptographic digests against RFC and NIST standard test vectors,
streaming I/O correctness, chunk boundary handling, and avalanche effect measurements.
"""

import io
import pytest
from backend.app.services.hashing_engine import (
    HashingEngine,
    HashAlgorithm,
    SUPPORTED_ALGORITHMS,
    ALGORITHM_METADATA,
)


KNOWN_TEST_VECTORS = [
    {
        "input": "",
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
        "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "sha512": (
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        ),
    },
    {
        "input": "hello",
        "md5": "5d41402abc4b2a76b9719d911017c592",
        "sha1": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
        "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        "sha512": (
            "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca7"
            "2323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"
        ),
    },
    {
        "input": "Hello World",
        "md5": "b10a8db164e0754105b7a99be72e3fe5",
        "sha1": "0a4d55a8d778e5022fab701977c5d840bbc486d0",
        "sha256": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
        "sha512": (
            "2c74fd17edafd80e8447b0d46741ee243b7eb74dd2149a0ab1b9246fb30382f2"
            "7e853d8585719e0e67cbda0daa8f51671064615d645ae27acb15bfb1447f459b"
        ),
    },
]


def test_known_test_vectors():
    """Verify standard RFC / NIST test vectors for all 4 algorithms."""
    for vector in KNOWN_TEST_VECTORS:
        results = HashingEngine.hash_text(vector["input"])
        assert results["md5"] == vector["md5"]
        assert results["sha1"] == vector["sha1"]
        assert results["sha256"] == vector["sha256"]
        assert results["sha512"] == vector["sha512"]


def test_unicode_hashing():
    """Ensure multi-byte UTF-8 sequences hash deterministically."""
    unicode_text = "HashLens 🛡️ 🔐 安全 / Безопасность / Sécurité"
    res1 = HashingEngine.hash_text(unicode_text)
    res2 = HashingEngine.hash_bytes(unicode_text.encode("utf-8"))
    assert res1 == res2
    assert len(res1["sha256"]) == 64
    assert len(res1["sha512"]) == 128


def test_streaming_matches_direct_bytes():
    """Verify that streaming chunk by chunk produces identical digest to whole bytes."""
    test_data = b"Streaming data payload: " + (b"A" * 50000) + (b"B" * 50000)
    direct_digests = HashingEngine.hash_bytes(test_data)

    # Stream with small chunk size to force multiple iterations across boundaries
    stream = io.BytesIO(test_data)
    stream_digests, total_bytes = HashingEngine.hash_stream(stream, chunk_size=1024)

    assert total_bytes == len(test_data)
    assert stream_digests == direct_digests


def test_algorithm_subset_filtering():
    """Check that requesting a subset of algorithms computes only those."""
    res = HashingEngine.hash_text("test", algorithms=["sha256", "md5"])
    assert set(res.keys()) == {"sha256", "md5"}
    assert "sha1" not in res
    assert "sha512" not in res


def test_unsupported_algorithm_raises():
    """Ensure requesting an invalid algorithm raises a clear ValueError."""
    with pytest.raises(ValueError, match="Unsupported algorithm"):
        HashingEngine.hash_text("test", algorithms=["sha256", "invalid_algorithm"])


def test_constant_time_verification():
    """Verify timing-safe verification method."""
    correct_hash = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    tampered_hash = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9825"
    assert HashingEngine.verify_digest(correct_hash, correct_hash.upper()) is True
    assert HashingEngine.verify_digest(correct_hash, tampered_hash) is False


def test_avalanche_effect():
    """Test that a 1-character difference flips approximately ~50% of the bits."""
    hash1 = HashingEngine.hash_text("The quick brown fox jumps over the lazy dog")["sha256"]
    hash2 = HashingEngine.hash_text("The quick brown fox jumps over the lazy cog")["sha256"]

    avalanche = HashingEngine.calculate_avalanche(hash1, hash2)
    assert avalanche["total_bits"] == 256
    # Avalanche effect typically flips between 40% and 60% of bits
    assert 35.0 <= avalanche["flip_percentage"] <= 65.0
    assert avalanche["flipped_bits"] + avalanche["identical_bits"] == 256


def test_algorithm_metadata_completeness():
    """Ensure all supported algorithms have rich security metadata."""
    for alg in SUPPORTED_ALGORITHMS:
        assert alg in ALGORITHM_METADATA
        meta = ALGORITHM_METADATA[alg]
        assert "name" in meta
        assert "digest_bits" in meta
        assert "security_status" in meta
        assert "recommended_for_passwords" in meta
        # Explicit requirement: raw cryptographic hashes must not be recommended for passwords
        assert meta["recommended_for_passwords"] is False
        assert "password_alternative" in meta
