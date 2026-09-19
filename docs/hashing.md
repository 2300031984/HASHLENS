# Cryptographic Hashing: Theory, Mathematics, and Forensic Standards

This document covers the mathematics, historical developments, known vulnerabilities, and standard test vectors for the cryptographic hash functions implemented in HashLens.

---

## 1. What is a Cryptographic Hash Function?

A cryptographic hash function is a deterministic mathematical algorithm that maps an arbitrary-length binary message $M \in \{0, 1\}^*$ to a fixed-length bit string digest $H \in \{0, 1\}^n$:

$$h = H(M)$$

### Essential Security Criteria:
1. **Determinism:** The same input message $M$ always generates the exact identical digest $h$.
2. **Efficiency:** Computing $H(M)$ is computationally fast and linear in the size of the message ($O(|M|)$).
3. **Preimage Resistance (One-Way):** Given digest $h$, finding any message $M$ such that $H(M) = h$ requires $2^n$ operations.
4. **Second Preimage Resistance:** Given message $M_1$, finding another message $M_2 \neq M_1$ such that $H(M_1) = H(M_2)$ requires $2^n$ operations.
5. **Collision Resistance:** Finding *any* two arbitrary messages $M_1 \neq M_2$ such that $H(M_1) = H(M_2)$ requires $2^{n/2}$ operations (due to the Birthday Paradox).
6. **Avalanche Effect:** A 1-bit mutation in $M$ should invert roughly 50% of the bits in $h$.

---

## 2. Supported Algorithms & Security Profiles

### 2.1 MD5 (Message Digest 5)
* **Digest Size:** 128 bits (16 bytes)
* **Block Size:** 512 bits (64 bytes)
* **Internal Structure:** Merkle–Damgård construction with 64 operations grouped into 4 rounds.
* **Vulnerability:** **Collision Resistance Completely Broken.** In 2004, Wang et al. demonstrated practical collisions in under an hour. In 2008, researchers forged rogue SSL certificates using MD5. In 2012, the Flame cyber-espionage worm exploited an MD5 collision to forge Microsoft digital signatures.
* **HashLens Policy:** Supported solely for backward-compatibility checksums and legacy baseline cross-referencing. Never recommended for security-sensitive integrity verification.

### 2.2 SHA-1 (Secure Hash Algorithm 1)
* **Digest Size:** 160 bits (20 bytes)
* **Block Size:** 512 bits (64 bytes)
* **Internal Structure:** Merkle–Damgård construction with 80 rounds of logical functions.
* **Vulnerability:** **Collision Resistance Broken.** In 2017, Google and CWI Amsterdam released **SHAttered**, generating two distinct PDF files producing the identical SHA-1 hash. In 2020, chosen-prefix collision attacks dropped below $45,000 in GPU compute cost.
* **HashLens Policy:** Classified as cryptographically compromised. NIST mandates complete migration to SHA-2/SHA-3 by 2030.

### 2.3 SHA-256 (SHA-2 Family)
* **Digest Size:** 256 bits (32 bytes)
* **Block Size:** 512 bits (64 bytes)
* **Internal Structure:** Merkle–Damgård construction with 64 compression rounds using six non-linear logical functions ($\Sigma_0, \Sigma_1, \sigma_0, \sigma_1, \text{Ch}, \text{Maj}$).
* **Security Margin:** Preimage resistance: $2^{256}$, Collision resistance: $2^{128}$. No known practical or theoretical attacks weaken its core security.
* **HashLens Policy:** The primary enterprise standard for file integrity, chunk block mapping, and tamper-evident audit chaining.

### 2.4 SHA-512 (SHA-2 Family)
* **Digest Size:** 512 bits (64 bytes)
* **Block Size:** 1024 bits (128 bytes)
* **Internal Structure:** Merkle–Damgård construction operating natively on 64-bit words with 80 compression rounds.
* **Security Margin:** Preimage resistance: $2^{512}$, Collision resistance: $2^{256}$.
* **HashLens Policy:** High-security tier. Optimized for 64-bit architectures, delivering exceptional throughput on modern CPUs.

---

## 3. Standard Test Vectors (RFC & NIST Verification)

All HashLens implementations are validated against authoritative test vectors:

### 3.1 Empty String (`""`)
* **MD5:** `d41d8cd98f00b204e9800998ecf8427e`
* **SHA-1:** `da39a3ee5e6b4b0d3255bfef95601890afd80709`
* **SHA-256:** `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
* **SHA-512:** `cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e`

### 3.2 `"hello"`
* **MD5:** `5d41402abc4b2a76b9719d911017c592`
* **SHA-1:** `aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d`
* **SHA-256:** `2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824`
* **SHA-512:** `9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043`

### 3.3 `"Hello World"`
* **MD5:** `b10a8db164e0754105b7a99be72e3fe5`
* **SHA-1:** `0a4d55a8d778e5022fab701977c5d840bbc486d0`
* **SHA-256:** `a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e`
* **SHA-512:** `2c74fd17edafd80e8447b0d46741ee243b7eb74dd2149a0ab1b9246fb30382f27e853d8585719e0e67cbda0daa8f51671064615d645ae27acb15bfb1447f459b`
