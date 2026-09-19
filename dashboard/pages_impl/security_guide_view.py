"""
HashLens Dashboard - Security Education & Cryptographic Guide
Comprehensive cybersecurity educational module detailing hashing mechanics,
collision resistance, algorithm limitations, and password storage distinctions.
"""

import streamlit as st


def render():
    st.markdown('<div class="soc-header">CRYPTOGRAPHIC FORENSICS & SECURITY GUIDE</div>', unsafe_allow_html=True)

    st.markdown(
        """
        Cryptographic hash functions form the bedrock of digital forensics, malware analysis,
        code signing, and data integrity verification. Understanding their mathematical guarantees
        and limitations is critical for secure software engineering and incident response.
        """
    )

    # 1. Fundamental Properties
    st.subheader("1. Core Properties of Cryptographic Hash Functions")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown(
            """
            <div class="soc-card">
                <strong style="color: #00f0ff;">1. Preimage Resistance (One-Way)</strong>
                <p style="font-size: 13px; color: #cbd5e1; margin-top: 6px;">
                    Given a digest <code>h</code>, it is computationally infeasible to find any message <code>m</code>
                    such that <code>hash(m) = h</code>. Hashes cannot be mathematically "reversed" or decrypted.
                </p>
            </div>
            <div class="soc-card">
                <strong style="color: #00f0ff;">2. Second Preimage Resistance (Weak Collision)</strong>
                <p style="font-size: 13px; color: #cbd5e1; margin-top: 6px;">
                    Given a specific input <code>m₁</code>, it is computationally infeasible to find a different input
                    <code>m₂ ≠ m₁</code> such that <code>hash(m₁) = hash(m₂)</code>. This protects against modifying an existing document.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c2:
        st.markdown(
            """
            <div class="soc-card">
                <strong style="color: #00f0ff;">3. Collision Resistance (Strong Collision)</strong>
                <p style="font-size: 13px; color: #cbd5e1; margin-top: 6px;">
                    It is computationally infeasible to find <em>any two arbitrary distinct inputs</em> <code>m₁ ≠ m₂</code>
                    such that <code>hash(m₁) = hash(m₂)</code>. Birthday paradox reduces theoretical complexity to 2^(n/2).
                </p>
            </div>
            <div class="soc-card">
                <strong style="color: #00f0ff;">4. Avalanche Effect</strong>
                <p style="font-size: 13px; color: #cbd5e1; margin-top: 6px;">
                    Flipping a single bit in the input message cascades through internal compression rounds,
                    causing approximately 50% of the output digest bits to invert unpredictably.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("---")

    # 2. Algorithm Deep Dives
    st.subheader("2. Comparative Algorithm Analysis")

    t_md5, t_sha1, t_sha256, t_sha512 = st.tabs(["MD5", "SHA-1", "SHA-256", "SHA-512"])

    with t_md5:
        st.markdown(
            """
            ### MD5 (Message Digest 5)
            * **Digest Length:** 128 bits (32 hexadecimal characters)
            * **Designer:** Ronald Rivest (1992, RFC 1321)
            * **Status:** <span class="badge-tag badge-red">CRYPTOGRAPHICALLY BROKEN</span>
            
            **Forensic Context:**
            In 2004, Professor Xiaoyun Wang demonstrated practical collision attacks against MD5.
            By 2008, researchers generated rogue SSL Certificate Authority certificates using MD5 collisions.
            The Flame cyber-espionage malware famously weaponized MD5 collisions against Microsoft Windows Update.
            
            > **Accurate Understanding:** MD5 is broken due to **collision attacks** (finding two documents that produce
            the same hash), NOT because it is "reversible". MD5 remains suitable ONLY for non-cryptographic checksums
            or verifying historical records.
            """,
            unsafe_allow_html=True,
        )

    with t_sha1:
        st.markdown(
            """
            ### SHA-1 (Secure Hash Algorithm 1)
            * **Digest Length:** 160 bits (40 hexadecimal characters)
            * **Designer:** National Security Agency / NIST (1995, FIPS 180-1)
            * **Status:** <span class="badge-tag badge-red">CRYPTOGRAPHICALLY BROKEN</span>
            
            **Forensic Context:**
            In 2017, CWI Amsterdam and Google announced **SHAttered**, producing the first practical collision between
            two distinct PDF documents. In 2020, chosen-prefix collision attacks became economically viable (< $45,000).
            NIST formally announced the complete deprecation of SHA-1 by December 31, 2030.
            """,
            unsafe_allow_html=True,
        )

    with t_sha256:
        st.markdown(
            """
            ### SHA-256 (SHA-2 Family)
            * **Digest Length:** 256 bits (64 hexadecimal characters)
            * **Designer:** National Security Agency / NIST (2001, FIPS 180-2)
            * **Status:** <span class="badge-tag badge-green">SECURE STANDARD</span>
            
            **Forensic Context:**
            SHA-256 uses 64 rounds of non-linear logical operations on eight 32-bit working variables.
            It is the global industry standard for TLS/SSL certificates, Bitcoin proof-of-work, Docker container image IDs,
            and file integrity verification. No collision or practical preimage attacks are known.
            """,
            unsafe_allow_html=True,
        )

    with t_sha512:
        st.markdown(
            """
            ### SHA-512 (SHA-2 Family)
            * **Digest Length:** 512 bits (128 hexadecimal characters)
            * **Designer:** National Security Agency / NIST (2001, FIPS 180-2)
            * **Status:** <span class="badge-tag badge-green">HIGH-SECURITY STANDARD</span>
            
            **Forensic Context:**
            Engineered natively for 64-bit microprocessor architectures with 80 compression rounds on 64-bit words.
            On modern 64-bit CPUs, SHA-512 is frequently faster than SHA-256 while providing double the digest space (2^512),
            offering substantial resilience against hypothetical future cryptanalytic breakthroughs.
            """,
            unsafe_allow_html=True,
        )

    st.markdown("---")

    # 3. Critical Password Storage Distinction
    st.subheader("3. Critical Security Notice: Cryptographic Hashing vs Password Storage")

    st.error(
        """
        🛑 **CRITICAL RULE:** Raw cryptographic hash functions (MD5, SHA-1, SHA-256, SHA-512) 
        must **NEVER** be used for password storage!
        """
    )

    st.markdown(
        """
        **Why?**
        General-purpose cryptographic hash functions are deliberately designed to be **fast and computationally efficient**
        (processing gigabytes per second). Modern consumer GPUs can calculate **billions of SHA-256 digests per second**,
        enabling attackers to crack unsalted or fast-hashed passwords in minutes via dictionary attacks and rainbow tables.
        
        **The Correct Solution: Dedicated Key Derivation Functions (KDFs)**
        Password storage requires **intentionally slow**, **adaptive**, and **memory-hard** algorithms:
        
        * **Argon2id:** Winner of the Password Hashing Competition (PHC, 2015). Resistant to GPU/ASIC attacks via memory-hard matrix transformations.
        * **bcrypt:** Based on the Blowfish cipher with configurable cost factor (work factor). Highly battle-tested since 1999.
        * **scrypt:** Specifically designed to demand large amounts of RAM to neutralize hardware brute-force circuits.
        * **PBKDF2:** HMAC-based iteration scheme (recommend minimum 600,000 iterations for PBKDF2-HMAC-SHA256).
        """
    )

    st.markdown("---")

    # 4. Tamper-Evident Hash Chains
    st.subheader("4. Architecture of Tamper-Evident Hash Chains")
    st.markdown(
        """
        In digital forensics, establishing an immutable chain of custody is essential.
        HashLens implements a sequential audit chain where each record $R_n$ is cryptographically bound to its predecessor:
        
        $$H_n = \\text{SHA-256}(\\text{CanonicalPayload}(R_n) \\parallel H_{n-1})$$
        
        * **Tamper Detection:** If an adversary modifies record 2 in the database, its recalculated hash will diverge from $H_2$.
        * **Cascade Fault:** Even if the attacker updates $H_2$, record 3 references the old $H_2$ in its `previous_record_hash`, breaking the chain at record 3!
        * **Localization:** Verification inspects the entire chain in $O(N)$ linear time and pinpoints the exact sequence number and record ID where the tampering occurred.
        """
    )
