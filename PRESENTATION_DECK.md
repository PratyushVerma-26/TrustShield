# TrustShield: Unified Multi-Modal Cyber-Defense Platform
## Technical Architecture, Experimental Benchmarks & Evaluation Deck

---

## Slide 1: Title & Executive Summary
- **Project Title:** TrustShield: A Unified Digital Safety Platform for Multi-Threat Detection
- **Academic Context:** Capstone Project-I / BCSE497J (School of Computer Science and Engineering)
- **Domain:** Multi-Modal Cyber-Threat Intelligence, Explainable AI, Cryptographic Auditing
- **Core Mission:** Unify fragmented cybersecurity tools into an integrated, zero-false-safe microservice mesh spanning web phishing, credential breaches, deepfake media, and viral misinformation.

---

## Slide 2: Problem Statement & Industry Motivation
- **Tool Fragmentation:** Contemporary users navigate disconnected tools (phishing scanners, password checkers, fact-checking portals, deepfake upload forms).
- **Multi-Vector Attacks:** Modern threat actors combine vectors (e.g., synthetic voice audio paired with brand-spoofing phishing domains and fabricated news headlines).
- **The "False Safe" Danger:** When media lacks forensic traces due to lossy recompression or unindexed claims, traditional tools report "Safe" ($0\%$ threat), creating dangerous false security.
- **Training-Serving Skew:** Python ML pipelines often diverge from production runtime implementations, causing silent classification degradation.

---

## Slide 3: Unified Platform Architecture
```
                                 [ End-User Channels ]
                     +---------------------+---------------------+
                     |                     |                     |
               Web Console             Mobile App            Chat Bot
             (React 18 / Vite)       (Expo / React)      (Telegram/WhatsApp)
                     |                     |                     |
                     +---------------------+---------------------+
                                           |
                                  [ Port 8080 : Gateway ]
                      (Token Bucket Rate Limiter, Security Headers,
                           Structured 503 Degraded Fallback)
                                           |
    +---------------+---------------+------+--------+---------------+---------------+
    | :8083         | :8084         | :8085         | :8086         | :8087         | :8088
Phishing Shield  Breach Monitor  Deepfake Detect  Misinformation  Integrity Ledger  Fusion Engine
(18 Lexical Ftrs) ($k$-Anonymity) (ELA/DQT/Audio) (SimHash/Chyron) (SHA-256 Chain) (Rule Engine)
```

- **Single Origin Gateway (:8080):** Reverse proxies all traffic; eliminates cross-origin complexity.
- **Microservice Isolation:** Each threat vector runs in an independent, independently deployable Spring Boot container.
- **Cross-Modal Fusion:** Central engine normalizes heterogeneous module verdicts into composite risk ratings ($0–100$).

---

## Slide 4: Threat Vector 1 – Phishing & Malicious URL Shield
- **18 Lexical & Structural Features:** URL length, Shannon entropy, dot count, hyphens, digits, TLD risk, punycode, IP address in host, path depth, query tokens, and suspicious keywords.
- **Zero Training-Serving Drift:** Verified by `UrlFeatureExtractorParityTest` with mathematical parity ($\max |x_{\text{Java}} - x_{\text{Python}}| < 10^{-6}$).
- **In-Memory Decision Heuristics:** Sub-millisecond CPU inference without external network bottlenecks.

---

## Slide 5: Threat Vector 2 – Privacy-Preserving Breach Monitor
- **$k$-Anonymity Model:** Clients hash passwords with SHA-1, sending only the first 5 hexadecimal characters (`prefix`). The service queries HIBP and compares the remaining 35 characters locally.
- **Zero Password Exposure:** Plaintext credentials and full hashes are never transmitted or logged.
- **Offline Common Password Catalog:** 138 high-frequency breached password hashes loaded in memory for zero-latency instant offline matching.
- **zxcvbn Entropy Scoring:** Evaluates password complexity, character diversity, and structural patterns.

---

## Slide 6: Threat Vectors 3, 4 & 5 – Synthetic Media Forensics
- **Image Deepfake Forensics:**
  - *Error Level Analysis (ELA):* Detects differential compression artifacts across image blocks.
  - *Discrete Quantization Table (DQT):* Identifies non-standard JPEG luminance/chrominance tables.
  - *Spatial Blockiness & Noise Residual:* Measures $8\times 8$ grid periodicity and high-frequency noise variance.
  - *Provenance Metadata:* Parses EXIF camera metadata and verifies C2PA cryptographic manifests.
- **Video Temporal Forensics:**
  - *Container Analysis:* Parses MP4 box atoms (`ftyp`, `moov`, `mdat`) for streaming compatibility.
  - *Temporal Jitter:* Inspects inter-frame presentation timestamps and frame cadence.
- **Audio Synthetic Forensics:**
  - *Spectral Centroid:* Analyzes spectral energy distribution across speech frequencies.
  - *High-Frequency Roll-Off:* Detects steep synthetic cutoffs ($> 7.5\text{ kHz}$) characteristic of vocoders.

---

## Slide 7: Threat Vector 6 – Multimodal Misinformation & Fact Verification
- **Television Chyron Typography Forensics:**
  - Detects lower-third broadcast layouts and identifies spliced font step discontinuities and geometric inconsistencies.
- **64-bit SimHash Near-Duplicate Matching:**
  - Evaluates Hamming distance against bundled debunked hoax catalog with $O(1)$ lookup time.
- **Multi-Source Internet Directories:**
  - Queries Google Fact Check Tools API and internet fact-checking registries for real-time corroboration.

---

## Slide 8: Cryptographic Ledger & Audit Trail
- **Append-Only SHA-256 Hash Chain:**
  $$\text{chainHash}_i = \text{SHA-256}(\text{previousChainHash}_{i-1} \parallel \text{entryHash}_i)$$
- **Ed25519 Asymmetric Digital Signatures:**
  - The head chain hash is signed with a private Ed25519 key; public key is exposed for independent client verification.
- **Tamper Evidence:**
  - Any mutation to stored database records breaks subsequent links.
  - `/api/v1/ledger/verify` immediately pinpoints `firstCorruptedIndex` and designates subsequent blocks as unverifiable.

---

## Slide 9: Empirical Benchmarks & Hardware Performance
- **Phishing Model Benchmark (10,000 URLs - 5-Fold Cross Validation):**
  - **Accuracy:** $96.42\% \pm 0.13\%$
  - **Precision:** $96.81\% \pm 0.15\%$
  - **Recall:** $95.99\% \pm 0.14\%$
  - **$F_1$-Score:** $96.37\% \pm 0.14\%$
  - **ROC-AUC:** $0.9912 \pm 0.0005$
- **Production CPU Inference Latency (5,000 Scans, Commodity Hardware):**
  - **$p_{50}$ (Median):** **0.155 ms** (SLA target $< 10.0\text{ ms}$)
  - **$p_{90}$:** **0.312 ms**
  - **$p_{95}$:** **0.408 ms**
  - **$p_{99}$:** **0.538 ms**
  - **Peak Throughput:** $> 4,500\text{ requests/sec}$

---

## Slide 10: Fault Tolerance & Automated Failure Drills
TrustShield enforces strict resilience invariants verified via `scripts/test_failure_drills.ps1`:

| Failure Drill | Trigger Condition | System Behavior | Safety Invariant |
| :--- | :--- | :--- | :--- |
| **Drill 1: Service Outage** | Downstream service down/unreachable | Structured HTTP 503 with `degraded: true` | Prevents cascading 500 error crashes |
| **Drill 2: Ledger Tampering** | Modified database row payload | Flags exact `firstCorruptedIndex` | Subsequent entries marked unverifiable |
| **Drill 3: Lossy Recompression** | Social media compressed JPEG | Returns `ThreatLevel.UNKNOWN` (score 0) | **Zero False-Safe:** degraded $\ne$ safe |
| **Drill 4: Fact-Check Fallback** | Unindexed claim, API unreachable | Returns `ThreatLevel.UNKNOWN` (score 0) | Absence of proof is not proof of safety |

---

## Slide 11: Standalone Client Ecosystem
- **Operations Web Console (`:5173`):**
  - Built with React 18 and TypeScript; provides real-time scanner consoles, composite radar breakdown, and live cryptographic ledger auditing.
- **Conversational Bot (`:8089`):**
  - Standalone service routing user intents from Web Chat (`:8080/chat.html`), WhatsApp webhooks, and Telegram bots with Markdown threat badges.
- **Mobile Application (`:8081`):**
  - Standalone Expo / React Native client providing native mobile threat verification and incident lookup.

---

## Slide 12: Live Demonstration Roadmap
1. **Startup:** Single-command execution via `.\scripts\run-all.ps1 -Build`.
2. **Mesh Health:** Verification of all 8 ports via `.\scripts\run-all.ps1 -Status`.
3. **Phishing Scan:** High-risk homograph domain test vs. benign domain.
4. **Breach Monitor:** $k$-anonymity verification of breached password vs. high-entropy passphrase.
5. **Media Forensics:** ELA, DQT quantization, and temporal optical flow validation.
6. **Viral Hoax Verification:** SimHash matching of known disinformation.
7. **Cross-Modal Fusion:** Composite risk aggregation and ledger commit.
8. **Tamper Audit:** Ledger cryptographic verification link-by-link.
9. **Resilience Drills:** Execution of `scripts/test_failure_drills.ps1`.

---

## Slide 13: Summary of Technical Contributions
1. **Unified Multi-Threat Defense:** Integrated 7 distinct detection mechanisms under a cohesive microservice architecture.
2. **Zero-Drift Feature Engineering:** Guaranteed identical numerical behavior between ML training and JVM production serving.
3. **Sub-Millisecond Classification:** $p_{50} = 0.155\text{ ms}$ CPU latency enables transparent gateway integration.
4. **Verifiable Audit Integrity:** Ed25519-signed SHA-256 hash chains guarantee tamper evidence.
5. **Architectural Safety Invariants:** Strict rejection of false safe classifications under lossy or unindexed inputs.
