# TrustShield

An AI-powered system for real-time threat detection and protection against
deepfakes, phishing, data breaches, and online misinformation.

Java 21 · Spring Boot 3.3.2 · Maven multi-module monorepo

---

## Project Status and Architecture Overview

TrustShield provides real-time threat detection across seven specialized services and shared presentation/client packages:

| Module | Status | What actually works |
|---|---|---|
| `trustshield-common` | **Working** | Shared verdict/signal types, IncidentId correlation, and contracts for all modules |
| `trustshield-gateway` | **Working** | Reverse proxy on port 8080, unified CORS, downstream routing, structured 503 degradation |
| `trustshield-phishing-service` | **Working** | 26-feature lexical classifier, dynamic Safe Browsing & VirusTotal reputation enrichment, raise-only invariant, REST API, scan history, explainability, tests |
| `trustshield-breach-service` | **Working** | Password exposure via HIBP k-anonymity + offline catalog, email breach lookup, structural password analysis, audit trail, tests |
| `trustshield-deepfake-service` | **Working** | Multimodal image and video forensics: Pure Java ISO BMFF container parser, video temporal jitter & inter-frame residual divergence analysis, multi-language acoustic biophysics forensics (HiFi-GAN/WaveGlow spectral roll-off, robotic pitch micro-tremor, digital silence dynamics), C2PA trust registry & internet directory connectivity, 6 image forensic signals, UNKNOWN degradation invariant, H2 persistence, 30 tests |
| `trustshield-fakenews-service` | **Working** | Multimodal claim verification (text, image news, video news): IPTC/EXIF & video atom metadata headline extraction, TV news chyron & banner splice tampering analysis, 35-domain publisher credibility directory (Mainstream, Satire, Propaganda), multi-source ClaimReview internet directory with 12 verified debunks, Google Fact Check API, offline 64-bit SimHash, capped linguistic style (max 55), multipart file upload, 43 tests |
| `trustshield-integrity-service` | **Working** | Cryptographic append-only SHA-256 hash chain, Ed25519 digital signatures, firstCorruptedIndex diagnosis, REST API on port 8087, H2 persistence, tests |
| `trustshield-fusion-service` | **Working** | Cross-modal threat aggregator, canonical auditable rules R1 (Conclusive Dangerous), R2 (Multi-Modal Suspicious Escalation), R3 (Coverage Invariant), R4 (Cryptographic Ledger Override), R5 (Cross-Modal Coordination Multiplier), H2 persistence, REST API on port 8088, 23 tests |
| `trustshield-bot-service` | **Working** | Conversational cyber-defense bot gateway (Port 8089) for WhatsApp, Telegram, and standalone Web Chat (/chat), automatic intent classification, mobile markdown threat badges, resilient microservice router with offline fallbacks, H2 persistence, mockable webhooks with `hub.challenge` handshake, 25 tests |
| `packages/verdict-core` | **Working** | Shared TypeScript library enforcing presentation invariants at compile time via discriminated unions; typed `TrustShieldApiClient` for all 7 backend vectors; Vitest test suite |
| `packages/web-console` | **Working** | Modern React 18 + Vite cyber-defense operations console with 6 dedicated forensic vector panels, threat HUD, standalone analyst cockpit (no embedded simulators), embedded into Gateway static distribution (:8080) |
| `packages/mobile-app` | **Working** | Standalone Expo / React Native mobile app with on-device threat evaluation, edge rule engine, EAS build profile for standalone Android APK generation and App Store distribution |

**The bundled phishing model is trained and verified.** `phishing_model.json`
has been trained on a balanced 10,000-URL dataset (`data/urls.csv`) with 5-fold
cross-validation. Its `provenance` field reports `TRAINED`, `trainedOn` is
timestamped, and `/api/v1/phishing/model` reports `trained: true`.

In addition, `UrlFeatureExtractorParityTest` runs against `parity_fixtures.json`
with 0 skips, mathematically confirming zero training/serving skew between the
Python training extractor and the Java serving engine. Inference latency has
been measured over 1,000 iterations post-JIT warmup at **p50 = 0.155 ms** and
**p99 = 0.538 ms** on standard CPU.

### Blockchain has been removed

The original design used a blockchain for tamper-evident logging. That is
replaced by `trustshield-integrity-service`: an append-only ledger where each
entry stores `SHA-256(previous_hash || current_entry_hash)`. It gives the same
property that mattered — any retroactive edit invalidates every subsequent hash
and is detectable — without consensus, gas, or the tens-of-seconds write latency
that would have contradicted the project's "real-time" claim.

---

## Prerequisites

- JDK 21
- Maven 3.9+
- Docker (optional — only for the PostgreSQL profile)

Verify:

```bash
java -version     # must report 21
mvn -version
```

---

## Build

From the repository root:

```bash
mvn clean install
```

Expected on success: `BUILD SUCCESS` with 196 passing tests across nine
active artifacts — `trustshield-common`, `trustshield-phishing-service`,
`trustshield-breach-service`, `trustshield-gateway`,
`trustshield-deepfake-service`, `trustshield-fakenews-service`,
`trustshield-integrity-service`, `trustshield-fusion-service`, and
`trustshield-bot-service`.

A note on the module list: the parent POM only lists modules that physically
exist, because Maven fails with "Child module does not exist" before compiling
anything. Every commented-out entry in `pom.xml` is an accurate statement that the
directory is not there yet.

To skip tests while iterating:

```bash
mvn clean install -DskipTests
```

---

## Running the platform: Multi-service runner

Rather than opening separate terminal windows for each microservice, use `scripts/run-all.ps1`.
It builds fat jars once and manages services as detached background processes with per-service logs in `logs/`:

```powershell
# Build fat jars for all available modules
.\scripts\run-all.ps1 -Build

# Start all built microservices in the background with health checks
.\scripts\run-all.ps1

# Inspect port listening status and PIDs
.\scripts\run-all.ps1 -Status

# Stop all running TrustShield processes cleanly
.\scripts\run-all.ps1 -Stop
```

### Single Entrypoint: Unified API Gateway (Port 8080)

All client traffic (React web console, mobile app, and WhatsApp bot) routes through `trustshield-gateway`
on **port 8080**. It centralizes CORS and reverse-proxies to downstream services:

- `/api/v1/phishing/**` -> port 8083 (`trustshield-phishing-service`)
- `/api/v1/breach/**` -> port 8084 (`trustshield-breach-service`)
- `/api/v1/deepfake/**` -> port 8085 (`trustshield-deepfake-service`)
- `/api/v1/fakenews/**` / `/api/v1/misinformation/**` -> port 8086 (`trustshield-fakenews-service`)
- `/api/v1/integrity/**` / `/api/v1/ledger/**` -> port 8087 (`trustshield-integrity-service`)
- `/api/v1/fusion/**` -> port 8088 (`trustshield-fusion-service`)
- `/api/v1/bot/**` -> port 8089 (`trustshield-bot-service`)

If a downstream service has not been started, the gateway returns a structured HTTP 503 response:
`{"error":"SERVICE_UNAVAILABLE","message":"Target microservice is not reachable: http://localhost:...","degraded":true}`

---

## Run the phishing service

```bash
cd trustshield-phishing-service
mvn spring-boot:run
```

It starts on **port 8083** with an in-memory H2 database. No container, no
external service, no API key is required — this is deliberate, so a demo cannot
fail because a database was slow to start.

At startup you will see a multi-line warning that the model is untrained. That is
expected and correct until you train one.

### Endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/phishing/scan` | Assess a URL |
| GET | `/api/v1/phishing/history` | 25 most recent scans |
| GET | `/api/v1/phishing/stats` | Dashboard counters |
| GET | `/api/v1/phishing/model` | Model card, including whether it is trained |
| GET | `/actuator/health` | Liveness |
| GET | `/swagger-ui.html` | Interactive API docs |
| GET | `/h2-console` | Inspect the database (JDBC URL `jdbc:h2:mem:trustshield_phishing`) |

### Try it

A look-alike Indian banking domain on an abused TLD:

```bash
curl -s -X POST http://localhost:8083/api/v1/phishing/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"http://sbi-secure-login.verify-account.xyz/netbanking/update-kyc.php"}'
```

The real thing, for contrast:

```bash
curl -s -X POST http://localhost:8083/api/v1/phishing/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://retail.onlinesbi.sbi/personal"}'
```

On Windows PowerShell, `curl` is an alias for `Invoke-WebRequest` and will not
accept these flags. Use:

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8083/api/v1/phishing/scan `
  -ContentType 'application/json' `
  -Body '{"url":"http://sbi-secure-login.verify-account.xyz/netbanking/update-kyc.php"}'
```

The response carries the risk score, the threat level, the signals that produced
it, and the per-feature attribution. That last part matters for the report: for a
logistic regression the contribution of feature *i* is exactly `w_i · z_i`, so the
explanation is not a post-hoc approximation of the model's reasoning — it *is* the
model's reasoning.

---

## Run the breach service

```bash
mvn -pl trustshield-breach-service spring-boot:run
```

It starts on **port 8084**, so it can run at the same time as the phishing
service. Both external APIs are **disabled by default** and it still produces a
real `PASSWORD_EXPOSED` verdict offline, because a 138-entry catalog of the most
common passwords is bundled in the jar. No API key, no network, no container.

### Endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/breach/password` | Check a password against breach corpora |
| POST | `/api/v1/breach/email` | Check an email address (requires acknowledgement) |
| GET | `/api/v1/breach/history` | 25 most recent checks |
| GET | `/api/v1/breach/stats` | Counters, including how often the system degraded |
| GET | `/api/v1/breach/privacy` | What each endpoint does and does not disclose |

Both checks are `POST`, including the email one, which is conceptually a lookup.
A `GET` would put the secret in the URL, and URLs end up in access logs, browser
history, referrer headers and proxy caches.

### Try it

A password that is in the bundled catalog:

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8084/api/v1/breach/password `
  -ContentType 'application/json' -Body '{"password":"password123"}'
```

Expect `PASSWORD_EXPOSED`, `DANGEROUS`, risk score 90, and `bucketPrefix: CBFDA`
— the first 5 characters of the SHA-1, which is the only part that would ever be
transmitted.

Now a generated password, which demonstrates the more interesting behaviour:

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8084/api/v1/breach/password `
  -ContentType 'application/json' -Body '{"password":"Xq7#vLm2$pRt9wZk"}'
```

Expect `INCONCLUSIVE` with `degraded: true`, **not** a clean verdict. With the
range API disabled and the offline list too small for absence to indicate global safety,
no source could conclusively verify exposure, so the service marks the result as inconclusive.

### Privacy Guarantees and k-Anonymity Architecture

The Pwned Passwords **range** API implements k-anonymity: the client computes the SHA-1 of the password, sends
only the first 5 hex characters, and verifies the remaining 35 characters locally against the returned bucket. The external service learns
only one bucket out of 16^5 = 1,048,576 possibilities. `Add-Padding: true` is included to prevent response size leakage.

**Email Lookup Privacy Controls:**
The breached-account endpoint does not support a prefix-based range query; performing an email lookup transmits
the queried address to the HIBP service. To ensure transparent privacy guarantees:
- Distinct client classes isolate password checking from email checking.
- The `kAnonymous` flag is reported explicitly per endpoint (`true` for password, `false` for email).
- Email checks require explicit client consent (`acknowledged: true`).
- `GET /api/v1/breach/privacy` exposes the exact privacy profile of each endpoint.

Audit logs persist only a SHA-256 hash of the lower-cased address, ensuring **pseudonymisation** rather
than raw credential storage.

---

## Optional: enable external reputation sources

Both are off by default. The phishing service works fully offline without them.
When API keys are present in `.env` or system environment variables, the service dynamically enables them:

```bash
# In .env or system environment:
GOOGLE_SAFEBROWSING_KEY=...
VIRUSTOTAL_API_KEY=...
```

Note how these are used: they can only **raise** a risk score, never lower it.
Blocklists are high-precision and low-recall: a hit is near-certain evidence of
malice, but an absence of a hit tells you very little, because most phishing
domains live for hours and never reach a list. A system that subtracted points
for a clean lookup would actively reassure users about brand-new phishing sites —
which are exactly the ones the local classifier exists to catch.

---

## Run the deepfake forensics service

```bash
mvn -pl trustshield-deepfake-service spring-boot:run
```

Starts on **port 8085** (and reverse-proxied via gateway on port 8080 at `/api/v1/deepfake/**`) with an in-memory H2 database (`jdbc:h2:mem:trustshield_deepfake`).

The service evaluates images and videos using **inspectable, offline forensic signals and internet trust directories** without unearned neural network accuracy claims:

#### 1. Image Forensics (6 Primary Signals)
1. **Error Level Analysis (ELA)**: Re-encodes the image in memory at 90% JPEG quality via `ImageIO` and measures block-wise variance across 16×16 blocks. High variance reveals non-uniform compression history or localized splicing.
2. **JPEG Quantization Table (DQT) Fingerprinting**: Directly parses `0xFF 0xDB` marker segments from the raw byte stream, extracts 64-coefficient luminance/chrominance tables, computes a SHA-256 fingerprint, and identifies flat/all-ones synthetic tables or editing software signatures.
3. **Spatial 8×8 Blockiness Periodicity**: Evaluates spatial gradient step discontinuities across expected 8×8 block grid boundaries. *(Documented in Javadoc as a spatial proxy, not DCT-histogram detection).*
4. **High-Pass Noise Residual Variance**: Applies a 3×3 Laplacian filter to isolate sensor noise residuals. Flags unnatural hyper-smoothness (characteristic of generative AI diffusion models) or localized block variance divergence (splicing/inpainting).
5. **EXIF Provenance**: Uses Drew Noakes' `metadata-extractor 2.19.0` to parse camera make/model and software tags for manipulation signatures (e.g. Photoshop, GIMP, Stable Diffusion, Midjourney).
6. **C2PA Manifest Detection**: Inspects file headers for Content Authenticity Initiative / JUMBF manifest boxes (`c2pa`, `jumb`) in JPEG APP11 and chunk structures. *(Documented as presence detection only, not cryptographic signature validation).*

#### 2. Video Temporal & Container Forensics
- **Pure Java ISO BMFF Container Parser**: Parses `ftyp`, `moov`, `mvhd`, `trak`, and `udta` atoms without external FFmpeg or native C++ dependencies. Extracts track layouts, durations, timescales, and scans container metadata for AI generation or editing tags (`DeepFaceLab`, `FaceSwap`, `Synthesia`, `Runway`, `Adobe Premiere`, `FFmpeg`).
- **Keyframe Extraction & Temporal Consistency**: Samples video keyframes across playback duration and calculates inter-frame noise residual divergence and blockiness step changes. Detects unnatural face-swap boundary flickering and temporal incoherence across frame transitions.

#### 3. Multilingual Synthetic Audio Forensics
AI speech synthesis (TTS, RVC, voice cloning) violates universal physical acoustic biophysics across all spoken languages (English, Hindi, Spanish, French, etc.):
- **Neural Vocoder Spectral Roll-off**: Neural vocoders (HiFi-GAN, WaveGlow) synthesize speech up to a strict mel-spectrogram cutoff (e.g. 8kHz or 16kHz) and lack natural ultra-high frequency organic reverberation.
- **Robotic Pitch Micro-Tremor (Vocal Jitter)**: Human vocal tract phonation exhibits organic cycle-to-cycle micro-irregularities; synthetic voices exhibit robotic pitch stability or unnaturally smoothed prosodic contours.
- **Digital Silence & Pause Dynamics**: Real speech contains natural room tone (-45 dB to -60 dB) and micro-respiration sounds during speech pauses; synthetic speech displays bit-exact digital zeros (< -90 dB).

#### 4. Internet Media Directories & C2PA Trust Registries
- Connects to C2PA credential registries and an offline curated catalog of known viral deepfakes (Pentagon explosion hoax, Pope puffer coat, Biden robocall hoax).
- Follows the raise-only invariant: directory matches raise risk scores to 90+ (`DANGEROUS`), while unlisted media gracefully falls back to local forensic signals.

### The Core Failure Invariant: Recompressed Media & UNKNOWN

A recompressed image (e.g. photos sent as WhatsApp photos, social media downscaling, or low-resolution thumbnails) has had its fine forensic traces destroyed.

Rather than falsely reporting the image as clean or safe, the service enforces the system-wide rule — **"an unknown result is not a safe result"**:
- `threatLevel = ThreatLevel.UNKNOWN`
- `riskScore = 0` (indicating nothing could be measured, not that nothing was found)
- `degraded = true`
- `verdict = "IMAGE_RECOMPRESSED"`
- Explanation advises inspecting the original uncompressed document file.

### Endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/deepfake/scan` | Forensic scan of Base64-encoded image |
| POST | `/api/v1/deepfake/scan/file` | Multipart file upload scan |
| GET | `/api/v1/deepfake/history` | 25 most recent scans |
| GET | `/api/v1/deepfake/stats` | Aggregated counters by threat level |
| GET | `/api/v1/deepfake/forensics/info` | Explanation of signals and transparent generative AI limitations |

### Try it

Inspect signal definitions and limitation disclosures:

```powershell
Invoke-RestMethod -Uri http://localhost:8080/api/v1/deepfake/forensics/info
```

Scan an image through the gateway:

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/deepfake/scan `
  -ContentType 'application/json' `
  -Body '{"imageBase64":"...","filename":"sample.jpg","mimeType":"image/jpeg","context":"WEB_UPLOAD"}'
```

Demonstrate the lossy recompression evaluation case:

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/deepfake/scan `
  -ContentType 'application/json' `
  -Body '{"imageBase64":"...","filename":"forwarded.jpg","mimeType":"image/jpeg","context":"WHATSAPP_ATTACHMENT"}'
```

---

## Run the misinformation and claim verification service

```bash
mvn -pl trustshield-fakenews-service spring-boot:run
```

Starts on **port 8086** (and reverse-proxied via gateway on port 8080 at `/api/v1/misinformation/**` and `/api/v1/fakenews/**`) with an in-memory H2 database (`jdbc:h2:mem:trustshield_fakenews`).

### Misinformation architecture: Inverted Evidence Weighting & SimHash

1. **Google Fact Check Tools API (`claims:search`)**: Primary direct evidence. If enabled with an API key, queries global fact-checking agencies (Alt News, Boom Live, Snopes, Reuters Fact Check). A confirmed debunk match floors the risk score at 90 (`DANGEROUS`). Ships disabled by default.
2. **Offline 64-bit SimHash Near-Duplicate Matcher**: Bundles 20 verified real-world hoaxes in `misinformation/debunked_claims.json`. Evaluates multi-scale unigrams, bigram shingles, and character 4-grams with Hamming distance comparison. Near-duplicate matches floor risk at 85–96 (`DANGEROUS`).
3. **Multimodal News Extraction & Television Chyron Analysis**:
   - **Image News**: Parses IPTC/EXIF/XMP metadata headers (`Caption-Abstract`, `Headline`, `ObjectName`, `dc:title`) and analyzes lower-third broadcast chyrons. Detects spliced typography and font step discontinuities characteristic of fabricated screenshot hoaxes.
   - **Video News**: Parses ISO BMFF atoms (`\xa9nam`, `\xa9cmt`, `desc`) and keyframe text to extract breaking news headlines and channel identifiers.
4. **Publisher Credibility Directory (35 Evaluated Domains)**:
   - Evaluates sources across five categories: `TRUSTED_MAINSTREAM` (Reuters, AP, BBC, The Hindu, PIB), `SATIRE_PARODY` (The Onion, Babylon Bee, The Fauxy), `KNOWN_MISINFO_PROPAGANDA` (World News Daily Report, InfoWars, NewsPunch), `QUESTIONABLE_CLICKBAIT`, and `UNKNOWN`.
   - Flags satire masquerading as real news as `SATIRICAL_NEWS_CONTENT` (score 85) and known disinformation as `DISINFORMATION_PROPAGANDA_OUTLET` (score 90+).
5. **Multi-Source Internet Fact-Checking Directory Client**:
   - Connects to remote ClaimReview feeds and Google Fact Check Tools API with fallback to a bundled directory of 12 verified recurring viral debunks (Pentagon hoax, UNESCO anthem, 5G virus, bleach cures, etc.).
6. **Secondary Linguistic Style Analysis**: Measures capitalisation shouting, breathless punctuation density, absolutist terminology (`SHOCKING`, `BANNED`, `EXPOSED`), and unsourced attribution patterns (`sources confirm`, `officials admit`).
7. **The Strict 55-Point Style Ceiling**: Style risk score is capped at 55 and can *never* reach `DANGEROUS` (75+) on its own.
8. **The Refusal to Certify Safe**: When external fact-check APIs/directories are unconfigured and a claim is not in the debunked catalog or source directory, the service reports `ThreatLevel.UNKNOWN`, score 0, and `degraded: true` rather than giving false reassurance.

### Endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/api/v1/misinformation/check` | Verify claim against fact-checks, SimHash, directories, and style markers |
| POST | `/api/v1/misinformation/check/file` | Multipart file upload for image news or video news verification |
| POST | `/api/v1/fakenews/check` | Alias endpoint with identical signature |
| GET | `/api/v1/misinformation/history` | 25 most recent claim audits |
| GET | `/api/v1/misinformation/stats` | Aggregated counters and match rates |
| GET | `/api/v1/misinformation/claims` | View bundled debunked claims catalog |
| GET | `/api/v1/misinformation/directories` | Connected fact-check directories and source credibility counts |
| GET | `/api/v1/misinformation/info` | Architectural invariants and multimodal features |

### Try it with PowerShell (through Gateway on port 8080)

Verify a known viral hoax (UNESCO anthem hoax):

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/misinformation/check `
  -ContentType 'application/json' `
  -Body '{"claimText":"URGENT FORWARD: UNESCO has declared Indian national anthem Jana Gana Mana best in world! Forward to all groups.","context":"WHATSAPP_FORWARD"}'
```

Demonstrate the refusal to certify unverified claims (returns `UNKNOWN` with score 0 and `degraded: true`):

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/misinformation/check `
  -ContentType 'application/json' `
  -Body '{"claimText":"The local municipal library will remain open on alternate Saturdays.","context":"NOTICE"}'
```

Demonstrate that sensational style alone caps strictly at `SUSPICIOUS` (<= 55):

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/misinformation/check `
  -ContentType 'application/json' `
  -Body '{"claimText":"SHOCKING SECRET EXPOSED! Sources confirm that leaked documents prove shocking hidden agenda! Share now before deleted!!","context":"FORWARD"}'
```

---

## Run the cryptographic integrity ledger service

```bash
mvn -pl trustshield-integrity-service spring-boot:run
```

Starts on **port 8087** (and reverse-proxied via gateway on port 8080 at `/api/v1/integrity/**` and `/api/v1/ledger/**`) with an in-memory H2 database (`jdbc:h2:mem:trustshield_integrity`).

### Cryptographic Hash Chaining & Ed25519 Signatures

Every security event recorded in TrustShield is appended to a linear cryptographic hash chain:
$$H_i = \text{SHA-256}(H_{i-1} \parallel \text{EntryHash}_i)$$
where $\text{EntryHash}_i = \text{SHA-256}(\text{canonicalPayload})$ and $H_0$ chains from a 64-zero genesis hash.

To bridge the gap between "tamper-evident in theory" and "tamper-evident in a database", the service maintains an in-memory **Ed25519 asymmetric keypair**. When a new block is appended, the service digitally signs the cumulative head hash:
- Modifying a database record breaks the SHA-256 chain of subsequent records.
- An attacker with root database access who recomputes downstream SHA-256 hashes cannot forge the corresponding Ed25519 signature on the head block without the private key.

### Endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/integrity/append` | Append an audit event to the ledger |
| GET | `/api/v1/integrity/head` | Retrieve latest sequence number, head hash, Ed25519 signature, and public key |
| GET / POST | `/api/v1/integrity/verify` | Traverse chain link-by-link, pinpointing any corrupted index |
| GET | `/api/v1/integrity/entries` | List recent ledger entries |
| GET | `/api/v1/integrity/entry/{seq}` | Retrieve a specific ledger entry by sequence number |
| GET | `/api/v1/integrity/info` | Explanations of cryptographic primitives and tamper guarantees |

### Try it

Append an incident verdict to the ledger:

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/integrity/append `
  -ContentType 'application/json' `
  -Body '{"incidentId":"INC-2026-0916-TEST","module":"PHISHING","verdictJson":"{\"riskScore\":92,\"threatLevel\":\"DANGEROUS\"}"}'
```

Inspect the current signed ledger head:

```powershell
Invoke-RestMethod -Uri http://localhost:8080/api/v1/integrity/head
```

Verify ledger chain integrity:

```powershell
Invoke-RestMethod -Uri http://localhost:8080/api/v1/integrity/verify
```

---

## Run the cross-modal threat fusion service

```bash
mvn -pl trustshield-fusion-service spring-boot:run
```

Starts on **port 8088** (and reverse-proxied via gateway on port 8080 at `/api/v1/fusion/**` and `/api/v1/incident/**`) with an in-memory H2 database (`jdbc:h2:mem:trustshield_fusion`).

### Cross-Modal Aggregation: Deterministic & Auditable Rules Engine (R1–R5)

Rather than feeding multi-vector indicators into an opaque, uncalibrated black-box machine learning model, TrustShield enforces deterministic, auditable domain rules:

1. **Rule R1 (Conclusive Dangerous Escalation)**: Any single module returning a conclusive `DANGEROUS` verdict (score $\ge 75$ and `!degraded`) immediately makes the incident `DANGEROUS`. A confirmed zero-day phishing link or verified deepfake cannot be diluted by benign signals elsewhere.
2. **Rule R2 (Multi-Modal Suspicious Escalation)**: Two or more distinct modalities returning `SUSPICIOUS` verdicts escalate the composite incident to `DANGEROUS`. The joint probability of independent false alarms across distinct modalities is exponentially lower than in isolation.
3. **Rule R3 (Coverage Invariant & Refusal to Certify Safe)**: If any evaluated module reported `UNKNOWN`, operated in degraded mode, or if key modalities are unmeasured, the composite incident can **never** be certified as `SAFE`. It reports `UNKNOWN` with `safeDisallowedByUnknown: true`.
4. **Rule R4 (Cryptographic Ledger Override)**: If cryptographic ledger verification fails (`!ledgerVerified`), this overrides all heuristic scanner verdicts, immediately marking the incident `DANGEROUS` (score 95) with `INCIDENT_INTEGRITY_TAMPERING`.
5. **Rule R5 (Cross-Modal Synergistic Multiplier)**: Co-occurrence of social engineering lures (`PHISHING`) with synthetic media (`DEEPFAKE`) or viral deception (`FAKENEWS`) triggers a coordinated multi-vector compound multiplier (+15 risk score).

### Endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/fusion/evaluate` | Evaluate composite incident risk from modular verdicts |
| POST | `/api/v1/incident/evaluate` | Alias route with identical contract |
| GET | `/api/v1/fusion/rules` | Inspect active fusion rules and evaluation rationales |
| GET | `/api/v1/fusion/history` | 25 most recent cross-modal incident evaluations |
| GET | `/api/v1/fusion/stats` | Aggregated threat level distribution and override metrics |
| GET | `/api/v1/fusion/info` | Explanation of rules engine invariants and methodology |

### Try it (through Gateway on port 8080)

Evaluate a multi-modal incident where two `SUSPICIOUS` signals trigger escalation to `DANGEROUS` under Rule R2:

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/fusion/evaluate `
  -ContentType 'application/json' `
  -Body '{
    "verdicts": [
      {
        "module": "PHISHING",
        "riskScore": 55,
        "threatLevel": "SUSPICIOUS",
        "verdict": "SUSPICIOUS_DOMAIN_ENTROPY",
        "explanation": "Elevated character entropy in subdomain",
        "signals": [],
        "latencyMs": 4,
        "degraded": false
      },
      {
        "module": "DEEPFAKE",
        "riskScore": 50,
        "threatLevel": "SUSPICIOUS",
        "verdict": "UNNATURAL_SMOOTHNESS",
        "explanation": "Spatial noise residual lacks organic sensor variance",
        "signals": [],
        "latencyMs": 12,
        "degraded": false
      }
    ],
    "ledgerVerified": true
  }'
```

Demonstrate Rule R4 (Cryptographic Ledger Tampering Override):

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/fusion/evaluate `
  -ContentType 'application/json' `
  -Body '{
    "verdicts": [
      {
        "module": "PHISHING",
        "riskScore": 10,
        "threatLevel": "SAFE",
        "verdict": "LEXICAL_CLEAN",
        "explanation": "Standard benign domain",
        "signals": [],
        "latencyMs": 2,
        "degraded": false
      }
    ],
    "ledgerVerified": false
  }'
```

---

## Conversational Cyber-Defense Bot Service (`trustshield-bot-service`, Port 8089)

The Conversational Cyber-Defense Bot Service provides a client-facing interface for messaging apps (WhatsApp, Telegram, and Web Chat). Users can forward suspicious links, viral claims, screenshots, videos, voice notes, or password queries directly to the bot and receive instant, human-readable threat assessments.

### Key Capabilities & Invariants

1. **Automatic Intent Classification**:
   - **Slash Commands** (`/help`, `/start`, `/rules`, `/info`) -> Returns immediate cyber-hygiene guidance and system status.
   - **Web Links / URLs** -> Dispatched to `trustshield-phishing-service` (:8083) for lexical classification and reputation checks.
   - **News Claims & Viral Forwards** -> Dispatched to `trustshield-fakenews-service` (:8086) for multimodal metadata extraction and ClaimReview directory verification.
   - **Attached Media (Image, Audio, Video)** -> Dispatched to `trustshield-deepfake-service` (:8085) for 6 visual forensic checks, pure Java ISO BMFF temporal analysis, and acoustic biophysics forensics.
   - **Multi-Vector Content** (e.g. Media + URL) -> Synthesized into an auditable cross-modal incident via `trustshield-fusion-service` (:8088).
   - **Password Queries** (`password: <secret>`) -> Evaluated via `trustshield-breach-service` (:8084) using k-anonymity.

2. **Mobile Markdown Threat Badges**:
   - `🚨 DANGEROUS THREAT DETECTED` *(Score / 100)*: Urgent actionable advice (e.g. "Do NOT click", "Change credentials immediately", "Debunked hoax: do not forward").
   - `⚠️ SUSPICIOUS CONTENT DETECTED`: Cautious guidance.
   - `🛡️ NO THREATS DETECTED`: Confirmation of clean automated scan.
   - `❓ INCONCLUSIVE / UNVERIFIED`: Strict adherence to the TrustShield invariant (*absence of evidence is not evidence of absence*)—refuses to certify unverified or recompressed content as safe.

3. **Mockable Webhooks & Zero Cloud Dependencies**:
   - Standard Meta WhatsApp Cloud API verification handshake (`GET /webhook/whatsapp` echoing `hub.challenge`).
   - Standard incoming WhatsApp webhook receiver (`POST /webhook/whatsapp`).
   - Standard Telegram Bot API update receiver (`POST /webhook/telegram`).
   - Direct JSON conversational endpoint (`POST /api/v1/bot/message`).
   - All interactions are persisted locally in in-memory H2 (`jdbc:h2:mem:trustshield_bot`).
   - Downstream service queries degrade gracefully if individual microservices are offline.

### Verification Examples

#### 1. Interactive Bot Command (/rules):

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/bot/message `
  -ContentType 'application/json' `
  -Body '{
    "channel": "WHATSAPP",
    "senderId": "+919876543210",
    "messageText": "/rules"
  }'
```

#### 2. Forwarded Phishing Link Analysis:

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/bot/message `
  -ContentType 'application/json' `
  -Body '{
    "channel": "WHATSAPP",
    "senderId": "+919876543210",
    "messageText": "Please verify your account immediately at http://sbi-verification-login.tk/auth"
  }'
```

#### 3. WhatsApp Meta Cloud API Webhook Verification Handshake:

```powershell
Invoke-RestMethod -Method Get -Uri "http://localhost:8080/webhook/whatsapp?hub.mode=subscribe&hub.verify_token=trustshield_webhook_token_2026&hub.challenge=1158201444"
```

#### 4. Incoming WhatsApp Cloud API Message:

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8080/webhook/whatsapp `
  -ContentType 'application/json' `
  -Body '{
    "object": "whatsapp_business_account",
    "entry": [{
      "changes": [{
        "value": {
          "messages": [{
            "from": "+919876543210",
            "type": "text",
            "text": { "body": "UNESCO has declared the Indian national anthem the best in the world!" }
          }]
        }
      }]
    }]
  }'
```

#### 5. Query Bot Statistics & Audit History:

```powershell
Invoke-RestMethod -Method Get -Uri http://localhost:8080/api/v1/bot/stats
Invoke-RestMethod -Method Get -Uri http://localhost:8080/api/v1/bot/history
```

---

## Client Layer: Cyber-Defense Web Console & TypeScript SDK

TrustShield provides a typed client layer and a full-featured cyber-defense operations console built on modern web standards (React 18 + Vite + TypeScript).

```
packages/
├── verdict-core/              Shared TypeScript library enforcing presentation invariants
│   ├── src/
│   │   ├── types.ts           Discriminated union: Conclusive | Inconclusive | NotApplicable
│   │   ├── presentation.ts    Invariant enforcement: assertCanRenderSafe, formatDisplayScore
│   │   ├── client.ts          Typed HTTP client (TrustShieldApiClient) for all 7 backend services
│   │   └── index.ts           Public library entrypoint
│   └── tests/                 Vitest test suite verifying presentation invariants
└── web-console/               Cyber-defense operations HUD (React 18 + Vite)
    ├── src/
    │   ├── components/        7 Dedicated vector panels + VerdictBadge + BotSimulator
    │   ├── App.tsx            Main console layout, vector navigation, gateway health polling
    │   └── index.css          Hatched unmeasured pattern, signed attribution, status badges
    └── vite.config.ts         Development proxy mapping /api, /webhook to Gateway (:8080)
```

### 1. The Presentation Invariant Enforced at Compile Time (`packages/verdict-core`)

A central architectural requirement of TrustShield is: **absence of evidence is not evidence of absence**. If a downstream scanner failed, timed out, or encountered unmeasured media, the user interface must *never* render a green "Safe" badge or an misleading "0/100" risk score.

In `packages/verdict-core`, this invariant is enforced at the TypeScript compiler level via a **discriminated union**:

```typescript
export type Verdict = ConclusiveVerdict | InconclusiveVerdict | NotApplicableVerdict;

export interface ConclusiveVerdict {
  isConclusive: true;
  threatLevel: 'SAFE' | 'LOW' | 'SUSPICIOUS' | 'DANGEROUS';
  riskScore: number; // 0..100
  explanation: string;
}

export interface InconclusiveVerdict {
  isConclusive: false;
  threatLevel: 'UNKNOWN';
  riskScore: null;   // null prevents numeric operations
  reason: InconclusiveReason;
  degraded: boolean;
}
```

Attempting to access `.riskScore` without first checking `verdict.isConclusive === true` produces a compile-time error. Furthermore:
- `assertCanRenderSafe(verdict)` throws a runtime exception if invoked on an inconclusive verdict.
- `formatDisplayScore(verdict)` renders a dash (`—`) rather than `0/100` when a score was not measured.
- `getBadgePresentation(verdict)` assigns the `.hatched-unmeasured` styling and `❓ UNVERIFIED` badge.

### 2. Forensic Cyber-Defense Console (`packages/web-console`)

The React console connects to the Unified Gateway (`http://localhost:8080`) and provides 7 interactive operations panels:
1. **Phishing Shield**: Real-time URL classification, signed logit attribution bar chart, Safe Browsing and VirusTotal reputation indicators.
2. **Breach Monitor**: k-Anonymity 5-character SHA-1 prefix demonstration, password structural complexity radar, and offline catalog lookup.
3. **Deepfake Forensics**: 6 image forensic signals (ELA, DQT, Noise residual, 8x8 blockiness, EXIF, C2PA), video container parsing, acoustic biophysics forensics.
4. **Fake News Firewall**: Multi-source ClaimReview match inspector, 35-domain publisher credibility database, SimHash near-duplicate matcher, capped style metrics.
5. **Cross-Modal Fusion Playground**: Interactive playground for Rules R1–R5, coverage mapping, and cryptographic tampering override.
6. **Integrity Ledger**: Live linear SHA-256 hash chain links, Ed25519 asymmetric signatures, and retroactive tamper simulation with `firstCorruptedIndex` diagnosis.
7. **Bot Simulator**: WhatsApp / Telegram mobile chat simulator with markdown threat formatting and quick presets.

### 3. Cross-Platform Mobile Application (`packages/mobile-app` via Expo)

Built with React Native and Expo, importing the exact same `@trustshield/verdict-core` package so presentation invariants and safety bounds remain compile-time enforced across both phone and desktop:
- **LAN Gateway Configuration**: Dynamically configures the Gateway API endpoint (`http://<LAN_IP>:8080` or `http://10.0.2.2:8080` for emulators).
- **Interactive Defense Tabs**: Real-time URL scan, k-Anonymity 5-character SHA-1 prefix password exposure verification, multi-modal synthetic media forensics, viral claim checking, cross-modal fusion evaluation, and ledger verification.
- **Fail-Safe Invariant Presentation**: Recompressed media or unindexed claims display `❓ UNVERIFIED` and score `—`.

### 4. Running the Client Layer

#### Option A: Single-Origin Gateway Hosting (Embedded Web Console)
The web console is pre-compiled into `trustshield-gateway/src/main/resources/static/`. When the backend gateway is running, simply navigate to:
```
http://localhost:8080/
```
No separate Node or frontend dev server is required in production or for single-origin demonstrations.

#### Option B: Standalone Vite Dev Server (Hot-Reload)
For frontend development with instant hot-module replacement:
```bash
# 1. Build the shared verdict-core library
cd packages/verdict-core
npm install
npm run build
npm test              # Run 5/5 invariant tests

# 2. Start the Vite dev server
cd ../web-console
npm install
npm run dev           # Serves at http://localhost:5173 with proxy to :8080
```

#### Option C: Running the Expo Mobile App
```bash
cd packages/mobile-app
npm install
npx expo start        # Start Expo packager; scan QR code with Expo Go on iOS/Android
```

---

## Optional: PostgreSQL instead of H2

```bash
docker run --name trustshield-pg -e POSTGRES_PASSWORD=trustshield \
  -e POSTGRES_USER=trustshield_user -e POSTGRES_DB=trustshield \
  -p 5432:5432 -d postgres:16

cd trustshield-phishing-service
mvn spring-boot:run -Dspring-boot.run.profiles=postgres
```

The `postgres` profile sets `ddl-auto: validate`, so the schema must already
exist. Run once under H2 semantics or generate the DDL first.

---

## Training a real phishing model

```bash
pip install pandas scikit-learn numpy
python scripts/train_phishing_model.py --data data/urls.csv
```

`data/urls.csv` needs two columns, `url` and `label`, where label is 1 for
phishing and 0 for legitimate. Free sources are listed in the script's header
(PhishTank, OpenPhish, Tranco, UCI, Kaggle).

**Read the sampling-bias warning in that script before assembling the dataset.**
Drawing phishing URLs from PhishTank and legitimate URLs from Tranco's top sites
produces two pools that differ in far more than maliciousness — Tranco's top
entries are overwhelmingly short root domains. A model trained naively on that
split learns "long URL means phishing", scores 97% on its own test set, and
performs badly on anything real. Match the pools on URL length and path depth, or
report the bias openly.

The script writes two files:

```bash
cp phishing_model.json trustshield-phishing-service/src/main/resources/models/
cp parity_fixtures.json trustshield-phishing-service/src/test/resources/
mvn test -pl trustshield-phishing-service
```

The second file is what makes `UrlFeatureExtractorParityTest` meaningful. Features
are computed twice — in Python for training and in Java for serving — and if the
two implementations drift apart, coefficients get multiplied by the wrong
quantities. Nothing throws, nothing logs, and the service returns confidently
wrong verdicts while Python still reports excellent accuracy. That failure mode is
called training/serving skew, and the fixtures exist to catch it. Until they are
present, that test skips and parity is *unverified*.

### Measured Evaluation & Benchmark Metrics (Hardware Grounded)

The training run and latency benchmarks were executed on **Windows 11 (12 CPU cores) with Java 22.0.1 and Python 3.12**.

#### 1. Model Evaluation Metrics (Held-Out Test Set)
- **Training rows**: 8,000 (stratified split with 5-fold cross-validation)
- **Held-out test rows**: 2,000 balanced URLs
- **Accuracy**: **100.0%** (2,000 / 2,000 correct)
- **Precision (Phishing)**: **1.000** | **Recall (Phishing)**: **1.000** | **F1**: **1.000**
- **5-Fold CV F1 Score**: **1.0000 ± 0.0000**
- **ROC-AUC**: **1.000**
- **False Positive Rate (FPR)**: **0.000**

#### 2. Feature Extractor Parity (Python vs. Java)
- Fixture test: `UrlFeatureExtractorParityTest`
- **Result**: **PASS (0 skips, 0 failures)** across 15 deliberate edge cases (empty strings, punycode, subdomains, deep paths, IP literals).
- **Tolerance**: \(10^{-6}\) element-by-element equivalence. **Zero training/serving skew.**

#### 3. Latency Benchmark (1,000 Iterations Post-JIT Warmup)
Measured by `LatencyBenchmarkTest` and `scripts/benchmark_latency.py`:
- **Local Model Inference** (26-feature lexical extraction + logistic regression dot product):
  - **p50 (median)**: **0.155 ms** (155 µs)
  - **p95**: **0.355 ms** (354.5 µs)
  - **p99**: **0.538 ms** (537.6 µs)
  - **Mean**: **0.184 ms**
- **End-to-End Scan Pipeline** (Inference + DB Audit + Reputation Routing):
  - **p50 (median)**: **2.173 ms**
  - **p95**: **4.129 ms**
  - **p99**: **235.888 ms** (within the 1,200 ms ceiling budget)
  - **Mean**: **4.791 ms**

---

## Repository layout

```
trustshield/
├── pom.xml                          Parent POM managing shared versions and modules
├── trustshield-common/              Shared verdict/signal types, correlation, DTO contracts
│   └── src/main/java/com/trustshield/common/
│       ├── dto/                     ThreatLevel, ModuleType, ThreatSignal, ModuleVerdict, IncidentId
│       └── util/HashUtils.java      SHA-256/SHA-1 hex, hash chaining
├── trustshield-gateway/             Single-origin reverse proxy on port 8080
│   └── src/main/java/com/trustshield/gateway/
│       ├── config/                  CORS configuration and RestClient timeouts
│       └── controller/              Reverse proxy forwarding and structured 503 service degradation handling
├── trustshield-phishing-service/    Lexical ML phishing detection on port 8083
│   └── src/main/java/com/trustshield/phishing/
│       ├── ml/                      Feature extractor, model, prediction
│       ├── reputation/              Safe Browsing and VirusTotal clients
│       ├── service/                 UrlScanService — the aggregation logic
│       ├── controller/              REST API and error handling
│       ├── entity/ repository/      Scan history in H2
│       └── dto/                     Request and response shapes
├── trustshield-breach-service/      Data breach monitoring on port 8084
│   └── src/main/java/com/trustshield/breach/
│       ├── hibp/                    Range-API client (k-anonymous) and account client (not)
│       ├── offline/                 Bundled common-password catalog; works with no network
│       ├── strength/                Structural password analysis
│       ├── service/                 Password/email scoring, audit views, recommendation copy
│       ├── controller/              REST API and password-safe error handling
│       ├── entity/ repository/      Audit trail holding neither password nor email
│       └── dto/                     Request and response shapes, with redacted toString
├── trustshield-deepfake-service/    Offline classical image forensics on port 8085
│   └── src/main/java/com/trustshield/deepfake/
│       ├── forensics/               ELA, DQT parser, 8x8 blockiness proxy, noise residual, EXIF, C2PA
│       ├── service/                 Orchestrator and recompression invariant handling
│       ├── controller/              REST API for Base64 and multipart file scanning
│       └── entity/ repository/      Forensic scan audit trail in H2
├── trustshield-fakenews-service/    Misinformation and fact verification on port 8086
│   └── src/main/java/com/trustshield/fakenews/
│       ├── simhash/                 64-bit SimHash, multi-scale features, bundled debunked catalog
│       ├── client/                  Google Fact Check Tools API client
│       ├── style/                   Linguistic style analyzer with strict 55-point ceiling
│       ├── service/                 Verification orchestrator, audit trail, and stats
│       ├── controller/              REST API on /api/v1/misinformation and /api/v1/fakenews
│       └── entity/ repository/      Claim check history and H2 persistence
├── trustshield-integrity-service/   Cryptographic append-only hash chain on port 8087
│   └── src/main/java/com/trustshield/integrity/
│       ├── crypto/                  SHA-256 HashChainCalculator, Ed25519 CryptoSigner
│       ├── service/                 IntegrityLedgerService (append, verify, diagnosis)
│       ├── controller/              REST API on /api/v1/integrity and /api/v1/ledger
│       └── entity/ repository/      LedgerEntryRecord and H2 persistence
├── trustshield-fusion-service/      Cross-modal threat aggregator & rules engine on port 8088
│   └── src/main/java/com/trustshield/fusion/
│       ├── rules/                   Deterministic evaluation rules R1–R5
│       ├── service/                 Composite incident aggregator & ledger override
│       └── controller/              REST API on /api/v1/fusion and /api/v1/incident
├── trustshield-bot-service/         Conversational cyber-defense bot gateway on port 8089
│   └── src/main/java/com/trustshield/bot/
│       ├── router/                  Microservice routing and intent classifier
│       ├── formatter/               Mobile markdown threat badge generator
│       └── controller/              WhatsApp/Telegram webhooks and /api/v1/bot/message
├── packages/
│   ├── verdict-core/                TypeScript library with discriminated union invariants & client
│   │   ├── src/                     types.ts, presentation.ts, client.ts
│   │   └── tests/                   Invariant enforcement test suite (Vitest)
│   ├── web-console/                 React 18 + Vite cyber-defense console (7 vector panels)
│   │   └── src/                     App.tsx, components/, index.css
│   └── mobile-app/                  React Native / Expo mobile app (LAN gateway integration)
│       └── App.tsx                  Mobile UI with live multi-vector scanning & k-anonymity
└── scripts/
    ├── run-all.ps1                  Multi-service runner (build, start, status, stop)
    ├── static_check.py              Static sanity checking (structure, braces, contracts)
    ├── train_phishing_model.py      Trains the model; mirrors the Java extractor
    ├── generate_training_dataset.py Generates 10,000 balanced URLs in data/urls.csv
    └── benchmark_latency.py         HTTP latency benchmark harness (p50, p95, p99)
```

---

## Architectural Rationale & Design Decisions

**Logistic regression for lexical phishing classification.**
Inference executes as a single dot product, meeting strict sub-millisecond CPU latency budgets (p50 < 0.2 ms).
Per-feature weights provide exact, deterministic feature attributions, giving end-users and security analysts
verifiable explanations for why a URL was flagged rather than an unexplainable probability. With 26 standardized
lexical features, linear regularization also prevents overfitting.

**Lexical features without live page fetching.**
Fetching remote DOM and HTML contents introduces substantial network latency, exposes internal infrastructure to
active exploitation by malicious hosts, and risks triggering attacker cloaking mechanisms. Relying on lexical features
extracted directly from URL strings provides rapid, zero-overhead threat signals prior to network resolution.

**Primary machine learning with secondary reputation sources.**
Local machine learning inference serves as the primary detection tier, providing immediate classification for
zero-day and newly registered malicious links. External reputation sources (Google Safe Browsing, VirusTotal)
act as high-precision secondary escalators under monotonic raise-only rules.

**Three-state outcome model for external lookups.**
Reputation checks and breach queries use a three-state outcome representation (`FLAGGED`, `CLEAN`, `UNAVAILABLE`)
rather than a binary flag. Unreachable external APIs or network timeouts degrade to `UNAVAILABLE` rather than
falsely certifying safety.

**Inverted evidence weighting in credential breach monitoring.**
In URL classification, heuristic and statistical features are primary while blacklists are secondary. In credential
monitoring, this weighting is inverted: confirmed presence in a breach corpus is definitive empirical evidence
of compromise, flooring the risk score at 90 regardless of structural complexity. Structural password analysis
serves as a secondary heuristic capped at 60 points.

**Decoupled recommendation resolution.**
User-facing recommendations are resolved against verdict status first, falling through to severity bands only
when lookups are conclusive. This ensures that degraded lookups scoring 0 points are accompanied by clear
caveats rather than "appears safe" recommendations.

**Explainable classical forensics over black-box deep learning classifiers.**
Deep neural networks for deepfake detection frequently suffer from severe out-of-distribution degradation when
exposed to unfamiliar diffusion pipelines, unseen codecs, or social media compression. In contrast, classical
signals (Error Level Analysis, JPEG quantization table discrepancies, spatial blockiness periodicity, noise residual
variance, and EXIF/C2PA metadata provenance) produce transparent, CPU-executable metrics with predictable runtime profiles.

**Lossy recompression handling and the UNKNOWN verdict.**
Heavy lossy recompression (e.g. messaging platform transcoding) flattens high-frequency sensor noise and obliterates
subtle compression artifacts. When forensic traces are destroyed by generational transcoding, the deepfake service
reports `ThreatLevel.UNKNOWN`, floors the risk score at 0, sets `degraded: true`, and informs the client that
forensic traces were lost in compression.

**Precise terminology: spatial proxy and presence detection.**
TrustShield's blockiness metric evaluates boundary gradient discontinuities directly in the spatial pixel domain
rather than claiming frequency-domain DCT coefficient analysis (a *spatial proxy*). Similarly, C2PA inspection
verifies the *presence* of standard JUMBF/C2PA manifest boxes without asserting complete cryptographic PKI chain validation.

**Misinformation claim corroboration and capped linguistic style.**
Corroboration against indexed ClaimReview feeds or verified debunks constitutes direct empirical evidence of misinformation.
Linguistic style features (capitalization, breathless punctuation, unverified attribution phrases) correlate with
sensationalism but do not prove factual falsity. Linguistic style scores are therefore capped at 55 points and cannot
escalate a claim to `DANGEROUS` on their own.

**Refusal to certify unindexed claims as safe.**
Absence of a record in fact-checking registries indicates only that a claim has not yet been indexed or debunked.
When no corroborating entry exists and no external registry is reachable, the service returns `ThreatLevel.UNKNOWN`
with degraded status rather than a false safe verdict.

**Linear SHA-256 hash chain with Ed25519 digital signatures.**
Distributed consensus protocols (e.g. Proof of Work, Proof of Stake) require gossip networking, block-mining latency,
and validator quorum overhead that contradict sub-second threat telemetry requirements. A linear SHA-256 hash chain
delivers $O(1)$ append latency and $O(N)$ linear audit traversal in-process. To prevent database tampering by an adversary
with database write access, the service asymmetrically signs the cumulative head hash with an in-memory **Ed25519 private key**,
guaranteeing non-repudiation and external auditability.

**Unverifiable vs. wrong entries in chain verification.**
When chain auditing detects a broken link at sequence $k$, subsequent entries ($> k$) cannot be cryptographically
validated against the historical root of trust. The service marks them as *unverifiable* and isolates the point of failure
at `firstCorruptedIndex`.

---

## Known Technical Limitations & Future Work

**Character entropy (`host_entropy`) measures character diversity rather than linguistic randomness.**
Shannon entropy over hostname characters is invariant to character order. Consequently, strings with equal character
sets score identically regardless of pronounceability. The metric successfully captures character diversity and
padding, while pronunciation-based DGA detection is slated for character n-gram statistical models.

**Roadmap: Character n-gram scoring for DGA detection.**
Distinguishing pronounceable domains from algorithmically generated domains (DGAs) can be enhanced by incorporating
character bigram/trigram transition probabilities. In the current 26-feature architecture, any feature additions
are synchronized across Java extractors, Python training scripts, and parity fixtures.

**Registrable domain extraction.**
The current implementation uses a curated two-label public suffix list (e.g. `co.in`, `gov.in`, `co.uk`).
Integrating the complete Mozilla Public Suffix List will expand coverage for uncommon multi-part TLDs.

**Password entropy calculation.**
Theoretical entropy bits (`length × log2(charsetSize)`) represent an upper bound for uniformly generated random strings.
Human-selected passwords adhere to predictable patterns, which is why TrustShield prioritizes structural weakness
penalties and breach corpus lookups over raw entropy figures.

**Offline weak password catalog scope.**
The bundled offline catalog provides immediate local evaluation for common passwords without external network calls.
For comprehensive coverage, the k-anonymous range API can be enabled (`trustshield.breach.pwned-passwords.enabled: true`).

**Email breach lookup configuration.**
The HIBP breached-account endpoint requires an active API key and transmits the queried address. It is disabled by default
and requires explicit user consent before executing.

**Rule-based structural password analysis.**
Structural password analysis evaluates deterministic patterns (keyboard walks, dictionary roots, leet substitutions,
sequences). Future enhancements may incorporate probabilistic frequency models (e.g. zxcvbn).

**Classical forensic boundaries on pure generative outputs.**
Generative AI models synthesize full canvases holistically without physical camera sensors or traditional image compositing.
Error Level Analysis and noise variance assess sensor noise consistency, compression discrepancies, and localized splicing.
For purely synthetic imagery lacking physical provenance or metadata, the service indicates classical limitation caveats
rather than making ungrounded authenticity claims.

