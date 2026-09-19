# TrustShield

An AI-powered system for real-time threat detection and protection against
deepfakes, phishing, data breaches, and online misinformation.

Java 21 · Spring Boot 3.3.2 · Maven multi-module monorepo

---

## Current state, stated plainly

This section is deliberately the first thing in the file. A project report that
overstates what runs is worse than one that admits what does not, because a
single question in a viva ("show me that number") collapses the whole document.

| Module | Status | What actually works |
|---|---|---|
| `trustshield-common` | **Working** | Shared verdict/signal types, IncidentId correlation, and contracts for all modules |
| `trustshield-gateway` | **Working** | Reverse proxy on port 8080, unified CORS, downstream routing, honest 503 degradation |
| `trustshield-phishing-service` | **Working** | 26-feature lexical classifier, dynamic Safe Browsing & VirusTotal reputation enrichment, raise-only invariant, REST API, scan history, explainability, tests |
| `trustshield-breach-service` | **Working** | Password exposure via HIBP k-anonymity + offline catalog, email breach lookup, structural password analysis, audit trail, tests |
| `trustshield-deepfake-service` | **Working** | Multimodal image and video forensics: Pure Java ISO BMFF container parser, video temporal jitter & inter-frame residual divergence analysis, multi-language acoustic biophysics forensics (HiFi-GAN/WaveGlow spectral roll-off, robotic pitch micro-tremor, digital silence dynamics), C2PA trust registry & internet directory connectivity, 6 image forensic signals, honest UNKNOWN invariant, H2 persistence, 30 tests |
| `trustshield-fakenews-service` | **Working** | Multimodal claim verification (text, image news, video news): IPTC/EXIF & video atom metadata headline extraction, TV news chyron & banner splice tampering analysis, 35-domain publisher credibility directory (Mainstream, Satire, Propaganda), multi-source ClaimReview internet directory with 12 verified debunks, Google Fact Check API, offline 64-bit SimHash, capped linguistic style (max 55), multipart file upload, 43 tests |
| `trustshield-integrity-service` | **Working** | Cryptographic append-only SHA-256 hash chain, Ed25519 digital signatures, firstCorruptedIndex diagnosis, REST API on port 8087, H2 persistence, tests |
| `trustshield-fusion-service` | **Working** | Cross-modal threat aggregator, canonical auditable rules R1 (Conclusive Dangerous), R2 (Multi-Modal Suspicious Escalation), R3 (Coverage Invariant), R4 (Cryptographic Ledger Override), R5 (Cross-Modal Coordination Multiplier), H2 persistence, REST API on port 8088, 23 tests |
| `trustshield-bot-service` | **Working** | Conversational cyber-defense bot gateway (Port 8089) for WhatsApp, Telegram, and Web Chat, automatic intent classification, mobile markdown threat badges, resilient microservice router with offline fallbacks, H2 persistence, mockable webhooks with `hub.challenge` handshake, 25 tests |

**The bundled phishing model is not trained.** `phishing_model.json` ships with
hand-initialised bootstrap weights so the service is runnable before a dataset is
assembled. Its `provenance` field says `HEURISTIC_BOOTSTRAP`, the service logs a
loud warning at startup, and `/api/v1/phishing/model` reports `trained: false`.

Accuracy, precision, recall and F1 must not be quoted until
`scripts/train_phishing_model.py` has been run on real data and the regenerated
file reports `provenance: TRAINED`.

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

Expected on success: `BUILD SUCCESS` with 194 passing tests across nine
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

If a downstream service has not been started, the gateway returns a structured, honest HTTP 503 response:
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
range API disabled and the offline list too small for absence to mean anything,
no source could actually answer, so the service says so. This is the single most
defensible behaviour in the module and it is worth demonstrating deliberately.

### The k-anonymity claim, stated correctly

The Pwned Passwords **range** API supports k-anonymity: SHA-1 the password, send
the first 5 hex characters, and match the remaining 35 locally. The server learns
one bucket out of 16^5 = 1,048,576. `Add-Padding: true` is sent so that response
size does not leak which bucket was queried.

**This does not apply to the email lookup.** The breached-account endpoint has no
prefix-based variant, so if that check runs at all, the full address is
transmitted. The original project draft conflated the two. Here they are separate
client classes, `kAnonymous` is reported per endpoint, the email check refuses to
run without explicit `acknowledged: true`, and `GET /api/v1/breach/privacy`
serves the difference as data so a dashboard cannot describe the guarantee
differently from the implementation.

Only a SHA-256 of the lower-cased address is stored. That is
**pseudonymisation, not anonymisation** — email addresses have low entropy, so a
candidate list can confirm a guess. The README says so, the code says so, and the
report should say so too.

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

Demonstrate the honest recompression failure case:

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
│       └── controller/              Reverse proxy forwarding and honest 503 handling
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
└── scripts/
    ├── run-all.ps1                  Multi-service runner (build, start, status, stop)
    ├── static_check.py              Static sanity checking (structure, braces, contracts)
    └── train_phishing_model.py      Trains the model; mirrors the Java extractor
```

---

## Design decisions worth defending in a viva

**Why logistic regression rather than a neural network.** Three reasons, in order
of importance. Inference is a single dot product, which is what makes the latency
target reachable. The per-feature contribution is an exact attribution, so the
system can tell a user *why* a link was flagged rather than producing a score with
no derivation — and a score with no derivation is not evidence. And with 26
features and a modest dataset, a high-capacity model would mostly memorise.

**Why lexical features only, with no page fetch.** Fetching the page would give
richer signal, but it means visiting a possibly malicious host on the user's
behalf and it destroys the latency budget. Following Ma et al. (KDD 2009) and the
survey of Sahoo et al. (2017), features drawn from the URL string alone are
enough to be useful and cost nothing but string operations.

**Why the machine learning is primary and the blocklists are secondary.** This is
the inversion of the original design, and it is the difference between an
AI-powered system and a client for other people's blocklists. See the extended
comment on `UrlScanService`.

**Why unavailable is a distinct state from clean.** `ReputationVerdict` has three
states, not two. Collapsing "the API timed out" into "the API said it was fine" is
a one-character bug with a security consequence, and it is the kind of thing worth
being explicit about in a security project.

**Why the breach module inverts that weighting.** In the phishing service the
model is primary and blocklists are secondary. In the breach service it is the
reverse: corpus membership is primary and structural analysis is secondary. The
reason is that they are different kinds of evidence. A password found in a breach
corpus is not a probabilistic inference — it is direct evidence that the exact
string is already in an attacker's wordlist. Structure only *predicts* how a
password might fare, and prediction should not be allowed to argue with
observation. So a confirmed hit floors the score at 90, and structural analysis
alone is capped at 60 so it can never reach `DANGEROUS` on its own.

**Why "unavailable is not clean" had to be enforced twice.** The three-state
verdict was correct in the scoring layer from the start: a check that reached no
source scored 0 with `degraded: true`. But the user-facing `recommendation` field
was built from the shared `ThreatLevel`, which maps a score of 0 to `SAFE`, whose
text reads *"This appears safe."* So four code paths — including the default demo
path for a strong password — would have told a user their credential appeared safe
when nothing had been checked at all. The score was right; the sentence the user
actually reads was wrong.

`Recommendations` fixes this by selecting guidance on **verdict state first**, and
falling through to the severity band only when the verdict is a complete answer.
The lesson generalises: a correctness property enforced in the domain layer can
still be violated in the presentation layer, and the presentation layer is the
only one the user sees. Two integration tests now assert that no response body
contains the string "appears safe" on a path where nothing was checked.

**Why classical forensics rather than an opaque deepfake CNN classifier.**
The deepfake service avoids black-box neural networks for three reasons. First,
deep learning deepfake detectors suffer severe out-of-distribution failure: a
CNN trained on FaceForensics++ or StyleGAN2 fails dramatically when presented
with modern diffusion outputs or alternate compression pipelines. Second, an
academic project cannot defensibly claim 95%+ classification accuracy when the
underlying model is brittle and unvalidated. Third, classical forensic signals
(Error Level Analysis, JPEG quantization table discrepancies, noise residual
variance, and EXIF/C2PA metadata provenance) produce concrete, inspectable
indicators that run instantly on a standard CPU with zero warmup latency and no
GPU requirement. The user and examiner are presented with explainable evidence
rather than an opaque, uncalibrated probability.

**Why recompressed media returns `UNKNOWN` rather than clean.**
The central invariant across TrustShield is that *an unknown result is not a safe
result*. Heavy JPEG recompression or re-encoding from social messaging platforms
(WhatsApp, Telegram, Twitter) flattens high-frequency noise and obliterates
subtle edge artifacts. When recompression artifacts dominate, classical analysis
cannot distinguish a pristine original from a manipulated image whose traces
were crushed by the re-encoder. Collapsing this uncertainty into `SAFE` would
be an active false negative. Instead, the service reports `ThreatLevel.UNKNOWN`,
floors the threat score at 0, sets `degraded: true`, and explicitly warns the user
that generational recompression prevents reliable forensic determination.

**Why 8x8 blockiness is named a spatial proxy and C2PA is named presence detection.**
Precision in naming prevents technical overclaims under viva scrutiny. In strict
JPEG compression, block artifact grids are frequency-domain 8x8 DCT boundary
structures. TrustShield's blockiness metric evaluates boundary discontinuities
directly in the spatial pixel domain; calling it a *spatial proxy* accurately
reflects its implementation rather than claiming to perform frequency-domain DCT
coefficient analysis. Similarly, C2PA inspection checks for the *presence* of
standard manifest boxes and JUMBF metadata containers. It does not claim to
perform cryptographic certificate chain validation or root-of-trust verification,
which would require external public-key infrastructure.

**Why the misinformation module inverts evidence weighting and caps style at 55.**
Corroboration against an external, authoritative source (Google Fact Check Tools
API or an offline SimHash match against debunked claims) is *direct evidence* of
known misinformation. In contrast, linguistic style (capitalisation, breathless
punctuation, unsourced phrases like "sources confirm") *only correlates* with
misinformation. An urgent truth is still urgent; breathless punctuation does not
turn factual news into a malicious attack. Therefore, style analysis is strictly
capped at 55 points and can never escalate a claim to `DANGEROUS` (75+) on its own.

**Why the service refuses to certify unindexed claims as clean.**
TrustShield cannot establish that an unindexed statement is true or false. A miss
in the fact-checking catalog simply means the claim has not been investigated or
debunked by indexed agencies. Collapsing this absence of evidence into `SAFE`
would falsely reassure users about unverified claims. When no external fact-checking
API is reachable and no local match exists, the module honestly returns
`ThreatLevel.UNKNOWN`, score 0, and `degraded: true`.

**Why a hash chain with Ed25519 signatures replaced blockchain.**
The original project plan called for a blockchain audit trail. In a security
viva, that claim collapses under basic scrutiny: distributed consensus (e.g. Proof
of Work or Proof of Stake) requires gossip networking, block-mining latency (seconds
to minutes), and economic incentives or validator quorum overhead that directly
contradict the sub-second requirements of real-time threat telemetry. A linear
SHA-256 hash chain provides $O(1)$ append latency and $O(N)$ linear audit traversal
in-process.

Furthermore, claiming a database-backed hash chain is "tamper-proof" is an academic
falsehood: an attacker with root database access can alter an entry and recompute
all subsequent SHA-256 hashes. To enforce genuine *tamper-evidence*, TrustShield
asymmetrically signs the cumulative head hash with an in-memory **Ed25519 private key**
(`KeyPairGenerator.getInstance("Ed25519")`). An attacker modifying database records
cannot forge valid digital signatures without the private key. Framing this as
*"weaker than distributed consensus, and here is exactly how"* is an academically
defensible thesis.

**Why subsequent entries are unverifiable rather than wrong.**
When ledger verification encounters a broken hash link at index $k$, the audit
engine does not report entries $> k$ as malicious or wrong. Once a link in a
cryptographic chain of custody is broken, subsequent hashes cannot be evaluated
against the historical root of trust — they are strictly **unverifiable**. Reporting
the exact `firstCorruptedIndex` isolates the point of failure while acknowledging
the limits of cryptographic diagnosis.

## Known limitations of the current feature set

These are real weaknesses, written down because a limitation you can state is a
limitation an examiner cannot ambush you with.

**`host_entropy` does not detect algorithmically generated domains, and the code
no longer claims it does.** The feature is a unigram Shannon entropy over the
hostname's characters. Because it depends only on the multiset of characters, it
is completely invariant to their order, so it measures character *diversity*
rather than randomness in any linguistic sense. Concretely, `x7k2mq9v` and
`hdfcbank` both consist of eight distinct characters over eight positions, so both
score exactly log2(8) = 3.0 bits. This was originally documented the wrong way
round in both the javadoc and the user-facing feature description; the failing
assertion in `UrlFeatureExtractorTest` is what exposed it. The limitation is now
pinned by `entropyCannotSeparateRandomFromPronounceable`, which asserts the two
values are *equal* — a test whose purpose is to stop the wrong claim being
reintroduced.

What the feature does capture is narrower but genuine: hostnames padded with
repeated characters or drawn from a small alphabet score low, and long hostnames
mixing letters, digits and hyphens score high.

**Roadmap: character bigram scoring for DGA detection.** Separating pronounceable
strings from random-looking ones requires character bigram or trigram statistics
fitted to a corpus of real domain names — scoring `hdfcbank` highly because `hd`,
`df`, `ba`, `nk` are common English digraphs while `x7`, `7k`, `k2` are not. This
is deliberately *not* being added before the demo, because it takes the feature
count from 26 to 27 and therefore requires, in lockstep — the full list, since
`grep -rn "26" src scripts` is the only thing standing between you and a bricked
service:

- regenerating `phishing_model.json` (`mean`, `scale`, `coefficients`, `featureNames` all change length)
- `UrlFeatureExtractorTest.java:43` — `assertEquals(26, FEATURE_COUNT)`
- `PhishingScanIntegrationTest.java:137` — `jsonPath("$.featureCount").value(26)`
- adding the matching extractor to `scripts/train_phishing_model.py`, or the Java and Python extractors drift apart and `UrlFeatureExtractorParityTest` fails
- adding a `FEATURE_DESCRIPTIONS` entry, since the two arrays are asserted to be the same length
- prose mentioning "26 features", which is not load-bearing but goes stale: `WebConfig.java:38` (the OpenAPI description users see), `PhishingModel.java:32`, and the `train_phishing_model.py` docstring at line 229

`PhishingModel` hard-fails at startup on a feature-count mismatch, which is the
correct behaviour but means a partial change bricks the service. Post-demo work.

**The bundled model is not trained.** Weights carry `provenance:
HEURISTIC_BOOTSTRAP`, the service logs a warning on boot, and
`GET /api/v1/phishing/model` reports `trained: false`. No accuracy, precision or
recall figure may be quoted for this build. See "Training a real phishing model"
above.

**`registrableDomain` uses a hard-coded suffix list, not the Public Suffix List.**
It handles the common two-label suffixes (`co.in`, `gov.in`, `co.uk` and similar)
and will mis-handle uncommon ones. Swapping in a real PSL library is a contained
change.

**Password "entropy bits" is an upper bound, not a strength rating.** The
`theoreticalBits` figure is `length × log2(charsetSize)`, which is the entropy of
a password *generated uniformly at random* over that alphabet. Human-chosen
passwords are not generated that way, so the number is an upper bound on strength
and often a wildly flattering one. `Password123!` scores 78.66 bits — a figure
that would look excellent on a dashboard — while being among the first strings any
cracking dictionary tries.

This is the same category of overclaim as the `host_entropy` mistake above, and it
is handled the same way: the field is labelled an upper bound, the assumed attack
rate (10^10 guesses/second) travels alongside every crack-time estimate, and the
*operative* number is the structural weakness score, which rates
`Password123!` at 55 rather than "excellent". `PasswordStrengthAnalyzerTest`
pins the divergence between the two numbers so the flattering one cannot quietly
become the headline.

**The offline catalog is 138 entries, so a miss means almost nothing.** It is a
demo-reliability measure, not a breach corpus. Accordingly a miss is reported as
`UNAVAILABLE` rather than `NOT_FOUND`, and a hit reports no occurrence count
because a membership-only list does not have one. Enable the range API
(`trustshield.breach.pwned-passwords.enabled: true`) for real coverage — it needs
no API key.

**Email breach lookup is disabled by default and needs a paid key.** The HIBP
breached-account API requires a subscription, so `GET /api/v1/breach/stats`
reports `hibpAccountApiUsable: false` on a stock checkout and the endpoint returns
`SOURCE_UNAVAILABLE`. The password check needs no key and works offline, which is
why the demo is built around it.

**Structural analysis is regex-based, not a trained model.** It detects keyboard
walks, common base words, leet substitutions, sequences, repeats and
word-plus-digits patterns. It has no notion of the probability distribution over
real passwords, so it cannot rank two structurally clean passwords against each
other. A frequency-model approach (zxcvbn-style) would be the upgrade; it is not
being attempted before the demo.

**Classical forensics does not reliably detect pure generative AI outputs with uniform pixel statistics.**
Generative models (such as modern diffusion architectures or Midjourney)
synthesize full images holistically rather than compositing or splicing disparate
elements. Consequently, techniques like Error Level Analysis (ELA) and noise
residual variance find uniform statistics across the entire canvas, because there
is no splice boundary or differential compression level between composite parts.
Classical forensics excels at identifying local tampering, cut-and-paste
splicing, recompression discrepancies, and metadata tampering — not identifying
pure synthetic images generated from scratch without physical camera provenance.
For purely synthetic imagery lacking provenance metadata or splicing artifacts,
the service refrains from making ungrounded claims of authenticity.

