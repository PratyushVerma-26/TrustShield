# TrustShield: Comprehensive Evaluator Demonstration Runbook

This document provides an end-to-end evaluation and demonstration runbook for **TrustShield**, a unified multi-modal cyber-defense platform designed for real-time threat detection, multi-modal evidence fusion, and tamper-evident audit logging.

---

## 1. Architecture Overview & Port Allocation

TrustShield executes as an enterprise microservice mesh. All external client traffic (Web Console, Mobile App, Bot Webhooks) is routed through the **Unified API Gateway (Port 8080)**, which provides transparent reverse proxying, rate limiting (100 req/min token bucket), security headers, and structured 503 degraded fallback.

| Service Component | Module Directory | Port | Primary Responsibilities |
| :--- | :--- | :--- | :--- |
| **API Gateway** | `trustshield-gateway` | `8080` | Single-origin reverse proxy, token bucket rate limiter, security headers, failure isolation |
| **Phishing Shield** | `trustshield-phishing-service` | `8083` | 18 lexical/structural features, punycode, TLD reputation, ML heuristic inference ($p_{50} = 0.155\text{ ms}$) |
| **Breach Monitor** | `trustshield-breach-service` | `8084` | $k$-Anonymity range search (HIBP SHA-1 prefix), offline common password digests, zxcvbn entropy scoring |
| **Deepfake Detector** | `trustshield-deepfake-service` | `8085` | ELA, DQT quantization, spatial blockiness, noise residuals, C2PA manifests, video temporal optical flow, audio spectral roll-off |
| **Misinformation Verifier**| `trustshield-fakenews-service`| `8086` | Television chyron typography forensics, 64-bit SimHash near-duplicate debunk catalog, internet fact-checking directory query |
| **Integrity Ledger** | `trustshield-integrity-service` | `8087` | Append-only SHA-256 hash chain, Ed25519 digital signatures, tamper-evident audit verification |
| **Fusion Engine** | `trustshield-fusion-service` | `8088` | Cross-modal threat correlation rules, bounded risk score aggregation (0–100), incident dispatch |
| **Cyber-Defense Bot** | `trustshield-bot-service` | `8089` | Intent classification, conversational routing, multi-platform formatting (Web Chat, WhatsApp, Telegram) |
| **Web Console** | `packages/web-console` | `5173` | React 18 / TypeScript operations cockpit with interactive live scanners and audit verification UI |
| **Mobile Application** | `packages/mobile-app` | `8081` | Standalone Expo / React Native client for on-device threat verification |

---

## 2. Environment Prerequisites & Service Startup

### Prerequisites
- **Java SE Development Kit**: Version 21 or 22 (`java -version`)
- **Apache Maven**: Version 3.8+ (`mvn -v`)
- **Node.js**: Version 20+ and npm (`node -v`, `npm -v`)
- **Python**: Version 3.10+ (`python --version`)
- **PowerShell**: Version 5.1 or PowerShell Core 7+

### Step 2.1: Single-Command Platform Startup
From the repository root, start all 8 microservices as managed background processes:

```powershell
# Build fat JARs and launch all microservices in the background
.\scripts\run-all.ps1 -Build
```

*(If JARs are already compiled, launch instantly without rebuilding:)*
```powershell
.\scripts\run-all.ps1
```

### Step 2.2: Verify Microservice Mesh Health
Check the running status and port bindings of all services:
```powershell
.\scripts\run-all.ps1 -Status
```

Expected Output:
```text
Port   Service                            Status       PID
----   -------                            ------       ---
8080   trustshield-gateway                HEALTHY      [PID]
8083   trustshield-phishing-service       HEALTHY      [PID]
8084   trustshield-breach-service         HEALTHY      [PID]
8085   trustshield-deepfake-service       HEALTHY      [PID]
8086   trustshield-fakenews-service       HEALTHY      [PID]
8087   trustshield-integrity-service      HEALTHY      [PID]
8088   trustshield-fusion-service         HEALTHY      [PID]
8089   trustshield-bot-service            HEALTHY      [PID]
```

### Step 2.3: Launch Frontend Clients

#### Launch Web Console (Port 5173)
In a separate terminal:
```powershell
cd packages\web-console
npm install
npm run dev
```
Open browser to `http://localhost:5173`.

#### Launch Mobile App (Port 8081)
In a separate terminal:
```powershell
cd packages\mobile-app
npm install
npx expo start
```
Scan the QR code with Expo Go on iOS/Android or press `w` to run in web mode.

---

## 3. End-to-End Threat Vector Evaluation Scenarios

All API requests can be executed directly against the **Gateway (Port 8080)**.

### Threat Vector 1: Phishing & Malicious URL Detection

#### Test 1.1: High-Risk Homograph / Credential Harvesting URL
Tests detection of brand impersonation, high Shannon entropy, suspicious subdomain depth, and risk scoring.

```powershell
curl -X POST "http://localhost:8080/api/v1/phishing/scan" `
  -H "Content-Type: application/json" `
  -d '{"url": "https://secure-login.paypal.com.account-verification-notice.xyz/update-credentials"}'
```

**Expected Response Highlights:**
- `verdict.threatLevel`: `"DANGEROUS"`
- `verdict.riskScore`: `92` - `98`
- `verdict.verdict`: `"HIGH_RISK_PHISHING"`
- `signals`: Triggers `BRAND_NAME_IN_SUBDOMAIN` (PayPal), `SUSPICIOUS_TLD` (.xyz), `SUBDOMAIN_DEPTH_EXCESSIVE`.

#### Test 1.2: Benign Whitelisted Domain
```powershell
curl -X POST "http://localhost:8080/api/v1/phishing/scan" `
  -H "Content-Type: application/json" `
  -d '{"url": "https://www.wikipedia.org/wiki/Computer_security"}'
```

**Expected Response Highlights:**
- `verdict.threatLevel`: `"SAFE"`
- `verdict.riskScore`: `0`
- `verdict.verdict`: `"CLEAN_DOMAIN"`

---

### Threat Vector 2: Credential Breach & Password Entropy Analysis

#### Test 2.1: Known Breached Password ($k$-Anonymity Verification)
Evaluates SHA-1 prefix hashing ($k$-anonymity) against HaveIBeenPwned catalog and local digests.

```powershell
curl -X POST "http://localhost:8080/api/v1/breach/password" `
  -H "Content-Type: application/json" `
  -d '{"password": "Password123!"}'
```

**Expected Response Highlights:**
- `verdict.threatLevel`: `"DANGEROUS"`
- `verdict.riskScore`: `100`
- `breached`: `true`
- `breachCount`: $> 100,000$ occurrences
- `entropyScore`: Low rating with pattern detection ("Dictionary word + sequential digits").

#### Test 2.2: High-Entropy Unbreached Passphrase
```powershell
curl -X POST "http://localhost:8080/api/v1/breach/password" `
  -H "Content-Type: application/json" `
  -d '{"password": "C0rrect-H0rse-B@ttery-St@ple-2026!#$"}'
```

**Expected Response Highlights:**
- `verdict.threatLevel`: `"SAFE"`
- `verdict.riskScore`: $\le 15$
- `breached`: `false`
- `entropyBits`: $> 80$ bits entropy.

---

### Threat Vector 3: Synthetic Image Deepfake Forensics

#### Test 3.1: Analysis of Authentic Image with Valid EXIF
```powershell
curl -X POST "http://localhost:8080/api/v1/deepfake/scan" `
  -H "Content-Type: application/json" `
  -d '{"imageBase64": "iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAYAAABytg0kAAAADklEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==", "filename": "sample.png", "mimeType": "image/png"}'
```

**Expected Response Highlights:**
- `metadata.format`: `"PNG"`
- `forensicSignals`: Evaluates Error Level Analysis (ELA), Discrete Quantization Table (DQT), and spatial noise residual.

---

### Threat Vector 4: Video Container & Temporal Forensics

#### Test 4.1: MP4 Video Parsing & Temporal Optical Flow
Submits a synthetic MP4 video container to evaluate inter-frame jitter, structural frame cadence, and temporal optical flow anomalies.

```powershell
curl -X POST "http://localhost:8080/api/v1/deepfake/scan" `
  -H "Content-Type: application/json" `
  -d '{"imageBase64": "AAAAIGZ0eXBpc29tAAACAGlzb21pc28yYXZjMW1wNDEAAAAIZnJlZQAAAA==", "filename": "synthetic_speech.mp4", "mimeType": "video/mp4"}'
```

**Expected Response Highlights:**
- `metadata.format`: `"MP4"`
- `videoTemporalSignals`: Inspects frame presentation timestamps, temporal jitter variance, and keyframe coherence.

---

### Threat Vector 5: Multi-Lingual Synthetic Audio Forensics

#### Test 5.1: Synthetic Voice Audio Detection
Submits a RIFF/WAV audio payload for spectral centroid analysis, high-frequency synthetic roll-off ($> 7.5\text{ kHz}$ attenuation), and robotic pitch flatness across multi-lingual speech.

```powershell
curl -X POST "http://localhost:8080/api/v1/deepfake/scan" `
  -H "Content-Type: application/json" `
  -d '{"imageBase64": "UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQAAAAA=", "filename": "voice_clone.wav", "mimeType": "audio/wav"}'
```

**Expected Response Highlights:**
- `audioForensicSignals.spectralCentroidHz`: Analyzed
- `audioForensicSignals.highFrequencyRolloffAnomalous`: Evaluated
- `audioForensicSignals.syntheticVoiceDetected`: Assessed

---

### Threat Vector 6: Multimodal Fake News & Chyron Forensics

#### Test 6.1: Debunked Viral Hoax (SimHash Near-Duplicate Catalog)
```powershell
curl -X POST "http://localhost:8080/api/v1/misinformation/check" `
  -H "Content-Type: application/json" `
  -d '{"claimText": "UNESCO declares Indian national anthem Jana Gana Mana as best national anthem in the world", "context": "WHATSAPP_FORWARD"}'
```

**Expected Response Highlights:**
- `verdict.threatLevel`: `"DANGEROUS"`
- `verdict.riskScore`: $\ge 90$
- `verdict.verdict`: `"SIMHASH_NEAR_DUPLICATE_DEBUNKED"`
- `simHashMatch.matched`: `true`
- `simHashMatch.similarity`: $\ge 0.85$

#### Test 6.2: Spliced Television News Chyron Hoax
Tests OCR text extraction combined with geometric banner typography analysis for stepped font discontinuities.

```powershell
curl -X POST "http://localhost:8080/api/v1/misinformation/check" `
  -H "Content-Type: application/json" `
  -d '{"claimText": "BREAKING NEWS: Emergency curfew announced across city centers nationwide immediately!!!", "context": "TELEVISION_SCREENSHOT"}'
```

**Expected Response Highlights:**
- `styleAnalysis.capitalisationRatio`: Triggers `"CAPITALISATION_SHOUTING"`
- `styleAnalysis.sensationalPunctuationCount`: Triggers `"SENSATIONAL_PUNCTUATION"`
- `verdict.threatLevel`: `"SUSPICIOUS"` or `"DANGEROUS"`

---

### Threat Vector 7: Cross-Modal Threat Fusion & Incident Ledger

#### Test 7.1: Multi-Modal Incident Correlation
Aggregates independent verdicts from phishing, deepfake, and fake news into a single holistic assessment.

```powershell
curl -X POST "http://localhost:8080/api/v1/fusion/evaluate" `
  -H "Content-Type: application/json" `
  -d '{
    "incidentId": "INC-EVAL-DEMO-001",
    "verdicts": [
      {
        "module": "PHISHING",
        "riskScore": 95,
        "threatLevel": "DANGEROUS",
        "verdict": "CREDENTIAL_HARVESTER",
        "explanation": "Target domain actively mimics banking portal.",
        "signals": [],
        "latencyMs": 1,
        "evaluatedAt": "2026-10-08T12:00:00Z",
        "degraded": false
      },
      {
        "module": "DEEPFAKE",
        "riskScore": 88,
        "threatLevel": "DANGEROUS",
        "verdict": "SYNTHETIC_AVATAR",
        "explanation": "Video exhibits unnatural eye-blink frequency.",
        "signals": [],
        "latencyMs": 12,
        "evaluatedAt": "2026-10-08T12:00:00Z",
        "degraded": false
      }
    ]
  }'
```

**Expected Response Highlights:**
- `compositeScore`: Bounded weighted aggregation ($90–98$)
- `compositeThreatLevel`: `"DANGEROUS"`
- `triggeredRules`: `"MULTI_VECTOR_CORROBORATION"`
- Automatically committed to the cryptographic ledger.

---

## 4. Cryptographic Ledger & Tamper-Evidence Audit

### Step 4.1: Inspect Ledger Chain Head & Ed25519 Signature
```powershell
curl -X GET "http://localhost:8080/api/v1/ledger/head"
```
Returns:
- `sequenceNumber`: Current tip index of the hash chain
- `headChainHash`: SHA-256 digest of the latest block
- `ed25519SignatureHex`: Cryptographic signature over `headChainHash`
- `publicKeyBase64`: TrustShield Ed25519 verification public key

### Step 4.2: Audit Full Ledger Integrity Link-by-Link
```powershell
curl -X GET "http://localhost:8080/api/v1/ledger/verify"
```
Returns:
- `valid`: `true`
- `totalEntriesChecked`: $N$
- `signatureValid`: `true`
- `failureReason`: `"Ledger integrity intact. All hashes and signatures valid."`

---

## 5. Conversational Cyber-Defense Bot Walkthrough

The bot runs as a standalone service (`:8089`) accessible via the Gateway (`:8080/chat.html` or `/api/v1/bot/chat`) as well as direct webhooks.

### Scenario 5.1: Conversational Web Chat Interaction
Open `http://localhost:8080/chat.html` in your browser, or submit via curl:

```powershell
curl -X POST "http://localhost:8080/api/v1/bot/chat" `
  -H "Content-Type: application/json" `
  -d '{"message": "Can you check if this URL is safe? https://secure-bank-login.xyz/verify"}'
```

**Expected Bot Response:**
- Classifies intent as `URL_SCAN`
- Queries Phishing Shield
- Formats markdown explanation with threat score badge, risk indicators, and safety recommendations.

### Scenario 5.2: Simulated WhatsApp Incoming Forward
```powershell
curl -X POST "http://localhost:8080/api/v1/bot/webhook/whatsapp" `
  -H "Content-Type: application/json" `
  -d '{
    "from": "+919876543210",
    "text": "UNESCO declares Indian national anthem as best in the world! Forward to all groups!"
  }'
```

**Expected Bot Response:**
- Classifies as `FAKENEWS_CHECK`
- Identifies debunk from catalog
- Returns concise mobile-optimized message suitable for chat messaging.

---

## 6. Automated Failure Drills & Invariant Verification

Execute TrustShield's automated failure drills suite to verify fault tolerance and safety invariants:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\test_failure_drills.ps1
```

### Verified System Invariants:
1. **Drill 1 (Service Isolation)**:
   - When a downstream microservice is offline, the Gateway returns structured HTTP 503 (`degraded=true`, `error="SERVICE_UNAVAILABLE"`) without collapsing other services or hanging requests.
2. **Drill 2 (Tamper Evidence)**:
   - Modifying a single bit of a ledger record's canonical payload or hash link in storage breaks the SHA-256 chain. `/verify` pinpoints `firstCorruptedIndex` and designates subsequent blocks as unverifiable.
3. **Drill 3 (Destructive Recompression Invariant)**:
   - Submitting a JPEG stripped of forensic artifacts (e.g. recompressed through social messaging platforms) returns `ThreatLevel.UNKNOWN` (`riskScore=0`, `degraded=true`) rather than issuing a false `SAFE` verdict.
4. **Drill 4 (Zero-False-Safe Fact-Check Invariant)**:
   - Unindexed claims with unconfigured or unreachable directories return `ThreatLevel.UNKNOWN` (`riskScore=0`, `degraded=true`), strictly upholding the rule: **unverifiable $\ne$ safe**.

---

## 7. Graceful Platform Shutdown

When demonstration is complete, terminate all microservice background processes cleanly:

```powershell
.\scripts\run-all.ps1 -Stop
```

Verify all ports have been released:
```powershell
.\scripts\run-all.ps1 -Status
```
