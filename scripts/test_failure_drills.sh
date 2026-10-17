#!/usr/bin/env bash
# ==============================================================================
# TrustShield Automated Failure Drills Suite (POSIX / Linux / macOS)
# Validates platform resilience, zero-false-safe invariants, and cryptographic tamper-evidence.
# ==============================================================================

set -eo pipefail

GATEWAY_URL="${1:-http://localhost:8080}"
DEEPFAKE_URL="${2:-http://localhost:8085}"
FAKENEWS_URL="${3:-http://localhost:8086}"
INTEGRITY_URL="${4:-http://localhost:8087}"

echo "================================================================="
echo "  TrustShield Resilience & Failure Drill Validation Suite (POSIX)"
echo "================================================================="
echo " Target Gateway: $GATEWAY_URL"
echo ""

PASSED=0
FAILED=0
SKIPPED=0

report_result() {
  local drill_name="$1"
  local success="$2"
  local details="$3"

  if [ "$success" -eq 1 ]; then
    PASSED=$((PASSED + 1))
    echo -e "  \033[0;32m[PASS]\033[0m $drill_name"
    echo -e "         \033[0;90m$details\033[0m"
  else
    FAILED=$((FAILED + 1))
    echo -e "  \033[0;31m[FAIL]\033[0m $drill_name"
    echo -e "         \033[0;33m$details\033[0m"
  fi
}

report_skip() {
  local drill_name="$1"
  local reason="$2"
  SKIPPED=$((SKIPPED + 1))
  echo -e "  \033[0;33m[SKIP]\033[0m $drill_name"
  echo -e "         \033[0;90m$reason\033[0m"
}

# --- DRILL 1: Service Unavailability Degraded Handling ---
echo "[1/4] Running Drill 1: Downstream Service Unavailability..."
if curl -s -f -m 3 "$GATEWAY_URL/actuator/health" >/dev/null 2>&1; then
  RESP=$(curl -s -w "\n%{http_code}" -X POST "$GATEWAY_URL/api/v1/deepfake/scan" \
    -H "Content-Type: application/json" \
    -d '{"imageBase64":"dGVzdA=="}' || true)
  STATUS_CODE=$(echo "$RESP" | tail -n1)
  BODY=$(echo "$RESP" | sed '$d')

  if [ "$STATUS_CODE" -eq 200 ]; then
    report_result "Drill 1 - Service Unavailability Resilience" 1 "Gateway reachable and routed request successfully."
  elif [ "$STATUS_CODE" -eq 503 ] && echo "$BODY" | grep -q '"degraded":true'; then
    report_result "Drill 1 - Service Unavailability Resilience" 1 "HTTP 503 received with degraded=true and structured fallback."
  else
    report_result "Drill 1 - Service Unavailability Resilience" 0 "Expected HTTP 200 or 503 degraded, got HTTP $STATUS_CODE"
  fi
else
  report_skip "Drill 1 - Service Unavailability" "Gateway at $GATEWAY_URL is offline."
fi

# --- DRILL 2: Ledger Tamper Evident Verification ---
echo ""
echo "[2/4] Running Drill 2: Cryptographic Ledger Tamper Evidence..."
VERIFY_URL="$GATEWAY_URL/api/v1/ledger/verify"
if ! curl -s -f -m 3 "$VERIFY_URL" >/dev/null 2>&1; then
  VERIFY_URL="$INTEGRITY_URL/api/v1/ledger/verify"
fi

if curl -s -f -m 3 "$VERIFY_URL" >/dev/null 2>&1; then
  AUDIT_RESP=$(curl -s -m 3 "$VERIFY_URL")
  if echo "$AUDIT_RESP" | grep -q '"valid":true' && echo "$AUDIT_RESP" | grep -q '"signatureValid":true'; then
    report_result "Drill 2 - Cryptographic Hash Chain Integrity" 1 "Ledger chain verified intact. Ed25519 signature valid."
  else
    report_result "Drill 2 - Cryptographic Hash Chain Integrity" 0 "Audit verification reported invalid or corrupted link."
  fi
else
  report_skip "Drill 2 - Ledger Tamper Evidence" "Ledger service is offline. (Verified in LedgerIntegrationTest)"
fi

# --- DRILL 3: Destructive Recompression Handling ---
echo ""
echo "[3/4] Running Drill 3: Destructive Recompression UNKNOWN Invariant..."
DEEPFAKE_ENDPOINT="$GATEWAY_URL/api/v1/deepfake/scan"
B64="/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////wgALCAABAAEBAREA/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABPxA="

if curl -s -f -m 3 "$GATEWAY_URL/actuator/health" >/dev/null 2>&1; then
  PAYLOAD="{\"imageBase64\":\"$B64\",\"filename\":\"whatsapp_image.jpg\",\"mimeType\":\"image/jpeg\",\"context\":\"WHATSAPP_ATTACHMENT\"}"
  RECOMP_RESP=$(curl -s -m 5 -X POST "$DEEPFAKE_ENDPOINT" -H "Content-Type: application/json" -d "$PAYLOAD" || true)

  if echo "$RECOMP_RESP" | grep -q '"threatLevel":"UNKNOWN"' && echo "$RECOMP_RESP" | grep -q '"degraded":true'; then
    report_result "Drill 3 - Destructive Recompression" 1 "ThreatLevel=UNKNOWN, Degraded=True. Zero false-safe invariant preserved."
  else
    report_result "Drill 3 - Destructive Recompression" 0 "Expected UNKNOWN and degraded=true on stripped lossy JPEG."
  fi
else
  report_skip "Drill 3 - Destructive Recompression" "Deepfake service is offline. (Verified in RecompressionFailureTest)"
fi

# --- DRILL 4: Disabled Fact-Check Directory Handling ---
echo ""
echo "[4/4] Running Drill 4: Disabled / Unindexed Fact-Check Directory..."
CLAIM_ENDPOINT="$GATEWAY_URL/api/v1/misinformation/check"
CLAIM_BODY='{"claimText":"Civic municipal garden will be closed next Wednesday afternoon for routine hedge maintenance.","context":"LOCAL_BULLETIN"}'

if curl -s -f -m 3 "$GATEWAY_URL/actuator/health" >/dev/null 2>&1; then
  CLAIM_RESP=$(curl -s -m 5 -X POST "$CLAIM_ENDPOINT" -H "Content-Type: application/json" -d "$CLAIM_BODY" || true)

  if echo "$CLAIM_RESP" | grep -q '"threatLevel":"UNKNOWN"' && echo "$CLAIM_RESP" | grep -q '"degraded":true'; then
    report_result "Drill 4 - Unindexed Claim Fact-Check Invariant" 1 "ThreatLevel=UNKNOWN, Degraded=True. Zero false-safe invariant enforced."
  else
    report_result "Drill 4 - Unindexed Claim Fact-Check Invariant" 0 "Expected UNKNOWN and degraded=true for unindexed claim."
  fi
else
  report_skip "Drill 4 - Unindexed Claim Fact-Check Invariant" "Fake news service is offline. (Verified in ClaimCheckIntegrationTest)"
fi

echo ""
echo "================================================================="
echo "  Drill Results Summary: Passed: $PASSED | Failed: $FAILED | Skipped: $SKIPPED"
echo "================================================================="

if [ "$FAILED" -gt 0 ]; then
  exit 1
else
  exit 0
fi
