/**
 * Canonical types and discriminated unions for TrustShield threat intelligence.
 */

export type ThreatLevel = 'DANGEROUS' | 'SUSPICIOUS' | 'SAFE' | 'LOW' | 'UNKNOWN';

export type ModuleType = 'PHISHING' | 'DEEPFAKE' | 'BREACH' | 'FAKENEWS' | 'FUSION';

export interface ThreatSignal {
  name: string;
  description: string;
  weight: number;
  triggered: boolean;
  rawEvidence?: string | null;
}

export interface ModuleVerdict {
  module: ModuleType;
  riskScore: number;
  threatLevel: ThreatLevel;
  verdict: string;
  explanation: string;
  signals: ThreatSignal[];
  latencyMs: number;
  evaluatedAt: string;
  degraded: boolean;
}

/**
 * Discriminated union over verdict state.
 *
 * Enforces that an inconclusive result (ThreatLevel UNKNOWN or missing inputs)
 * can NEVER be passed into components or methods that render SAFE presentation.
 */
export interface ConclusiveVerdict {
  isConclusive: true;
  module: ModuleType;
  threatLevel: 'DANGEROUS' | 'SUSPICIOUS' | 'SAFE' | 'LOW';
  riskScore: number;
  verdict: string;
  explanation: string;
  signals: ThreatSignal[];
  latencyMs: number;
  evaluatedAt: string;
  degraded: boolean;
}

export interface InconclusiveVerdict {
  isConclusive: false;
  module: ModuleType;
  threatLevel: 'UNKNOWN';
  riskScore: 0;
  verdict: string;
  explanation: string;
  signals: ThreatSignal[];
  latencyMs: number;
  evaluatedAt: string;
  degraded: true;
  reason?: string;
}

export interface NotApplicableVerdict {
  isConclusive: false;
  module: ModuleType;
  threatLevel: 'UNKNOWN';
  riskScore: 0;
  verdict: 'NOT_APPLICABLE';
  explanation: string;
  signals: ThreatSignal[];
  latencyMs: number;
  evaluatedAt: string;
  degraded: true;
}

export type Verdict = ConclusiveVerdict | InconclusiveVerdict | NotApplicableVerdict;

/**
 * Normalizes any ModuleVerdict from backend JSON into the typed Verdict discriminated union.
 */
export function normalizeVerdict(v: ModuleVerdict): Verdict {
  if (v.threatLevel === 'UNKNOWN' || v.degraded && v.riskScore === 0) {
    if (v.verdict === 'NOT_APPLICABLE') {
      return {
        ...v,
        isConclusive: false,
        threatLevel: 'UNKNOWN',
        riskScore: 0,
        verdict: 'NOT_APPLICABLE',
        degraded: true
      };
    }
    return {
      ...v,
      isConclusive: false,
      threatLevel: 'UNKNOWN',
      riskScore: 0,
      degraded: true
    };
  }

  return {
    ...v,
    isConclusive: true,
    threatLevel: v.threatLevel as 'DANGEROUS' | 'SUSPICIOUS' | 'SAFE' | 'LOW',
    riskScore: Math.max(0, Math.min(100, v.riskScore))
  };
}

/* ========================================================================== */
/* Module-Specific Responses                                                  */
/* ========================================================================== */

// Phishing Module
export interface FeatureAttribution {
  feature: string;
  description: string;
  standardised: number;
  logitDelta: number;
}

export interface ReputationVerdict {
  source: string;
  status: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | 'UNKNOWN' | 'ERROR';
  scoreContribution: number;
  detail: string;
}

export interface PhishingScanResponse {
  scanId: number;
  url: string;
  verdict: ModuleVerdict;
  model: {
    version: string;
    provenance: string;
    trained: boolean;
    probability: number;
    logit: number;
  };
  reputation: ReputationVerdict[];
  topFeatures: FeatureAttribution[];
}

// Breach Module
export interface StrengthAssessment {
  length: number;
  entropy: number;
  weaknessScore: number;
  hasSpecialChars: boolean;
  hasDigits: boolean;
  hasMixedCase: boolean;
}

export interface BreachSourceOutcome {
  source: string;
  status: 'EXPOSED' | 'NOT_FOUND' | 'UNAVAILABLE';
  occurrences: number | null;
  detail: string;
}

export interface PasswordCheckResponse {
  verdict: ModuleVerdict;
  recommendation: string;
  strength: StrengthAssessment;
  sourcesConsulted: BreachSourceOutcome[];
  kAnonymous: boolean;
  bucketPrefix: string;
}

export interface EmailCheckResponse {
  verdict: ModuleVerdict;
  email: string;
  breachCount: number;
  breaches: Array<{
    name: string;
    title: string;
    domain: string;
    breachDate: string;
    pwnCount: number;
    description: string;
    dataClasses: string[];
    isVerified: boolean;
  }>;
  recommendations: string[];
}

// Deepfake Module
export interface ImageMetadata {
  filename: string;
  format: string;
  width: number;
  height: number;
  sizeBytes: number;
  hasExif: boolean;
  cameraModel: string | null;
  software: string | null;
  hasC2paManifest: boolean;
}

export interface ForensicSignals {
  elaVariance: number;
  quantisationTableAnomalous: boolean;
  quantisationTableFingerprint: string;
  spatialBlockinessScore: number;
  noiseResidualVariance: number;
  metadataInconsistent: boolean;
  c2paDetected: boolean;
  recompressionDetected: boolean;
}

export interface AudioForensicSignals {
  audioAnalyzed: boolean;
  syntheticVoiceScore: number;
  spectralCutoffDetected: boolean;
  roboticPitchScore: number;
  breathingPauseRatio: number;
  detectedCadence: string;
}

export interface VideoTemporalSignals {
  videoAnalyzed: boolean;
  frameCount: number;
  temporalJitterScore: number;
  frameConsistencyScore: number;
  containerSoftware: string | null;
}

export interface DeepfakeScanResponse {
  incidentId: { value: string };
  verdict: ModuleVerdict;
  metadata: ImageMetadata;
  forensicSignals: ForensicSignals;
  audioSignals: AudioForensicSignals;
  videoSignals: VideoTemporalSignals;
  directoryResult: {
    consulted: boolean;
    matchFound: boolean;
    catalogSource: string | null;
    authenticityFlag: string | null;
    registryUrl: string | null;
  };
}

// Fake News / Misinformation Module
export interface ClaimReviewMatch {
  claimant: string;
  claimDate: string;
  claimTitle: string;
  rating: string;
  factCheckerName: string;
  reviewUrl: string;
  confidence: number;
}

export interface PublisherCredibility {
  domain: string;
  category: 'MAINSTREAM_RELIABLE' | 'PROPAGANDA' | 'SATIRE' | 'UNINDEXED';
  credibilityScore: number;
  rationale: string;
}

export interface LinguisticStyleMetrics {
  capitalisationRatio: number;
  punctuationDensity: number;
  sensationalWordCount: number;
  absolutistRatio: number;
  styleScoreRaw: number;
  styleScoreCapped: number;
}

export interface ClaimCheckResponse {
  incidentId: { value: string };
  verdict: ModuleVerdict;
  claimReviewMatches: ClaimReviewMatch[];
  publisherCredibility: PublisherCredibility;
  simHashMatch: {
    matched: boolean;
    catalogId: string | null;
    canonicalText: string | null;
    hammingDistance: number;
  };
  styleMetrics: LinguisticStyleMetrics;
}

// Cross-Modal Threat Fusion Module
export interface FusionRuleResult {
  ruleId: string;
  ruleName: string;
  fired: boolean;
  resultingLevel: ThreatLevel;
  rationale: string;
}

export interface IncidentFusionResponse {
  incidentId: { value: string };
  aggregateVerdict: ModuleVerdict;
  firedRules: FusionRuleResult[];
  contributions: Record<ModuleType, ModuleVerdict>;
  coverageMap: Record<ModuleType, boolean>;
  ledgerVerified: boolean;
  safeDisallowedByUnknown: boolean;
}

// Cryptographic Integrity Ledger
export interface LedgerEntry {
  sequenceNumber: number;
  entryHash: string;
  previousChainHash: string;
  cumulativeChainHash: string;
  module: ModuleType;
  incidentId: string;
  timestamp: string;
  signatureHex: string;
}

export interface LedgerVerifyResponse {
  valid: boolean;
  totalEntries: number;
  headChainHash: string;
  firstCorruptedIndex: number | null;
  message: string;
}

// Bot Module
export interface BotMessageRequest {
  incidentId?: { value: string };
  channel?: 'WHATSAPP' | 'TELEGRAM' | 'WEB_CHAT';
  senderId?: string;
  messageText?: string;
  mediaType?: 'IMAGE' | 'VIDEO' | 'AUDIO' | 'NONE';
  mediaBase64?: string;
  mediaFilename?: string;
}

export interface BotMessageResponse {
  incidentId: { value: string };
  channel: string;
  recipientId: string;
  replyText: string;
  threatLevel: ThreatLevel;
  riskScore: number;
  primaryCategory: string;
  recommendations: string[];
  latencyMs: number;
}
