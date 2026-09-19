import React, { useState } from 'react';
import { TrustShieldApiClient, IncidentFusionResponse, ModuleVerdict, ThreatLevel } from '@trustshield/verdict-core';
import { VerdictBadge } from './VerdictBadge.tsx';
import { Layers, Play, RefreshCw } from 'lucide-react';

interface Props {
  client: TrustShieldApiClient;
}

export const FusionPanel: React.FC<Props> = ({ client }) => {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<IncidentFusionResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Editable scenario inputs
  const [phishingLevel, setPhishingLevel] = useState<ThreatLevel>('SUSPICIOUS');
  const [phishingScore, setPhishingScore] = useState(65);

  const [deepfakeLevel, setDeepfakeLevel] = useState<ThreatLevel>('SUSPICIOUS');
  const [deepfakeScore, setDeepfakeScore] = useState(60);

  const [fakeNewsLevel, setFakeNewsLevel] = useState<ThreatLevel>('SAFE');
  const [fakeNewsScore, setFakeNewsScore] = useState(10);

  const [ledgerVerified, setLedgerVerified] = useState(true);

  const handleEvaluate = async (customVerdicts?: ModuleVerdict[], customLedger?: boolean) => {
    setLoading(true);
    setError(null);

    const isLedgerOk = customLedger !== undefined ? customLedger : ledgerVerified;

    const verdicts: ModuleVerdict[] = customVerdicts || [
      {
        module: 'PHISHING',
        riskScore: phishingScore,
        threatLevel: phishingLevel,
        verdict: `${phishingLevel}_URL`,
        explanation: `Phishing module assessed ${phishingLevel} risk.`,
        signals: [],
        latencyMs: 5,
        evaluatedAt: new Date().toISOString(),
        degraded: phishingLevel === 'UNKNOWN'
      },
      {
        module: 'DEEPFAKE',
        riskScore: deepfakeScore,
        threatLevel: deepfakeLevel,
        verdict: `${deepfakeLevel}_MEDIA`,
        explanation: `Deepfake module assessed ${deepfakeLevel} risk.`,
        signals: [],
        latencyMs: 8,
        evaluatedAt: new Date().toISOString(),
        degraded: deepfakeLevel === 'UNKNOWN'
      },
      {
        module: 'FAKENEWS',
        riskScore: fakeNewsScore,
        threatLevel: fakeNewsLevel,
        verdict: `${fakeNewsLevel}_CLAIM`,
        explanation: `Misinformation module assessed ${fakeNewsLevel} risk.`,
        signals: [],
        latencyMs: 12,
        evaluatedAt: new Date().toISOString(),
        degraded: fakeNewsLevel === 'UNKNOWN'
      }
    ];

    try {
      const res = await client.evaluateFusion(verdicts, isLedgerOk);
      setResult(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  // Rule test presets
  const applyPreset = (rule: 'R1' | 'R2' | 'R3' | 'R4' | 'R5') => {
    if (rule === 'R1') {
      setPhishingLevel('DANGEROUS');
      setPhishingScore(95);
      setDeepfakeLevel('SAFE');
      setDeepfakeScore(5);
      setFakeNewsLevel('SAFE');
      setFakeNewsScore(5);
      setLedgerVerified(true);
    } else if (rule === 'R2') {
      setPhishingLevel('SUSPICIOUS');
      setPhishingScore(65);
      setDeepfakeLevel('SUSPICIOUS');
      setDeepfakeScore(60);
      setFakeNewsLevel('SAFE');
      setFakeNewsScore(10);
      setLedgerVerified(true);
    } else if (rule === 'R3') {
      setPhishingLevel('SAFE');
      setPhishingScore(5);
      setDeepfakeLevel('UNKNOWN');
      setDeepfakeScore(0);
      setFakeNewsLevel('SAFE');
      setFakeNewsScore(5);
      setLedgerVerified(true);
    } else if (rule === 'R4') {
      setPhishingLevel('SAFE');
      setPhishingScore(5);
      setDeepfakeLevel('SAFE');
      setDeepfakeScore(5);
      setFakeNewsLevel('SAFE');
      setFakeNewsScore(5);
      setLedgerVerified(false);
    } else if (rule === 'R5') {
      setPhishingLevel('SUSPICIOUS');
      setPhishingScore(65);
      setDeepfakeLevel('DANGEROUS');
      setDeepfakeScore(85);
      setFakeNewsLevel('SAFE');
      setFakeNewsScore(5);
      setLedgerVerified(true);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header */}
      <div style={{ backgroundColor: 'var(--bg-card)', padding: '1.5rem', borderRadius: '0.75rem', border: '1px solid var(--border-color)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
          <Layers style={{ color: '#A855F7' }} size={24} />
          <div>
            <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>Cross-Modal Threat Aggregation & Fusion Playground</h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
              Deterministic, auditable evaluation of Canonical Rules R1–R5 over heterogeneous threat signals.
            </p>
          </div>
        </div>

        {/* Rule Scenarios Presets */}
        <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', alignSelf: 'center' }}>Rule Presets:</span>
          <button onClick={() => { applyPreset('R1'); }} style={presetBtnStyle}>R1: Conclusive Dangerous</button>
          <button onClick={() => { applyPreset('R2'); }} style={presetBtnStyle}>R2: Multi-Modal Escalation</button>
          <button onClick={() => { applyPreset('R3'); }} style={presetBtnStyle}>R3: Coverage Invariant (UNKNOWN)</button>
          <button onClick={() => { applyPreset('R4'); }} style={{ ...presetBtnStyle, borderColor: '#EF4444', color: '#F87171' }}>R4: Ledger Tamper Override</button>
          <button onClick={() => { applyPreset('R5'); }} style={presetBtnStyle}>R5: Coordinated Attack Multiplier</button>
        </div>

        {/* Modality Vector Controls */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginBottom: '1.25rem' }}>
          {/* Phishing Selector */}
          <div style={{ padding: '0.75rem', backgroundColor: '#0F172A', borderRadius: '0.5rem', border: '1px solid #1E293B' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600 }}>Phishing Modality</span>
            <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.4rem' }}>
              <select
                value={phishingLevel}
                onChange={(e) => setPhishingLevel(e.target.value as ThreatLevel)}
                style={selectStyle}
              >
                <option value="DANGEROUS">DANGEROUS</option>
                <option value="SUSPICIOUS">SUSPICIOUS</option>
                <option value="SAFE">SAFE</option>
                <option value="UNKNOWN">UNKNOWN</option>
              </select>
              <input
                type="number"
                min={0}
                max={100}
                value={phishingScore}
                onChange={(e) => setPhishingScore(Number(e.target.value))}
                style={scoreInputStyle}
              />
            </div>
          </div>

          {/* Deepfake Selector */}
          <div style={{ padding: '0.75rem', backgroundColor: '#0F172A', borderRadius: '0.5rem', border: '1px solid #1E293B' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600 }}>Deepfake Modality</span>
            <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.4rem' }}>
              <select
                value={deepfakeLevel}
                onChange={(e) => setDeepfakeLevel(e.target.value as ThreatLevel)}
                style={selectStyle}
              >
                <option value="DANGEROUS">DANGEROUS</option>
                <option value="SUSPICIOUS">SUSPICIOUS</option>
                <option value="SAFE">SAFE</option>
                <option value="UNKNOWN">UNKNOWN</option>
              </select>
              <input
                type="number"
                min={0}
                max={100}
                value={deepfakeScore}
                onChange={(e) => setDeepfakeScore(Number(e.target.value))}
                style={scoreInputStyle}
              />
            </div>
          </div>

          {/* Fake News Selector */}
          <div style={{ padding: '0.75rem', backgroundColor: '#0F172A', borderRadius: '0.5rem', border: '1px solid #1E293B' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600 }}>Fake News Modality</span>
            <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.4rem' }}>
              <select
                value={fakeNewsLevel}
                onChange={(e) => setFakeNewsLevel(e.target.value as ThreatLevel)}
                style={selectStyle}
              >
                <option value="DANGEROUS">DANGEROUS</option>
                <option value="SUSPICIOUS">SUSPICIOUS</option>
                <option value="SAFE">SAFE</option>
                <option value="UNKNOWN">UNKNOWN</option>
              </select>
              <input
                type="number"
                min={0}
                max={100}
                value={fakeNewsScore}
                onChange={(e) => setFakeNewsScore(Number(e.target.value))}
                style={scoreInputStyle}
              />
            </div>
          </div>

          {/* Ledger Integrity State */}
          <div style={{ padding: '0.75rem', backgroundColor: '#0F172A', borderRadius: '0.5rem', border: '1px solid #1E293B' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600 }}>Audit Ledger Integrity</span>
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '0.5rem', cursor: 'pointer', fontSize: '0.85rem' }}>
              <input
                type="checkbox"
                checked={ledgerVerified}
                onChange={(e) => setLedgerVerified(e.target.checked)}
                style={{ width: '1.1rem', height: '1.1rem', accentColor: '#10B981' }}
              />
              <span style={{ color: ledgerVerified ? '#10B981' : '#EF4444', fontWeight: 700 }}>
                {ledgerVerified ? 'Verified Authentic' : 'TAMPER DETECTED'}
              </span>
            </label>
          </div>
        </div>

        <button
          onClick={() => handleEvaluate()}
          disabled={loading}
          style={{
            padding: '0.75rem 1.75rem',
            backgroundColor: '#9333EA',
            color: 'white',
            border: 'none',
            borderRadius: '0.5rem',
            fontWeight: 700,
            cursor: loading ? 'not-allowed' : 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem'
          }}
        >
          {loading ? <RefreshCw className="animate-spin" size={18} /> : <Play size={18} />}
          {loading ? 'Evaluating Fusion Rules...' : 'Evaluate Cross-Modal Incident'}
        </button>
      </div>

      {error && (
        <div style={{ backgroundColor: 'rgba(239, 68, 68, 0.1)', border: '1px solid #EF4444', padding: '1rem', borderRadius: '0.5rem', color: '#FCA5A5' }}>
          ⚠️ <strong>Fusion Error:</strong> {error}
        </div>
      )}

      {/* Results Section */}
      {result && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.5rem' }}>
          {/* Aggregate Verdict Summary Card */}
          <div style={{ backgroundColor: 'var(--bg-card)', padding: '1.5rem', borderRadius: '0.75rem', border: '1px solid var(--border-color)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
              <div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Synthesized Incident Outcome</span>
                <h3 style={{ fontSize: '1.2rem', fontWeight: 700, marginTop: '0.25rem' }}>
                  {result.aggregateVerdict.verdict}
                </h3>
              </div>
              <VerdictBadge verdict={result.aggregateVerdict} />
            </div>

            <div style={{ padding: '0.75rem', backgroundColor: '#0B0F19', borderRadius: '0.5rem', border: '1px solid #1F2937', marginBottom: '1rem' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Incident Synthesis Explanation:</div>
              <div style={{ fontSize: '0.9rem', marginTop: '0.25rem' }}>{result.aggregateVerdict.explanation}</div>
            </div>

            {/* Invariant R3 Alert */}
            {result.safeDisallowedByUnknown && (
              <div className="hatched-unmeasured" style={{ padding: '0.75rem', borderRadius: '0.5rem', marginBottom: '1rem' }}>
                <div style={{ color: '#FBBF24', fontWeight: 700, fontSize: '0.85rem' }}>
                  ⚠️ Rule R3 Active: SAFE Designation Strictly Disallowed
                </div>
                <p style={{ fontSize: '0.75rem', color: '#CBD5E1', marginTop: '0.25rem' }}>
                  At least one modality evaluated as UNKNOWN or degraded. TrustShield coverage invariant guarantees unmeasured components cannot produce a SAFE incident verdict.
                </p>
              </div>
            )}

            {/* Invariant R4 Alert */}
            {!result.ledgerVerified && (
              <div style={{ padding: '0.75rem', borderRadius: '0.5rem', backgroundColor: 'rgba(239, 68, 68, 0.2)', border: '1px solid #EF4444', marginBottom: '1rem' }}>
                <div style={{ color: '#F87171', fontWeight: 700, fontSize: '0.85rem' }}>
                  🚨 Rule R4 Active: Cryptographic Ledger Tamper Override
                </div>
                <p style={{ fontSize: '0.75rem', color: '#FCA5A5', marginTop: '0.25rem' }}>
                  Ledger verification failed! Incident score forcefully escalated to DANGEROUS (95) regardless of clean scanner outputs.
                </p>
              </div>
            )}
          </div>

          {/* Fired Rules Card */}
          <div style={{ backgroundColor: 'var(--bg-card)', padding: '1.5rem', borderRadius: '0.75rem', border: '1px solid var(--border-color)' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '0.75rem' }}>
              Auditable Canonical Rules (R1–R5) Status
            </h3>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
              {result.firedRules.map((rule) => (
                <div
                  key={rule.ruleId}
                  style={{
                    padding: '0.6rem 0.75rem',
                    backgroundColor: '#0F172A',
                    borderRadius: '0.375rem',
                    border: `1px solid ${rule.fired ? '#9333EA' : '#1F2937'}`
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontWeight: 700, fontSize: '0.85rem', color: rule.fired ? '#C084FC' : '#94A3B8' }}>
                      {rule.ruleName}
                    </span>
                    <span
                      style={{
                        fontSize: '0.7rem',
                        fontWeight: 700,
                        padding: '0.15rem 0.5rem',
                        borderRadius: '0.25rem',
                        backgroundColor: rule.fired ? 'rgba(147, 51, 234, 0.3)' : 'rgba(75, 85, 99, 0.2)',
                        color: rule.fired ? '#E9D5FF' : '#9CA3AF'
                      }}
                    >
                      {rule.fired ? 'FIRED' : 'PASSED'}
                    </span>
                  </div>
                  <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                    {rule.rationale}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

const presetBtnStyle: React.CSSProperties = {
  fontSize: '0.75rem',
  padding: '0.25rem 0.5rem',
  backgroundColor: '#1E293B',
  color: '#E2E8F0',
  border: '1px solid #334155',
  borderRadius: '0.375rem',
  cursor: 'pointer'
};

const selectStyle: React.CSSProperties = {
  flex: 1,
  padding: '0.35rem 0.5rem',
  backgroundColor: '#111827',
  border: '1px solid #374151',
  borderRadius: '0.25rem',
  color: 'white',
  fontSize: '0.8rem'
};

const scoreInputStyle: React.CSSProperties = {
  width: '60px',
  padding: '0.35rem 0.5rem',
  backgroundColor: '#111827',
  border: '1px solid #374151',
  borderRadius: '0.25rem',
  color: 'white',
  fontFamily: 'monospace',
  fontSize: '0.8rem'
};
