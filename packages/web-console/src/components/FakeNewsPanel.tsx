import React, { useState } from 'react';
import { TrustShieldApiClient, ClaimCheckResponse } from '@trustshield/verdict-core';
import { VerdictBadge } from './VerdictBadge.tsx';
import { Newspaper, CheckCircle, AlertOctagon, RefreshCw, Hash } from 'lucide-react';

interface Props {
  client: TrustShieldApiClient;
}

export const FakeNewsPanel: React.FC<Props> = ({ client }) => {
  const [claimText, setClaimText] = useState('UNESCO has declared the Indian national anthem the best in the world!');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ClaimCheckResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const presets = [
    { label: 'UNESCO Anthem Viral', text: 'UNESCO has declared the Indian national anthem the best in the world!' },
    { label: '5G Radiation Conspiracy', text: '5G mobile towers are secretly causing COVID-19 respiratory infections!' },
    { label: 'Free Government Laptop Scheme', text: 'Government is giving free laptops to all students who register at this link.' },
    { label: 'Verified News Item', text: 'ISRO launched Chandrayaan-3 successfully from Sriharikota.' }
  ];

  const handleCheck = async (textToScan?: string) => {
    const text = textToScan || claimText;
    if (!text.trim()) return;

    setLoading(true);
    setError(null);
    try {
      const res = await client.checkClaim({ claimText: text });
      setResult(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Input Header */}
      <div style={{ backgroundColor: 'var(--bg-card)', padding: '1.5rem', borderRadius: '0.75rem', border: '1px solid var(--border-color)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
          <Newspaper style={{ color: 'var(--color-info)' }} size={24} />
          <div>
            <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>Misinformation & Viral Claim Verification Firewall</h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
              Google Fact Check API, multi-source ClaimReview directories, 35-domain publisher credibility, SimHash catalog, and capped style forensics.
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
          <textarea
            rows={3}
            value={claimText}
            onChange={(e) => setClaimText(e.target.value)}
            placeholder="Paste forwarded claim, news headline, or viral WhatsApp message..."
            style={{
              flex: 1,
              minWidth: '280px',
              padding: '0.75rem 1rem',
              backgroundColor: '#0F172A',
              border: '1px solid var(--border-color)',
              borderRadius: '0.5rem',
              color: 'var(--text-main)',
              fontSize: '0.9rem',
              resize: 'vertical'
            }}
          />
          <button
            onClick={() => handleCheck()}
            disabled={loading}
            style={{
              padding: '0.75rem 1.5rem',
              backgroundColor: 'var(--color-info)',
              color: 'white',
              border: 'none',
              borderRadius: '0.5rem',
              fontWeight: 600,
              cursor: loading ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              alignSelf: 'flex-start'
            }}
          >
            {loading ? <RefreshCw className="animate-spin" size={18} /> : <CheckCircle size={18} />}
            {loading ? 'Verifying...' : 'Verify Claim'}
          </button>
        </div>

        {/* Quick Presets */}
        <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.75rem', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', alignSelf: 'center' }}>Test Claims:</span>
          {presets.map((p) => (
            <button
              key={p.label}
              onClick={() => {
                setClaimText(p.text);
                handleCheck(p.text);
              }}
              style={{
                fontSize: '0.75rem',
                padding: '0.25rem 0.5rem',
                backgroundColor: '#1E293B',
                color: '#94A3B8',
                border: '1px solid #334155',
                borderRadius: '0.375rem',
                cursor: 'pointer'
              }}
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div style={{ backgroundColor: 'rgba(239, 68, 68, 0.1)', border: '1px solid #EF4444', padding: '1rem', borderRadius: '0.5rem', color: '#FCA5A5' }}>
          ⚠️ <strong>Verification Error:</strong> {error}
        </div>
      )}

      {/* Results Section */}
      {result && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.5rem' }}>
          {/* Main Verdict Card */}
          <div style={{ backgroundColor: 'var(--bg-card)', padding: '1.5rem', borderRadius: '0.75rem', border: '1px solid var(--border-color)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
              <div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Claim Verdict</span>
                <h3 style={{ fontSize: '1.1rem', fontWeight: 700, marginTop: '0.25rem' }}>{result.verdict.verdict}</h3>
              </div>
              <VerdictBadge verdict={result.verdict} />
            </div>

            <div style={{ padding: '0.75rem', backgroundColor: '#0B0F19', borderRadius: '0.5rem', border: '1px solid #1F2937', marginBottom: '1rem' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Explanation:</div>
              <div style={{ fontSize: '0.9rem', marginTop: '0.25rem' }}>{result.verdict.explanation}</div>
            </div>

            {/* SimHash Card */}
            <div style={{ padding: '0.75rem', backgroundColor: '#1E293B', borderRadius: '0.5rem', border: '1px solid #334155' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '0.75rem', color: '#94A3B8', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                  <Hash size={14} /> 64-bit SimHash Near-Duplicate
                </span>
                <span style={{ fontSize: '0.75rem', fontWeight: 700, color: result.simHashMatch.matched ? '#EF4444' : '#10B981' }}>
                  {result.simHashMatch.matched ? `MATCH (Dist: ${result.simHashMatch.hammingDistance})` : 'NO NEAR-DUPLICATES'}
                </span>
              </div>
              {result.simHashMatch.matched && (
                <div style={{ fontSize: '0.8rem', marginTop: '0.35rem', color: '#E2E8F0' }}>
                  Canonical: {result.simHashMatch.canonicalText}
                </div>
              )}
            </div>
          </div>

          {/* Publisher Credibility & Linguistic Style */}
          <div style={{ backgroundColor: 'var(--bg-card)', padding: '1.5rem', borderRadius: '0.75rem', border: '1px solid var(--border-color)' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '0.75rem' }}>
              Publisher Credibility & Style Capping
            </h3>

            <div style={{ padding: '0.75rem', backgroundColor: '#0F172A', borderRadius: '0.5rem', marginBottom: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontWeight: 600, fontSize: '0.85rem' }}>Domain Credibility:</span>
                <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#38BDF8' }}>
                  {result.publisherCredibility.category}
                </span>
              </div>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                {result.publisherCredibility.rationale}
              </p>
            </div>

            <h4 style={{ fontSize: '0.85rem', fontWeight: 700, marginBottom: '0.5rem', color: '#94A3B8' }}>
              Linguistic Style Forensics (Strict 55-Point Cap)
            </h4>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', fontSize: '0.8rem' }}>
              <div style={{ padding: '0.5rem', backgroundColor: '#1E293B', borderRadius: '0.25rem' }}>
                <span style={{ color: 'var(--text-muted)' }}>Caps Ratio:</span>
                <div style={{ fontWeight: 700 }}>{(result.styleMetrics.capitalisationRatio * 100).toFixed(0)}%</div>
              </div>
              <div style={{ padding: '0.5rem', backgroundColor: '#1E293B', borderRadius: '0.25rem' }}>
                <span style={{ color: 'var(--text-muted)' }}>Sensational Words:</span>
                <div style={{ fontWeight: 700 }}>{result.styleMetrics.sensationalWordCount}</div>
              </div>
              <div style={{ padding: '0.5rem', backgroundColor: '#1E293B', borderRadius: '0.25rem' }}>
                <span style={{ color: 'var(--text-muted)' }}>Punctuation Density:</span>
                <div style={{ fontWeight: 700 }}>{(result.styleMetrics.punctuationDensity * 100).toFixed(1)}%</div>
              </div>
              <div style={{ padding: '0.5rem', backgroundColor: '#1E293B', borderRadius: '0.25rem' }}>
                <span style={{ color: 'var(--text-muted)' }}>Capped Score:</span>
                <div style={{ fontWeight: 700, color: result.styleMetrics.styleScoreCapped >= 55 ? '#F59E0B' : '#10B981' }}>
                  {result.styleMetrics.styleScoreCapped} / 55
                </div>
              </div>
            </div>
          </div>

          {/* ClaimReview Direct Matches */}
          {result.claimReviewMatches && result.claimReviewMatches.length > 0 && (
            <div style={{ gridColumn: '1 / -1', backgroundColor: 'var(--bg-card)', padding: '1.5rem', borderRadius: '0.75rem', border: '1px solid var(--border-color)' }}>
              <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <AlertOctagon size={18} color="#EF4444" />
                Verified ClaimReview Fact-Checker Matches
              </h3>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {result.claimReviewMatches.map((cr, idx) => (
                  <div key={idx} style={{ padding: '0.75rem 1rem', backgroundColor: '#0F172A', borderRadius: '0.5rem', border: '1px solid #334155' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                      <div>
                        <h4 style={{ fontWeight: 700, fontSize: '0.9rem' }}>{cr.claimTitle}</h4>
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                          Fact-checked by <strong>{cr.factCheckerName}</strong> · Claimant: {cr.claimant}
                        </span>
                      </div>
                      <span
                        style={{
                          padding: '0.2rem 0.6rem',
                          borderRadius: '0.25rem',
                          backgroundColor: 'rgba(239, 68, 68, 0.2)',
                          color: '#F87171',
                          fontWeight: 700,
                          fontSize: '0.75rem'
                        }}
                      >
                        {cr.rating}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
