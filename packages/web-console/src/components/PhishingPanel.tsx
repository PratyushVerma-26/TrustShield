import React, { useState } from 'react';
import { TrustShieldApiClient, PhishingScanResponse } from '@trustshield/verdict-core';
import { VerdictBadge } from './VerdictBadge.tsx';
import { Globe, ShieldAlert, CheckCircle2, RefreshCw } from 'lucide-react';

interface Props {
  client: TrustShieldApiClient;
}

export const PhishingPanel: React.FC<Props> = ({ client }) => {
  const [url, setUrl] = useState('https://sbi-verification-login.tk/auth');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<PhishingScanResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const presets = [
    { label: 'State Bank Phish', url: 'https://sbi-verification-login.tk/auth' },
    { label: 'PayPal Update', url: 'https://paypal-security-update.xyz/verify' },
    { label: 'Legitimate Domain', url: 'https://google.com' },
    { label: 'Unindexed IP URL', url: 'http://192.168.1.100/login.html' }
  ];

  const handleScan = async (targetUrl?: string) => {
    const scanUrl = targetUrl || url;
    if (!scanUrl.trim()) return;

    setLoading(true);
    setError(null);
    try {
      const res = await client.scanUrl(scanUrl);
      setResult(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header card */}
      <div style={{ backgroundColor: 'var(--bg-card)', padding: '1.5rem', borderRadius: '0.75rem', border: '1px solid var(--border-color)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
          <Globe style={{ color: 'var(--color-info)' }} size={24} />
          <div>
            <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>Phishing & Malicious Website Shield</h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
              26-feature lexical classification with Google Safe Browsing and VirusTotal reputation enrichment.
            </p>
          </div>
        </div>

        {/* Search input & action */}
        <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="Enter URL to assess (e.g., https://sbi-verification.tk)..."
            style={{
              flex: 1,
              minWidth: '280px',
              padding: '0.75rem 1rem',
              backgroundColor: '#0F172A',
              border: '1px solid var(--border-color)',
              borderRadius: '0.5rem',
              color: 'var(--text-main)',
              fontFamily: 'monospace',
              fontSize: '0.9rem'
            }}
          />
          <button
            onClick={() => handleScan()}
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
              gap: '0.5rem'
            }}
          >
            {loading ? <RefreshCw className="animate-spin" size={18} /> : <ShieldAlert size={18} />}
            {loading ? 'Scanning...' : 'Scan URL'}
          </button>
        </div>

        {/* Quick Presets */}
        <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.75rem', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', alignSelf: 'center' }}>Presets:</span>
          {presets.map((p) => (
            <button
              key={p.label}
              onClick={() => {
                setUrl(p.url);
                handleScan(p.url);
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
          ⚠️ <strong>Scan Error:</strong> {error}
        </div>
      )}

      {/* Result Cards */}
      {result && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.5rem' }}>
          {/* Main Verdict Card */}
          <div style={{ backgroundColor: 'var(--bg-card)', padding: '1.5rem', borderRadius: '0.75rem', border: '1px solid var(--border-color)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
              <div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Scan Outcome</span>
                <h3 style={{ fontSize: '1.1rem', fontWeight: 700, fontFamily: 'monospace', wordBreak: 'break-all', marginTop: '0.25rem' }}>
                  {result.url}
                </h3>
              </div>
              <VerdictBadge verdict={result.verdict} />
            </div>

            <div style={{ margin: '1rem 0', padding: '0.75rem', backgroundColor: '#0B0F19', borderRadius: '0.5rem', border: '1px solid #1F2937' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Analysis Summary:</div>
              <div style={{ fontSize: '0.9rem', marginTop: '0.25rem' }}>{result.verdict.explanation}</div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', fontSize: '0.8rem' }}>
              <div style={{ padding: '0.5rem', backgroundColor: '#1E293B', borderRadius: '0.375rem' }}>
                <span style={{ color: 'var(--text-muted)' }}>Model Version:</span>
                <div style={{ fontWeight: 600 }}>{result.model.version}</div>
              </div>
              <div style={{ padding: '0.5rem', backgroundColor: '#1E293B', borderRadius: '0.375rem' }}>
                <span style={{ color: 'var(--text-muted)' }}>Provenance:</span>
                <div style={{ fontWeight: 600, color: result.model.trained ? '#10B981' : '#F59E0B' }}>
                  {result.model.provenance}
                </div>
              </div>
            </div>
          </div>

          {/* External Reputation Sources Card */}
          <div style={{ backgroundColor: 'var(--bg-card)', padding: '1.5rem', borderRadius: '0.75rem', border: '1px solid var(--border-color)' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <CheckCircle2 size={18} color="var(--color-info)" />
              External Threat Intelligence
            </h3>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {result.reputation.map((rep) => (
                <div
                  key={rep.source}
                  style={{
                    padding: '0.75rem',
                    backgroundColor: '#0F172A',
                    borderRadius: '0.5rem',
                    border: `1px solid ${rep.status === 'MALICIOUS' ? '#EF4444' : rep.status === 'CLEAN' ? '#10B981' : '#475569'}`
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontWeight: 600, fontSize: '0.85rem' }}>{rep.source}</span>
                    <span
                      style={{
                        fontSize: '0.7rem',
                        fontWeight: 700,
                        padding: '0.15rem 0.5rem',
                        borderRadius: '0.25rem',
                        backgroundColor: rep.status === 'MALICIOUS' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(16, 185, 129, 0.2)',
                        color: rep.status === 'MALICIOUS' ? '#F87171' : '#34D399'
                      }}
                    >
                      {rep.status}
                    </span>
                  </div>
                  <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>{rep.detail}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Lexical Feature Attributions Card */}
          <div style={{ gridColumn: '1 / -1', backgroundColor: 'var(--bg-card)', padding: '1.5rem', borderRadius: '0.75rem', border: '1px solid var(--border-color)' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '0.75rem' }}>
              Lexical Feature Explainability (Top Contributions)
            </h3>
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', textAlign: 'left' }}>
                    <th style={{ padding: '0.5rem' }}>Feature</th>
                    <th style={{ padding: '0.5rem' }}>Meaning</th>
                    <th style={{ padding: '0.5rem' }}>Z-Score</th>
                    <th style={{ padding: '0.5rem' }}>Logit Contribution</th>
                    <th style={{ padding: '0.5rem' }}>Direction</th>
                  </tr>
                </thead>
                <tbody>
                  {result.topFeatures.map((f) => (
                    <tr key={f.feature} style={{ borderBottom: '1px solid #1F2937' }}>
                      <td style={{ padding: '0.5rem', fontFamily: 'monospace', fontWeight: 600 }}>{f.feature}</td>
                      <td style={{ padding: '0.5rem', color: 'var(--text-muted)' }}>{f.description}</td>
                      <td style={{ padding: '0.5rem', fontFamily: 'monospace' }}>{f.standardised.toFixed(2)}</td>
                      <td style={{ padding: '0.5rem', fontFamily: 'monospace', color: f.logitDelta > 0 ? '#EF4444' : '#10B981' }}>
                        {f.logitDelta > 0 ? `+${f.logitDelta.toFixed(3)}` : f.logitDelta.toFixed(3)}
                      </td>
                      <td style={{ padding: '0.5rem' }}>
                        <span
                          style={{
                            fontSize: '0.7rem',
                            fontWeight: 700,
                            padding: '0.15rem 0.4rem',
                            borderRadius: '0.25rem',
                            backgroundColor: f.logitDelta > 0 ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                            color: f.logitDelta > 0 ? '#F87171' : '#34D399'
                          }}
                        >
                          {f.logitDelta > 0 ? 'RISK ELEVATING' : 'BENIGN REDUCING'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
