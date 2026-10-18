import React, { useState } from 'react';
import { TrustShieldApiClient, PhishingScanResponse } from '@trustshield/verdict-core';
import { Globe, ShieldAlert, ShieldCheck, RefreshCw, ExternalLink, AlertTriangle } from 'lucide-react';

interface Props {
  client: TrustShieldApiClient;
  onResultChange?: (status: 'idle' | 'safe' | 'danger') => void;
}

export const PhishingPanel: React.FC<Props> = ({ client, onResultChange }) => {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<PhishingScanResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async (targetUrl?: string) => {
    const scanUrl = targetUrl || url;
    if (!scanUrl.trim()) return;

    setLoading(true);
    setError(null);
    try {
      const res = await client.scanUrl(scanUrl);
      setResult(res);
      const isDangerous = res.verdict.threatLevel === 'DANGEROUS' || res.verdict.riskScore >= 70;
      const isSafe = res.verdict.threatLevel === 'SAFE' || res.verdict.threatLevel === 'LOW' || res.verdict.riskScore < 40;
      if (onResultChange) {
        onResultChange(isDangerous ? 'danger' : isSafe ? 'safe' : 'idle');
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  const isSafe = result && (result.verdict.threatLevel === 'SAFE' || result.verdict.threatLevel === 'LOW' || result.verdict.riskScore < 40);
  const isDangerous = result && (result.verdict.threatLevel === 'DANGEROUS' || result.verdict.riskScore >= 70);

  // Format URL nicely for iframe/preview
  const previewTargetUrl = result ? (result.url.startsWith('http://') || result.url.startsWith('https://') ? result.url : `https://${result.url}`) : '';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header Card */}
      <div className="cyber-card" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem', marginBottom: '1.25rem' }}>
          <div style={{ width: '40px', height: '40px', borderRadius: '0.5rem', backgroundColor: 'rgba(14, 165, 233, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', border: '1px solid #0284C7' }}>
            <Globe style={{ color: '#38BDF8' }} size={22} />
          </div>
          <div>
            <h2 style={{ fontSize: '1.25rem', fontWeight: 800, color: '#FFFFFF' }}>Website Safety &amp; Link Checker</h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
              Check whether any link, email offer, or SMS website is safe to open or dangerous.
            </p>
          </div>
        </div>

        {/* Input & Action */}
        <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="Enter the URL"
            onKeyDown={(e) => { if (e.key === 'Enter') handleScan(); }}
            style={{
              flex: 1,
              minWidth: '280px',
              padding: '0.85rem 1.15rem',
              backgroundColor: 'var(--bg-input)',
              border: '1px solid var(--border-color)',
              borderRadius: '0.5rem',
              color: '#FFFFFF',
              fontFamily: 'JetBrains Mono, monospace',
              fontSize: '0.92rem',
              outline: 'none',
              boxShadow: 'inset 0 1px 3px rgba(0, 0, 0, 0.5)'
            }}
          />
          <button
            onClick={() => handleScan()}
            disabled={loading || !url.trim()}
            style={{
              padding: '0.85rem 1.75rem',
              backgroundColor: loading || !url.trim() ? '#1E293B' : '#0284C7',
              color: loading || !url.trim() ? '#64748B' : 'white',
              border: '1px solid #0EA5E9',
              borderRadius: '0.5rem',
              fontWeight: 700,
              fontSize: '0.9rem',
              cursor: loading || !url.trim() ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              boxShadow: loading || !url.trim() ? 'none' : '0 2px 10px rgba(2, 132, 199, 0.4)',
              transition: 'all 0.15s ease'
            }}
          >
            {loading ? <RefreshCw className="animate-spin" size={18} /> : <ShieldAlert size={18} />}
            {loading ? 'Checking...' : 'Check Link'}
          </button>
        </div>
      </div>

      {error && (
        <div style={{ padding: '1rem', backgroundColor: 'var(--color-danger-bg)', border: '1px solid var(--color-danger)', borderRadius: '0.5rem', color: '#FCA5A5', fontSize: '0.875rem' }}>
          ⚠️ <strong>Scan Error:</strong> {error}
        </div>
      )}

      {/* Result Display: Simple Plain English Outcome & Interactive Web Preview */}
      {result && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* Simple Clean Status Banner */}
          <div
            className="cyber-card"
            style={{
              padding: '1.5rem',
              borderLeft: `5px solid ${isSafe ? '#10B981' : isDangerous ? '#EF4444' : '#F59E0B'}`,
              backgroundColor: isSafe ? 'rgba(16, 185, 129, 0.05)' : isDangerous ? 'rgba(239, 68, 68, 0.06)' : 'rgba(245, 158, 11, 0.05)'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
              <div
                style={{
                  width: '54px',
                  height: '54px',
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  backgroundColor: isSafe ? 'rgba(16, 185, 129, 0.2)' : isDangerous ? 'rgba(239, 68, 68, 0.2)' : 'rgba(245, 158, 11, 0.2)',
                  border: `2px solid ${isSafe ? '#10B981' : isDangerous ? '#EF4444' : '#F59E0B'}`
                }}
              >
                {isSafe ? <ShieldCheck size={32} color="#34D399" /> : isDangerous ? <ShieldAlert size={32} color="#F87171" /> : <AlertTriangle size={32} color="#FBBF24" />}
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: '1.35rem', fontWeight: 900, color: isSafe ? '#34D399' : isDangerous ? '#F87171' : '#FBBF24' }}>
                  {isSafe ? '✓ Link is Safe & Secure' : isDangerous ? '✗ Dangerous Phishing Link Detected!' : '⚠️ Caution: Unverified or Suspicious Link'}
                </div>
                <div style={{ fontSize: '0.92rem', color: '#CBD5E1', marginTop: '0.35rem' }}>
                  {isSafe
                    ? 'This link looks legitimate. No phishing signs, malicious deceptive patterns, or fraudulent redirects were detected.'
                    : isDangerous
                    ? 'Do NOT enter any passwords, OTPs, bank credentials, or personal details on this link. It appears designed to steal your information.'
                    : 'This link lacks established reputation or contains misleading domain patterns. Exercise extreme caution before proceeding.'}
                </div>
              </div>
            </div>

            {/* If dangerous, prompt reporting */}
            {isDangerous && (
              <div style={{ marginTop: '1.25rem', padding: '0.85rem 1rem', backgroundColor: 'rgba(239, 68, 68, 0.1)', borderRadius: '0.5rem', border: '1px solid rgba(239, 68, 68, 0.3)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
                <span style={{ fontSize: '0.85rem', color: '#FCA5A5' }}>
                  🚨 <strong>Safety Advisory:</strong> You can report fraudulent links directly to the National Cyber Crime Reporting Portal.
                </span>
                <a
                  href="https://cybercrime.gov.in"
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', color: '#38BDF8', fontSize: '0.85rem', fontWeight: 700, textDecoration: 'none' }}
                >
                  Report to Cyber Crime Portal <ExternalLink size={14} />
                </a>
              </div>
            )}
          </div>

          {/* Interactive Live Link Preview */}
          <div className="cyber-card" style={{ padding: '1.5rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
              <div>
                <h3 style={{ fontSize: '1.05rem', fontWeight: 800, color: '#FFFFFF' }}>Website Live Preview</h3>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                  Target: <span style={{ fontFamily: 'monospace', color: '#38BDF8' }}>{result.url}</span>
                </p>
              </div>
              <a
                href={previewTargetUrl}
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  padding: '0.45rem 0.9rem',
                  backgroundColor: '#1E293B',
                  border: '1px solid #334E68',
                  borderRadius: '0.375rem',
                  color: '#38BDF8',
                  fontSize: '0.8rem',
                  fontWeight: 700,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.4rem',
                  textDecoration: 'none'
                }}
              >
                Open in New Tab <ExternalLink size={14} />
              </a>
            </div>

            {/* Sandbox Container */}
            <div
              style={{
                width: '100%',
                height: '420px',
                backgroundColor: '#0B111E',
                borderRadius: '0.5rem',
                border: '1px solid var(--border-color)',
                overflow: 'hidden',
                position: 'relative'
              }}
            >
              <div
                style={{
                  height: '32px',
                  backgroundColor: '#152238',
                  borderBottom: '1px solid #263852',
                  display: 'flex',
                  alignItems: 'center',
                  padding: '0 0.75rem',
                  gap: '0.5rem'
                }}
              >
                <div style={{ display: 'flex', gap: '4px' }}>
                  <div style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: '#EF4444' }} />
                  <div style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: '#F59E0B' }} />
                  <div style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: '#10B981' }} />
                </div>
                <div
                  style={{
                    flex: 1,
                    backgroundColor: '#0B111E',
                    borderRadius: '4px',
                    height: '20px',
                    fontSize: '0.72rem',
                    color: '#94A3B8',
                    display: 'flex',
                    alignItems: 'center',
                    padding: '0 0.6rem',
                    fontFamily: 'monospace',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap'
                  }}
                >
                  🔒 {previewTargetUrl}
                </div>
              </div>

              {/* Sandboxed iframe preview */}
              <iframe
                src={previewTargetUrl}
                title="Website Preview"
                sandbox="allow-scripts allow-same-origin"
                style={{
                  width: '100%',
                  height: 'calc(100% - 32px)',
                  border: 'none',
                  backgroundColor: '#FFFFFF'
                }}
              />
            </div>
            <p style={{ fontSize: '0.75rem', color: '#64748B', marginTop: '0.6rem', textAlign: 'center' }}>
              Note: Some external websites with strict iframe security policies (X-Frame-Options) may block inline embedding. Use "Open in New Tab" if preview appears blank.
            </p>
          </div>
        </div>
      )}
    </div>
  );
};
