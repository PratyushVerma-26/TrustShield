import React, { useState } from 'react';
import { TrustShieldApiClient, ClaimCheckResponse } from '@trustshield/verdict-core';
import { Newspaper, CheckCircle2, ShieldAlert, ShieldCheck, RefreshCw, Upload, FileText, Image as ImageIcon, FileCheck, ExternalLink, AlertTriangle } from 'lucide-react';

interface Props {
  client: TrustShieldApiClient;
  onResultChange?: (status: 'idle' | 'safe' | 'danger') => void;
}

export const FakeNewsPanel: React.FC<Props> = ({ client, onResultChange }) => {
  const [mode, setMode] = useState<'text' | 'media'>('text');
  const [claimText, setClaimText] = useState('');
  const [mediaFile, setMediaFile] = useState<{ name: string; base64: string; type: string } | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ClaimCheckResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleTextCheck = async () => {
    if (!claimText.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const res = await client.checkClaim({ claimText });
      setResult(res);
      const isFake = res.verdict.threatLevel === 'DANGEROUS' || res.verdict.riskScore >= 60;
      const isTrue = res.verdict.threatLevel === 'SAFE' || res.verdict.threatLevel === 'LOW' || res.verdict.riskScore < 35;
      if (onResultChange) onResultChange(isFake ? 'danger' : isTrue ? 'safe' : 'idle');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  const handleMediaUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = () => {
      const b64 = (reader.result as string).split(',')[1] || '';
      let mType = 'IMAGE';
      if (file.type.startsWith('video/')) mType = 'VIDEO';

      setMediaFile({
        name: file.name,
        base64: b64,
        type: mType
      });
    };
    reader.readAsDataURL(file);
  };

  const handleMediaCheck = async () => {
    if (!mediaFile) return;
    setLoading(true);
    setError(null);
    try {
      const res = await client.checkClaim({
        claimText: claimText || `Visual news media analysis for ${mediaFile.name}`,
        mediaBase64: mediaFile.base64,
        mediaType: mediaFile.type
      });
      setResult(res);
      const isFake = res.verdict.threatLevel === 'DANGEROUS' || res.verdict.riskScore >= 60;
      const isTrue = res.verdict.threatLevel === 'SAFE' || res.verdict.threatLevel === 'LOW' || res.verdict.riskScore < 35;
      if (onResultChange) onResultChange(isFake ? 'danger' : isTrue ? 'safe' : 'idle');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  const isFakeNews = result && (result.verdict.threatLevel === 'DANGEROUS' || result.verdict.riskScore >= 60);
  const isVerifiedTrue = result && (result.verdict.threatLevel === 'SAFE' || result.verdict.threatLevel === 'LOW' || result.verdict.riskScore < 35);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header */}
      <div className="cyber-card" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem', marginBottom: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
            <div style={{ width: '40px', height: '40px', borderRadius: '0.5rem', backgroundColor: 'rgba(2, 132, 199, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', border: '1px solid #0284C7' }}>
              <Newspaper style={{ color: '#38BDF8' }} size={22} />
            </div>
            <div>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 800, color: '#FFFFFF' }}>Fake News &amp; Rumor Fact-Checker</h2>
              <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                Verify viral WhatsApp messages, social media news clips, rumors, and claims before believing or sharing.
              </p>
            </div>
          </div>

          {/* Mode Switcher */}
          <div style={{ display: 'flex', backgroundColor: 'var(--bg-input)', padding: '0.3rem', borderRadius: '0.5rem', border: '1px solid var(--border-color)' }}>
            <button
              onClick={() => { setMode('text'); setError(null); }}
              style={{
                padding: '0.45rem 1.15rem',
                borderRadius: '0.375rem',
                border: 'none',
                backgroundColor: mode === 'text' ? 'var(--color-info)' : 'transparent',
                color: mode === 'text' ? '#fff' : 'var(--text-muted)',
                fontWeight: 800,
                fontSize: '0.82rem',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
                transition: 'all 0.15s ease'
              }}
            >
              <FileText size={15} />
              Text Claim
            </button>
            <button
              onClick={() => { setMode('media'); setError(null); }}
              style={{
                padding: '0.45rem 1.15rem',
                borderRadius: '0.375rem',
                border: 'none',
                backgroundColor: mode === 'media' ? 'var(--color-info)' : 'transparent',
                color: mode === 'media' ? '#fff' : 'var(--text-muted)',
                fontWeight: 800,
                fontSize: '0.82rem',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
                transition: 'all 0.15s ease'
              }}
            >
              <ImageIcon size={15} />
              Image / Video News
            </button>
          </div>
        </div>

        {/* Text Mode Input */}
        {mode === 'text' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <textarea
              value={claimText}
              onChange={(e) => setClaimText(e.target.value)}
              placeholder="Paste the news message, claim, or viral rumor you want to check..."
              rows={3}
              style={{
                width: '100%',
                padding: '0.85rem 1.15rem',
                backgroundColor: 'var(--bg-input)',
                border: '1px solid var(--border-color)',
                borderRadius: '0.5rem',
                color: '#FFFFFF',
                fontSize: '0.92rem',
                outline: 'none',
                resize: 'vertical',
                boxShadow: 'inset 0 1px 3px rgba(0, 0, 0, 0.5)'
              }}
            />
            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button
                onClick={handleTextCheck}
                disabled={loading || !claimText.trim()}
                style={{
                  padding: '0.85rem 2rem',
                  backgroundColor: loading || !claimText.trim() ? '#1E293B' : '#8B5CF6',
                  color: loading || !claimText.trim() ? '#64748B' : 'white',
                  border: '1px solid #7C3AED',
                  borderRadius: '0.5rem',
                  fontWeight: 800,
                  fontSize: '0.9rem',
                  cursor: loading || !claimText.trim() ? 'not-allowed' : 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  boxShadow: loading || !claimText.trim() ? 'none' : '0 2px 10px rgba(139, 92, 246, 0.4)',
                  transition: 'all 0.15s ease'
                }}
              >
                {loading ? <RefreshCw className="animate-spin" size={18} /> : <CheckCircle2 size={18} />}
                {loading ? 'Fact-Checking...' : 'Check Claim'}
              </button>
            </div>
          </div>
        )}

        {/* Media Mode Input */}
        {mode === 'media' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <label
              style={{
                padding: '1.5rem',
                backgroundColor: 'var(--bg-input)',
                border: '2px dashed var(--border-light)',
                borderRadius: '0.75rem',
                color: '#FFFFFF',
                cursor: loading ? 'not-allowed' : 'pointer',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '0.65rem',
                transition: 'all 0.2s ease',
                textAlign: 'center'
              }}
            >
              <input
                type="file"
                accept="image/*,video/*"
                onChange={handleMediaUpload}
                disabled={loading}
                style={{ display: 'none' }}
              />
              <div style={{ width: '44px', height: '44px', borderRadius: '50%', backgroundColor: 'rgba(2, 132, 199, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', border: '1px solid #0284C7' }}>
                <Upload size={22} color="#38BDF8" />
              </div>
              <div>
                <div style={{ fontSize: '0.95rem', fontWeight: 800, color: '#F8FAFC' }}>
                  Upload News Screenshot, Clipping, or Video
                </div>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
                  Extracts text and checks against official fact-checking databases
                </div>
              </div>
              {mediaFile && (
                <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem', backgroundColor: '#1E293B', padding: '0.35rem 0.85rem', borderRadius: '9999px', fontSize: '0.8rem', color: '#38BDF8', border: '1px solid #334E68', marginTop: '0.25rem' }}>
                  <FileCheck size={14} />
                  <span>Attached: {mediaFile.name}</span>
                </div>
              )}
            </label>

            <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
              <input
                type="text"
                value={claimText}
                onChange={(e) => setClaimText(e.target.value)}
                placeholder="Optional: Enter caption or headline from this image/video..."
                style={{
                  flex: 1,
                  minWidth: '280px',
                  padding: '0.8rem 1rem',
                  backgroundColor: 'var(--bg-input)',
                  border: '1px solid var(--border-color)',
                  borderRadius: '0.5rem',
                  color: '#FFFFFF',
                  fontSize: '0.88rem',
                  outline: 'none'
                }}
              />
              <button
                onClick={handleMediaCheck}
                disabled={loading || !mediaFile}
                style={{
                  padding: '0.8rem 1.75rem',
                  backgroundColor: loading || !mediaFile ? '#1E293B' : 'var(--color-info)',
                  color: loading || !mediaFile ? '#64748B' : 'white',
                  border: '1px solid #0EA5E9',
                  borderRadius: '0.5rem',
                  fontWeight: 800,
                  fontSize: '0.9rem',
                  cursor: loading || !mediaFile ? 'not-allowed' : 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  boxShadow: loading || !mediaFile ? 'none' : '0 2px 10px rgba(2, 132, 199, 0.4)',
                  transition: 'all 0.15s ease'
                }}
              >
                {loading ? <RefreshCw className="animate-spin" size={18} /> : <CheckCircle2 size={18} />}
                {loading ? 'Checking...' : 'Check Media'}
              </button>
            </div>
          </div>
        )}
      </div>

      {error && (
        <div style={{ padding: '1rem', backgroundColor: 'var(--color-danger-bg)', border: '1px solid var(--color-danger)', borderRadius: '0.5rem', color: '#FCA5A5', fontSize: '0.875rem' }}>
          ⚠️ <strong>Verification Error:</strong> {error}
        </div>
      )}

      {/* Result Display: Simple Plain English Outcome & Reporting Guide */}
      {result && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <div
            className="cyber-card"
            style={{
              padding: '1.5rem',
              borderLeft: `5px solid ${isVerifiedTrue ? '#10B981' : isFakeNews ? '#EF4444' : '#F59E0B'}`,
              backgroundColor: isVerifiedTrue ? 'rgba(16, 185, 129, 0.05)' : isFakeNews ? 'rgba(239, 68, 68, 0.06)' : 'rgba(245, 158, 11, 0.05)'
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
                  backgroundColor: isVerifiedTrue ? 'rgba(16, 185, 129, 0.2)' : isFakeNews ? 'rgba(239, 68, 68, 0.2)' : 'rgba(245, 158, 11, 0.2)',
                  border: `2px solid ${isVerifiedTrue ? '#10B981' : isFakeNews ? '#EF4444' : '#F59E0B'}`
                }}
              >
                {isVerifiedTrue ? <ShieldCheck size={32} color="#34D399" /> : isFakeNews ? <ShieldAlert size={32} color="#F87171" /> : <AlertTriangle size={32} color="#FBBF24" />}
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: '1.35rem', fontWeight: 900, color: isVerifiedTrue ? '#34D399' : isFakeNews ? '#F87171' : '#FBBF24' }}>
                  {isVerifiedTrue ? '✓ Genuine / Verified Information' : isFakeNews ? '✗ False / Debunked Fake News Detected!' : '⚠️ Unverified Rumor / Caution Advised'}
                </div>
                <div style={{ fontSize: '0.92rem', color: '#CBD5E1', marginTop: '0.35rem' }}>
                  {isVerifiedTrue
                    ? 'This claim matches authenticated news sources or trusted public records. It appears accurate.'
                    : isFakeNews
                    ? 'Official fact-checkers and news sources have debunked this claim. Please do not forward or spread this message in chats.'
                    : 'This claim is circulating without confirmation from verified news agencies or government press bureaus. Treat it as an unverified rumor.'}
                </div>
              </div>
            </div>

            {/* Reporting Guide for Fake News */}
            {isFakeNews && (
              <div style={{ marginTop: '1.5rem', paddingTop: '1.25rem', borderTop: '1px solid rgba(239, 68, 68, 0.3)' }}>
                <h4 style={{ fontSize: '1rem', fontWeight: 800, color: '#FFFFFF', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  📢 How to Report this Fake News / Misinformation:
                </h4>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '0.85rem' }}>
                  {/* PIB Fact Check */}
                  <div style={{ backgroundColor: '#152238', padding: '1rem', borderRadius: '0.5rem', border: '1px solid #263852', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    <div style={{ fontWeight: 800, color: '#F8FAFC', fontSize: '0.95rem' }}>
                      1. PIB Fact Check (Govt of India)
                    </div>
                    <div style={{ fontSize: '0.82rem', color: '#94A3B8' }}>
                      For government schemes, viral circulars, policies, and exams: Send via WhatsApp to <strong>+91 8799711259</strong> or email <strong>pibfactcheck@gmail.com</strong>.
                    </div>
                    <div style={{ marginTop: 'auto', paddingTop: '0.5rem' }}>
                      <a
                        href="https://factcheck.pib.gov.in"
                        target="_blank"
                        rel="noopener noreferrer"
                        style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', color: '#38BDF8', fontSize: '0.85rem', fontWeight: 700, textDecoration: 'none' }}
                      >
                        Visit PIB Fact Check <ExternalLink size={14} />
                      </a>
                    </div>
                  </div>

                  {/* National Cyber Crime Reporting Portal */}
                  <div style={{ backgroundColor: '#152238', padding: '1rem', borderRadius: '0.5rem', border: '1px solid #263852', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    <div style={{ fontWeight: 800, color: '#F8FAFC', fontSize: '0.95rem' }}>
                      2. Cyber Crime Reporting Portal
                    </div>
                    <div style={{ fontSize: '0.82rem', color: '#94A3B8' }}>
                      If the misinformation incites violence, public disorder, or financial panic, report it directly under IT Act provisions.
                    </div>
                    <div style={{ marginTop: 'auto', paddingTop: '0.5rem' }}>
                      <a
                        href="https://cybercrime.gov.in"
                        target="_blank"
                        rel="noopener noreferrer"
                        style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', color: '#38BDF8', fontSize: '0.85rem', fontWeight: 700, textDecoration: 'none' }}
                      >
                        File Report Online <ExternalLink size={14} />
                      </a>
                    </div>
                  </div>

                  {/* WhatsApp / Messaging Flag */}
                  <div style={{ backgroundColor: '#152238', padding: '1rem', borderRadius: '0.5rem', border: '1px solid #263852', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    <div style={{ fontWeight: 800, color: '#F8FAFC', fontSize: '0.95rem' }}>
                      3. Stop the Spread in Groups
                    </div>
                    <div style={{ fontSize: '0.82rem', color: '#94A3B8' }}>
                      Reply in the group or chat with a note that this message is debunked fake news so others do not get misled. Report the sender to platform moderators.
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
