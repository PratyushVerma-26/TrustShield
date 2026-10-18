import React, { useState } from 'react';
import { TrustShieldApiClient, DeepfakeScanResponse } from '@trustshield/verdict-core';
import { Film, Upload, RefreshCw, FileCheck, ShieldAlert, ShieldCheck, ExternalLink, AlertTriangle, PhoneCall } from 'lucide-react';

interface Props {
  client: TrustShieldApiClient;
  onResultChange?: (status: 'idle' | 'safe' | 'danger') => void;
}

export const DeepfakePanel: React.FC<Props> = ({ client, onResultChange }) => {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<DeepfakeScanResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedFilename, setSelectedFilename] = useState<string | null>(null);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setSelectedFilename(file.name);
    const reader = new FileReader();
    reader.onload = async () => {
      const b64 = (reader.result as string).split(',')[1] || '';
      let mType = 'IMAGE';
      if (file.type.startsWith('video/')) mType = 'VIDEO';
      if (file.type.startsWith('audio/')) mType = 'AUDIO';

      setLoading(true);
      setError(null);
      try {
        const res = await client.scanMedia({
          base64: b64,
          filename: file.name,
          mediaType: mType
        });
        setResult(res);
        const isDeepfakeRes = res.verdict.threatLevel === 'DANGEROUS' || res.verdict.riskScore >= 60;
        const isAuthenticRes = res.verdict.threatLevel === 'SAFE' || res.verdict.riskScore < 35;
        if (onResultChange) onResultChange(isDeepfakeRes ? 'danger' : isAuthenticRes ? 'safe' : 'idle');
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setLoading(false);
      }
    };
    reader.readAsDataURL(file);
  };

  const isDeepfake = result && (result.verdict.threatLevel === 'DANGEROUS' || result.verdict.riskScore >= 60);
  const isAuthentic = result && (result.verdict.threatLevel === 'SAFE' || result.verdict.threatLevel === 'LOW' || result.verdict.riskScore < 35);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header */}
      <div className="cyber-card" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem', marginBottom: '1.25rem' }}>
          <div style={{ width: '40px', height: '40px', borderRadius: '0.5rem', backgroundColor: 'rgba(239, 68, 68, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', border: '1px solid #DC2626' }}>
            <Film style={{ color: '#F87171' }} size={22} />
          </div>
          <div>
            <h2 style={{ fontSize: '1.25rem', fontWeight: 800, color: '#FFFFFF' }}>Deepfake &amp; Fake Media Detector</h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
              Check if an image, video, or voice recording is genuine or AI-manipulated/deepfaked.
            </p>
          </div>
        </div>

        {/* Upload Zone */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <label
            style={{
              padding: '1.75rem 2rem',
              backgroundColor: 'var(--bg-input)',
              border: '2px dashed var(--border-light)',
              borderRadius: '0.75rem',
              color: '#FFFFFF',
              fontWeight: 600,
              cursor: loading ? 'not-allowed' : 'pointer',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '0.75rem',
              transition: 'all 0.2s ease',
              textAlign: 'center'
            }}
          >
            <input
              type="file"
              accept="image/*,video/*,audio/*"
              onChange={handleFileUpload}
              disabled={loading}
              style={{ display: 'none' }}
            />
            <div style={{ width: '48px', height: '48px', borderRadius: '50%', backgroundColor: 'rgba(2, 132, 199, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', border: '1px solid #0284C7' }}>
              {loading ? <RefreshCw className="animate-spin" size={24} color="#38BDF8" /> : <Upload size={24} color="#38BDF8" />}
            </div>
            <div>
              <div style={{ fontSize: '1rem', fontWeight: 800, color: '#F8FAFC' }}>
                {loading ? 'Analyzing Media for AI Tampering...' : 'Click or Tap to Upload Photo, Video, or Audio'}
              </div>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                Supports photos (JPG, PNG), video clips (MP4, AVI), and audio recordings (WAV, MP3)
              </div>
            </div>
            {selectedFilename && (
              <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem', backgroundColor: '#1E293B', padding: '0.35rem 0.85rem', borderRadius: '9999px', fontSize: '0.8rem', color: '#38BDF8', border: '1px solid #334E68', marginTop: '0.25rem' }}>
                <FileCheck size={14} />
                <span>Selected: {selectedFilename}</span>
              </div>
            )}
          </label>
        </div>
      </div>

      {error && (
        <div style={{ padding: '1rem', backgroundColor: 'var(--color-danger-bg)', border: '1px solid var(--color-danger)', borderRadius: '0.5rem', color: '#FCA5A5', fontSize: '0.875rem' }}>
          ⚠️ <strong>Analysis Error:</strong> {error}
        </div>
      )}

      {/* Forensic Results: Clear Plain English & Direct Reporting Pathways */}
      {result && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <div
            className="cyber-card"
            style={{
              padding: '1.5rem',
              borderLeft: `5px solid ${isAuthentic ? '#10B981' : isDeepfake ? '#EF4444' : '#F59E0B'}`,
              backgroundColor: isAuthentic ? 'rgba(16, 185, 129, 0.05)' : isDeepfake ? 'rgba(239, 68, 68, 0.06)' : 'rgba(245, 158, 11, 0.05)'
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
                  backgroundColor: isAuthentic ? 'rgba(16, 185, 129, 0.2)' : isDeepfake ? 'rgba(239, 68, 68, 0.2)' : 'rgba(245, 158, 11, 0.2)',
                  border: `2px solid ${isAuthentic ? '#10B981' : isDeepfake ? '#EF4444' : '#F59E0B'}`
                }}
              >
                {isAuthentic ? <ShieldCheck size={32} color="#34D399" /> : isDeepfake ? <ShieldAlert size={32} color="#F87171" /> : <AlertTriangle size={32} color="#FBBF24" />}
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: '1.35rem', fontWeight: 900, color: isAuthentic ? '#34D399' : isDeepfake ? '#F87171' : '#FBBF24' }}>
                  {isAuthentic ? '✓ Natural & Genuine Media' : isDeepfake ? '✗ AI Deepfake / Synthetic Tampering Detected!' : '⚠️ Inconclusive / Heavily Re-compressed File'}
                </div>
                <div style={{ fontSize: '0.92rem', color: '#CBD5E1', marginTop: '0.35rem' }}>
                  {isAuthentic
                    ? 'This file exhibits authentic organic camera sensor noise and natural biometric acoustic flow. No signs of generative AI synthesis.'
                    : isDeepfake
                    ? 'This media shows telltale signs of AI facial synthesis, unnatural robotic pitch micro-tremors, or generative video editing. It is not authentic.'
                    : 'The file has been repeatedly compressed or degraded over messaging apps. Treat this media with skepticism until verified by primary news sources.'}
                </div>
              </div>
            </div>

            {/* Reporting Guide for Common Users */}
            {isDeepfake && (
              <div style={{ marginTop: '1.5rem', paddingTop: '1.25rem', borderTop: '1px solid rgba(239, 68, 68, 0.3)' }}>
                <h4 style={{ fontSize: '1rem', fontWeight: 800, color: '#FFFFFF', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  📢 How to Report this Deepfake to Law Enforcement &amp; Authorities:
                </h4>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '0.85rem' }}>
                  {/* Option 1: National Cyber Crime Portal */}
                  <div style={{ backgroundColor: '#152238', padding: '1rem', borderRadius: '0.5rem', border: '1px solid #263852', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    <div style={{ fontWeight: 800, color: '#F8FAFC', fontSize: '0.95rem' }}>
                      1. National Cyber Crime Reporting Portal
                    </div>
                    <div style={{ fontSize: '0.82rem', color: '#94A3B8' }}>
                      Official Government portal for cyber fraud, impersonation, and non-consensual deepfakes.
                    </div>
                    <div style={{ marginTop: 'auto', paddingTop: '0.5rem' }}>
                      <a
                        href="https://cybercrime.gov.in"
                        target="_blank"
                        rel="noopener noreferrer"
                        style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', color: '#38BDF8', fontSize: '0.85rem', fontWeight: 700, textDecoration: 'none' }}
                      >
                        Visit cybercrime.gov.in <ExternalLink size={14} />
                      </a>
                    </div>
                  </div>

                  {/* Option 2: Cyber Crime Helpline */}
                  <div style={{ backgroundColor: '#152238', padding: '1rem', borderRadius: '0.5rem', border: '1px solid #263852', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    <div style={{ fontWeight: 800, color: '#F8FAFC', fontSize: '0.95rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                      <PhoneCall size={16} color="#34D399" /> 2. National Helpline: 1930
                    </div>
                    <div style={{ fontSize: '0.82rem', color: '#94A3B8' }}>
                      Toll-free 24x7 cyber fraud and extortion emergency helpline run by the Ministry of Home Affairs (MHA).
                    </div>
                    <div style={{ marginTop: 'auto', paddingTop: '0.5rem', color: '#34D399', fontWeight: 800, fontSize: '0.85rem' }}>
                      Dial 1930 immediately
                    </div>
                  </div>

                  {/* Option 3: Social Media Platform Grievance Officer */}
                  <div style={{ backgroundColor: '#152238', padding: '1rem', borderRadius: '0.5rem', border: '1px solid #263852', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    <div style={{ fontWeight: 800, color: '#F8FAFC', fontSize: '0.95rem' }}>
                      3. Report on Social Media Platform
                    </div>
                    <div style={{ fontSize: '0.82rem', color: '#94A3B8' }}>
                      Under IT Rules, platforms must remove synthetic impersonations within 24–36 hours of user complaint. Use the in-app "Report" button &rarr; "Misleading / Deepfake".
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
