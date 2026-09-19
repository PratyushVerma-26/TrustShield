import React, { useState } from 'react';
import { TrustShieldApiClient, DeepfakeScanResponse } from '@trustshield/verdict-core';
import { VerdictBadge } from './VerdictBadge.tsx';
import { Film, Image as ImageIcon, Volume2, AlertTriangle, Upload } from 'lucide-react';

interface Props {
  client: TrustShieldApiClient;
}

export const DeepfakePanel: React.FC<Props> = ({ client }) => {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<DeepfakeScanResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedFilename, setSelectedFilename] = useState('minister_announcement.mp4');

  // Sample synthetic media presets
  const samples = [
    {
      label: 'Deepfake Video (Voice Clone)',
      filename: 'minister_speech_spliced.mp4',
      mediaType: 'VIDEO',
      base64: 'AAAAIGZ0eXBtcDQyAAAAAG1wNDJpc29tYXZjMQAA'
    },
    {
      label: 'Tampered Face Swap (JPEG)',
      filename: 'face_swap_manipulated.jpg',
      mediaType: 'IMAGE',
      base64: '/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAAMCAgMCAgMDAwMEAwMEBQgF'
    },
    {
      label: 'Clean Authentic Photo (C2PA)',
      filename: 'press_conference_verified.jpg',
      mediaType: 'IMAGE',
      base64: '/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAUDBAQEAwUEBAQFBQUGBwwG'
    },
    {
      label: 'Recompressed WhatsApp Image',
      filename: 'whatsapp_lossy_forward.jpg',
      mediaType: 'IMAGE',
      base64: '/9j/4AAQSkZJRgABAgAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQN'
    }
  ];

  const handleScanSample = async (sample: typeof samples[0]) => {
    setSelectedFilename(sample.filename);
    setLoading(true);
    setError(null);
    try {
      const res = await client.scanMedia({
        base64: sample.base64,
        filename: sample.filename,
        mediaType: sample.mediaType
      });
      setResult(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

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
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setLoading(false);
      }
    };
    reader.readAsDataURL(file);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header */}
      <div style={{ backgroundColor: 'var(--bg-card)', padding: '1.5rem', borderRadius: '0.75rem', border: '1px solid var(--border-color)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
          <Film style={{ color: 'var(--color-danger)' }} size={24} />
          <div>
            <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>Deepfake & Synthetic Media Forensic Detector</h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
              ISO BMFF temporal analysis, biophysics audio forensics (spectral roll-off, robotic pitch micro-tremor), and 6 inspectable visual signals.
            </p>
          </div>
        </div>

        {/* Upload and Sample Buttons */}
        <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', alignItems: 'center' }}>
          <label
            style={{
              padding: '0.75rem 1.5rem',
              backgroundColor: '#1E293B',
              color: '#38BDF8',
              border: '1px dashed #0284C7',
              borderRadius: '0.5rem',
              fontWeight: 600,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem'
            }}
          >
            <Upload size={18} />
            Upload File (Image/Video/Audio)
            <input type="file" onChange={handleFileUpload} style={{ display: 'none' }} accept="image/*,video/*,audio/*" />
          </label>

          <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>or choose benchmark test sample:</span>
          {samples.map((s) => (
            <button
              key={s.label}
              onClick={() => handleScanSample(s)}
              disabled={loading}
              style={{
                fontSize: '0.75rem',
                padding: '0.5rem 0.75rem',
                backgroundColor: '#0F172A',
                color: '#E2E8F0',
                border: '1px solid #334155',
                borderRadius: '0.375rem',
                cursor: loading ? 'not-allowed' : 'pointer'
              }}
            >
              {s.label}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div style={{ backgroundColor: 'rgba(239, 68, 68, 0.1)', border: '1px solid #EF4444', padding: '1rem', borderRadius: '0.5rem', color: '#FCA5A5' }}>
          ⚠️ <strong>Forensic Error:</strong> {error}
        </div>
      )}

      {/* Results Section */}
      {result && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.5rem' }}>
          {/* Main Verdict Summary */}
          <div style={{ backgroundColor: 'var(--bg-card)', padding: '1.5rem', borderRadius: '0.75rem', border: '1px solid var(--border-color)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
              <div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Assessed File</span>
                <h3 style={{ fontSize: '1.1rem', fontWeight: 700, fontFamily: 'monospace' }}>{selectedFilename}</h3>
              </div>
              <VerdictBadge verdict={result.verdict} />
            </div>

            <div style={{ padding: '0.75rem', backgroundColor: '#0B0F19', borderRadius: '0.5rem', border: '1px solid #1F2937', marginBottom: '1rem' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Forensic Verdict Note:</div>
              <div style={{ fontSize: '0.9rem', marginTop: '0.25rem' }}>{result.verdict.explanation}</div>
            </div>

            {/* Invariant Note if Recompressed */}
            {result.forensicSignals.recompressionDetected && (
              <div className="hatched-unmeasured" style={{ padding: '0.75rem', borderRadius: '0.5rem', marginBottom: '1rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#FBBF24', fontWeight: 700, fontSize: '0.85rem' }}>
                  <AlertTriangle size={16} />
                  Recompression Detected (Refusal to Certify)
                </div>
                <p style={{ fontSize: '0.75rem', color: '#CBD5E1', marginTop: '0.25rem' }}>
                  Lossy recompression destroyed fine sensor noise residuals. TrustShield strictly reports UNKNOWN and warns the evaluator rather than calling it clean.
                </p>
              </div>
            )}

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', fontSize: '0.8rem' }}>
              <div style={{ padding: '0.5rem', backgroundColor: '#1E293B', borderRadius: '0.375rem' }}>
                <span style={{ color: 'var(--text-muted)' }}>Resolution:</span>
                <div>{result.metadata.width} × {result.metadata.height}</div>
              </div>
              <div style={{ padding: '0.5rem', backgroundColor: '#1E293B', borderRadius: '0.375rem' }}>
                <span style={{ color: 'var(--text-muted)' }}>Format:</span>
                <div>{result.metadata.format}</div>
              </div>
            </div>
          </div>

          {/* Visual Forensics Card */}
          <div style={{ backgroundColor: 'var(--bg-card)', padding: '1.5rem', borderRadius: '0.75rem', border: '1px solid var(--border-color)' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <ImageIcon size={18} color="#F59E0B" />
              Visual Forensics (6 Classical Signals)
            </h3>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', fontSize: '0.8rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.5rem', backgroundColor: '#0F172A', borderRadius: '0.375rem' }}>
                <span>ELA Variance:</span>
                <span style={{ fontFamily: 'monospace', fontWeight: 700 }}>{result.forensicSignals.elaVariance.toFixed(2)}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.5rem', backgroundColor: '#0F172A', borderRadius: '0.375rem' }}>
                <span>DQT Table Anomaly:</span>
                <span style={{ fontWeight: 700, color: result.forensicSignals.quantisationTableAnomalous ? '#EF4444' : '#10B981' }}>
                  {result.forensicSignals.quantisationTableAnomalous ? 'ANOMALOUS (NON-STANDARD)' : 'STANDARD'}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.5rem', backgroundColor: '#0F172A', borderRadius: '0.375rem' }}>
                <span>Spatial 8x8 Blockiness:</span>
                <span style={{ fontFamily: 'monospace', fontWeight: 700 }}>{result.forensicSignals.spatialBlockinessScore.toFixed(3)}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.5rem', backgroundColor: '#0F172A', borderRadius: '0.375rem' }}>
                <span>Noise Residual Variance:</span>
                <span style={{ fontFamily: 'monospace', fontWeight: 700 }}>{result.forensicSignals.noiseResidualVariance.toFixed(2)}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.5rem', backgroundColor: '#0F172A', borderRadius: '0.375rem' }}>
                <span>C2PA Manifest:</span>
                <span style={{ fontWeight: 700, color: result.forensicSignals.c2paDetected ? '#10B981' : '#64748B' }}>
                  {result.forensicSignals.c2paDetected ? 'AUTHENTIC CONTENT CREDENTIALS' : 'NOT PRESENT'}
                </span>
              </div>
            </div>
          </div>

          {/* Multimodal Acoustic & Temporal Card */}
          <div style={{ gridColumn: '1 / -1', backgroundColor: 'var(--bg-card)', padding: '1.5rem', borderRadius: '0.75rem', border: '1px solid var(--border-color)' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Volume2 size={18} color="#38BDF8" />
              Multimodal Temporal Video & Acoustic Biophysics Forensics
            </h3>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1rem' }}>
              {/* Video metrics */}
              <div style={{ padding: '0.75rem', backgroundColor: '#0F172A', borderRadius: '0.5rem' }}>
                <h4 style={{ fontSize: '0.85rem', fontWeight: 700, color: '#38BDF8', marginBottom: '0.5rem' }}>
                  Video ISO BMFF Temporal Analysis
                </h4>
                <div style={{ fontSize: '0.8rem', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span>Analyzed:</span>
                    <span>{result.videoSignals.videoAnalyzed ? 'YES' : 'NO'}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span>Frame Count:</span>
                    <span style={{ fontFamily: 'monospace' }}>{result.videoSignals.frameCount}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span>Temporal Jitter:</span>
                    <span style={{ fontFamily: 'monospace' }}>{result.videoSignals.temporalJitterScore.toFixed(3)}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span>Frame Consistency:</span>
                    <span style={{ fontFamily: 'monospace' }}>{result.videoSignals.frameConsistencyScore.toFixed(3)}</span>
                  </div>
                </div>
              </div>

              {/* Audio metrics */}
              <div style={{ padding: '0.75rem', backgroundColor: '#0F172A', borderRadius: '0.5rem' }}>
                <h4 style={{ fontSize: '0.85rem', fontWeight: 700, color: '#A855F7', marginBottom: '0.5rem' }}>
                  Acoustic Speech Forensics
                </h4>
                <div style={{ fontSize: '0.8rem', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span>Analyzed:</span>
                    <span>{result.audioSignals.audioAnalyzed ? 'YES' : 'NO'}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span>Synthetic Voice Score:</span>
                    <span style={{ fontFamily: 'monospace', fontWeight: 700 }}>{result.audioSignals.syntheticVoiceScore.toFixed(2)}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span>Spectral Roll-off:</span>
                    <span>{result.audioSignals.spectralCutoffDetected ? 'SYNTHETIC CUTOFF' : 'NATURAL'}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span>Robotic Pitch Micro-tremor:</span>
                    <span style={{ fontFamily: 'monospace' }}>{result.audioSignals.roboticPitchScore.toFixed(2)}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
