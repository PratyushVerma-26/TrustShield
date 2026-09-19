import React, { useState } from 'react';
import { TrustShieldApiClient, PasswordCheckResponse, EmailCheckResponse } from '@trustshield/verdict-core';
import { VerdictBadge } from './VerdictBadge.tsx';
import { KeyRound, Mail, Eye, EyeOff, RefreshCw } from 'lucide-react';

interface Props {
  client: TrustShieldApiClient;
}

export const BreachPanel: React.FC<Props> = ({ client }) => {
  const [activeTab, setActiveTab] = useState<'password' | 'email'>('password');
  const [password, setPassword] = useState('Password123!');
  const [showPassword, setShowPassword] = useState(false);
  const [email, setEmail] = useState('test@example.com');
  const [loading, setLoading] = useState(false);
  const [passwordResult, setPasswordResult] = useState<PasswordCheckResponse | null>(null);
  const [emailResult, setEmailResult] = useState<EmailCheckResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handlePasswordCheck = async () => {
    if (!password) return;
    setLoading(true);
    setError(null);
    try {
      const res = await client.checkPassword(password);
      setPasswordResult(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  const handleEmailCheck = async () => {
    if (!email) return;
    setLoading(true);
    setError(null);
    try {
      const res = await client.checkEmail(email);
      setEmailResult(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header & Mode Switcher */}
      <div style={{ backgroundColor: 'var(--bg-card)', padding: '1.5rem', borderRadius: '0.75rem', border: '1px solid var(--border-color)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem', marginBottom: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <KeyRound style={{ color: 'var(--color-warning)' }} size={24} />
            <div>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>Personal Data Breach & Exposure Monitor</h2>
              <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
                k-Anonymous password lookup and identity leak discovery.
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', backgroundColor: '#0B0F19', padding: '0.25rem', borderRadius: '0.5rem', border: '1px solid #1F2937' }}>
            <button
              onClick={() => setActiveTab('password')}
              style={{
                padding: '0.4rem 1rem',
                borderRadius: '0.375rem',
                border: 'none',
                backgroundColor: activeTab === 'password' ? 'var(--color-warning)' : 'transparent',
                color: activeTab === 'password' ? '#000' : 'var(--text-muted)',
                fontWeight: 700,
                fontSize: '0.8rem',
                cursor: 'pointer'
              }}
            >
              Password (k-Anonymous)
            </button>
            <button
              onClick={() => setActiveTab('email')}
              style={{
                padding: '0.4rem 1rem',
                borderRadius: '0.375rem',
                border: 'none',
                backgroundColor: activeTab === 'email' ? 'var(--color-info)' : 'transparent',
                color: activeTab === 'email' ? '#fff' : 'var(--text-muted)',
                fontWeight: 700,
                fontSize: '0.8rem',
                cursor: 'pointer'
              }}
            >
              Email Breach Check
            </button>
          </div>
        </div>

        {/* Password Tab Input */}
        {activeTab === 'password' && (
          <div>
            <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
              <div style={{ flex: 1, minWidth: '280px', position: 'relative' }}>
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter password to verify k-anonymity exposure..."
                  style={{
                    width: '100%',
                    padding: '0.75rem 2.5rem 0.75rem 1rem',
                    backgroundColor: '#0F172A',
                    border: '1px solid var(--border-color)',
                    borderRadius: '0.5rem',
                    color: 'var(--text-main)',
                    fontFamily: 'monospace',
                    fontSize: '0.9rem'
                  }}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  style={{
                    position: 'absolute',
                    right: '0.75rem',
                    top: '50%',
                    transform: 'translateY(-50%)',
                    background: 'none',
                    border: 'none',
                    color: 'var(--text-muted)',
                    cursor: 'pointer'
                  }}
                >
                  {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>

              <button
                onClick={handlePasswordCheck}
                disabled={loading}
                style={{
                  padding: '0.75rem 1.5rem',
                  backgroundColor: 'var(--color-warning)',
                  color: '#000',
                  border: 'none',
                  borderRadius: '0.5rem',
                  fontWeight: 700,
                  cursor: loading ? 'not-allowed' : 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem'
                }}
              >
                {loading ? <RefreshCw className="animate-spin" size={18} /> : <KeyRound size={18} />}
                {loading ? 'Verifying...' : 'Check Exposure'}
              </button>
            </div>
            <p style={{ fontSize: '0.75rem', color: '#94A3B8', marginTop: '0.5rem' }}>
              🔒 <strong>k-Anonymity Privacy Guarantee:</strong> Neither your password nor its full hash ever leaves your machine. Only the 5-character SHA-1 prefix is queried.
            </p>
          </div>
        )}

        {/* Email Tab Input */}
        {activeTab === 'email' && (
          <div>
            <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="Enter email address to check past breach leaks..."
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
                onClick={handleEmailCheck}
                disabled={loading}
                style={{
                  padding: '0.75rem 1.5rem',
                  backgroundColor: 'var(--color-info)',
                  color: '#fff',
                  border: 'none',
                  borderRadius: '0.5rem',
                  fontWeight: 700,
                  cursor: loading ? 'not-allowed' : 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem'
                }}
              >
                {loading ? <RefreshCw className="animate-spin" size={18} /> : <Mail size={18} />}
                {loading ? 'Checking...' : 'Check Email'}
              </button>
            </div>
          </div>
        )}
      </div>

      {error && (
        <div style={{ backgroundColor: 'rgba(239, 68, 68, 0.1)', border: '1px solid #EF4444', padding: '1rem', borderRadius: '0.5rem', color: '#FCA5A5' }}>
          ⚠️ <strong>Error:</strong> {error}
        </div>
      )}

      {/* Password Result */}
      {activeTab === 'password' && passwordResult && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.5rem' }}>
          {/* Main Verdict Card */}
          <div style={{ backgroundColor: 'var(--bg-card)', padding: '1.5rem', borderRadius: '0.75rem', border: '1px solid var(--border-color)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
              <div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Exposure Assessment</span>
                <h3 style={{ fontSize: '1.1rem', fontWeight: 700 }}>{passwordResult.verdict.verdict}</h3>
              </div>
              <VerdictBadge verdict={passwordResult.verdict} />
            </div>

            <div style={{ padding: '0.75rem', backgroundColor: '#0B0F19', borderRadius: '0.5rem', border: '1px solid #1F2937', marginBottom: '1rem' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Action Recommendation:</div>
              <div style={{ fontSize: '0.9rem', marginTop: '0.25rem', fontWeight: 600 }}>{passwordResult.recommendation}</div>
            </div>

            {/* k-Anonymity Proof Display */}
            <div style={{ padding: '0.75rem', backgroundColor: '#1E293B', borderRadius: '0.5rem', border: '1px solid #334155', marginBottom: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '0.75rem', color: '#94A3B8' }}>SHA-1 Range Bucket:</span>
                <span style={{ fontFamily: 'monospace', fontWeight: 700, backgroundColor: '#0F172A', padding: '0.2rem 0.5rem', borderRadius: '0.25rem', color: '#38BDF8' }}>
                  {passwordResult.bucketPrefix} (5 of 40 chars)
                </span>
              </div>
              <p style={{ fontSize: '0.75rem', color: '#94A3B8', marginTop: '0.4rem' }}>
                Only the prefix above was transmitted. HIBP returned a list of suffix candidates which were matched purely inside client memory.
              </p>
            </div>
          </div>

          {/* Structural Strength Card */}
          <div style={{ backgroundColor: 'var(--bg-card)', padding: '1.5rem', borderRadius: '0.75rem', border: '1px solid var(--border-color)' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '0.75rem' }}>Structural Strength Analysis</h3>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', marginBottom: '1rem' }}>
              <div style={{ padding: '0.5rem', backgroundColor: '#0F172A', borderRadius: '0.375rem' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Password Length:</span>
                <div style={{ fontSize: '1.1rem', fontWeight: 700 }}>{passwordResult.strength.length} chars</div>
              </div>
              <div style={{ padding: '0.5rem', backgroundColor: '#0F172A', borderRadius: '0.375rem' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Entropy:</span>
                <div style={{ fontSize: '1.1rem', fontWeight: 700 }}>{passwordResult.strength.entropy.toFixed(1)} bits</div>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', fontSize: '0.8rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.4rem', backgroundColor: '#1E293B', borderRadius: '0.25rem' }}>
                <span>Digits Included:</span>
                <span style={{ color: passwordResult.strength.hasDigits ? '#10B981' : '#EF4444' }}>
                  {passwordResult.strength.hasDigits ? 'YES' : 'NO'}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.4rem', backgroundColor: '#1E293B', borderRadius: '0.25rem' }}>
                <span>Special Characters:</span>
                <span style={{ color: passwordResult.strength.hasSpecialChars ? '#10B981' : '#EF4444' }}>
                  {passwordResult.strength.hasSpecialChars ? 'YES' : 'NO'}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.4rem', backgroundColor: '#1E293B', borderRadius: '0.25rem' }}>
                <span>Mixed Case (Aa):</span>
                <span style={{ color: passwordResult.strength.hasMixedCase ? '#10B981' : '#EF4444' }}>
                  {passwordResult.strength.hasMixedCase ? 'YES' : 'NO'}
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Email Result */}
      {activeTab === 'email' && emailResult && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ backgroundColor: 'var(--bg-card)', padding: '1.5rem', borderRadius: '0.75rem', border: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Monitored Identity</span>
              <h3 style={{ fontSize: '1.2rem', fontWeight: 700 }}>{emailResult.email}</h3>
              <p style={{ fontSize: '0.85rem', color: emailResult.breachCount > 0 ? '#F87171' : '#34D399', marginTop: '0.25rem' }}>
                {emailResult.breachCount > 0 ? `Exposed in ${emailResult.breachCount} compromised breaches` : 'No known public breaches found.'}
              </p>
            </div>
            <VerdictBadge verdict={emailResult.verdict} />
          </div>

          {emailResult.breaches.map((b) => (
            <div key={b.name} style={{ backgroundColor: 'var(--bg-card)', padding: '1rem 1.5rem', borderRadius: '0.5rem', border: '1px solid var(--border-color)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <h4 style={{ fontWeight: 700 }}>{b.title}</h4>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Breach Date: {b.breachDate}</span>
              </div>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', margin: '0.5rem 0' }} dangerouslySetInnerHTML={{ __html: b.description }} />
              <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
                {b.dataClasses.map((dc) => (
                  <span key={dc} style={{ fontSize: '0.7rem', padding: '0.15rem 0.5rem', backgroundColor: '#1E293B', borderRadius: '0.25rem', color: '#94A3B8' }}>
                    {dc}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
