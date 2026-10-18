import React, { useState } from 'react';
import { TrustShieldApiClient, PasswordCheckResponse, EmailCheckResponse } from '@trustshield/verdict-core';
import { ShieldCheck, KeyRound, Mail, RefreshCw, Eye, EyeOff, CheckCircle2, AlertOctagon } from 'lucide-react';

interface Props {
  client: TrustShieldApiClient;
  onResultChange?: (status: 'idle' | 'safe' | 'danger') => void;
}

export const BreachPanel: React.FC<Props> = ({ client, onResultChange }) => {
  const [activeTab, setActiveTab] = useState<'password' | 'email'>('password');
  const [password, setPassword] = useState('');
  const [email, setEmail] = useState('');
  const [showPassword, setShowPassword] = useState(false);
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
      const isBreached = res.verdict.threatLevel === 'DANGEROUS' || res.verdict.threatLevel === 'SUSPICIOUS' || res.verdict.riskScore >= 50;
      if (onResultChange) onResultChange(isBreached ? 'danger' : 'safe');
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
      const isBreached = res.breachCount > 0 || res.verdict.threatLevel === 'DANGEROUS' || res.verdict.threatLevel === 'SUSPICIOUS';
      if (onResultChange) onResultChange(isBreached ? 'danger' : 'safe');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  const isPasswordBreached = passwordResult && (passwordResult.verdict.threatLevel === 'DANGEROUS' || passwordResult.verdict.threatLevel === 'SUSPICIOUS' || passwordResult.verdict.riskScore >= 50);
  const isEmailBreached = emailResult && (emailResult.breachCount > 0 || emailResult.verdict.threatLevel === 'DANGEROUS' || emailResult.verdict.threatLevel === 'SUSPICIOUS');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header Card */}
      <div className="cyber-card" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem', marginBottom: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
            <div style={{ width: '40px', height: '40px', borderRadius: '0.5rem', backgroundColor: 'rgba(245, 158, 11, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', border: '1px solid #D97706' }}>
              <KeyRound style={{ color: '#FBBF24' }} size={22} />
            </div>
            <div>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 800, color: '#FFFFFF' }}>Password &amp; Email Breach Monitor</h2>
              <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                Check if your password or email address has been leaked in known data breaches.
              </p>
            </div>
          </div>

          {/* Mode Switcher */}
          <div style={{ display: 'flex', backgroundColor: 'var(--bg-input)', padding: '0.3rem', borderRadius: '0.5rem', border: '1px solid var(--border-color)' }}>
            <button
              onClick={() => { setActiveTab('password'); setError(null); }}
              style={{
                padding: '0.45rem 1.15rem',
                borderRadius: '0.375rem',
                border: 'none',
                backgroundColor: activeTab === 'password' ? 'var(--color-warning)' : 'transparent',
                color: activeTab === 'password' ? '#000' : 'var(--text-muted)',
                fontWeight: 800,
                fontSize: '0.82rem',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
                transition: 'all 0.15s ease'
              }}
            >
              <KeyRound size={15} />
              Password Check
            </button>
            <button
              onClick={() => { setActiveTab('email'); setError(null); }}
              style={{
                padding: '0.45rem 1.15rem',
                borderRadius: '0.375rem',
                border: 'none',
                backgroundColor: activeTab === 'email' ? 'var(--color-info)' : 'transparent',
                color: activeTab === 'email' ? '#fff' : 'var(--text-muted)',
                fontWeight: 800,
                fontSize: '0.82rem',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
                transition: 'all 0.15s ease'
              }}
            >
              <Mail size={15} />
              Email Check
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
                  placeholder="Enter the password"
                  onKeyDown={(e) => { if (e.key === 'Enter') handlePasswordCheck(); }}
                  style={{
                    width: '100%',
                    padding: '0.85rem 2.75rem 0.85rem 1.15rem',
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
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  style={{
                    position: 'absolute',
                    right: '0.85rem',
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
                disabled={loading || !password}
                style={{
                  padding: '0.85rem 1.75rem',
                  backgroundColor: loading || !password ? '#1E293B' : 'var(--color-warning)',
                  color: loading || !password ? '#64748B' : '#000',
                  border: '1px solid #D97706',
                  borderRadius: '0.5rem',
                  fontWeight: 800,
                  fontSize: '0.9rem',
                  cursor: loading || !password ? 'not-allowed' : 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  boxShadow: loading || !password ? 'none' : '0 2px 10px rgba(245, 158, 11, 0.3)',
                  transition: 'all 0.15s ease'
                }}
              >
                {loading ? <RefreshCw className="animate-spin" size={18} /> : <KeyRound size={18} />}
                {loading ? 'Checking...' : 'Check Password'}
              </button>
            </div>
            <p style={{ fontSize: '0.75rem', color: '#94A3B8', marginTop: '0.65rem' }}>
              🔒 <strong>Safe &amp; Private:</strong> Your actual password is never sent over the internet or saved anywhere.
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
                placeholder="Enter the Email"
                onKeyDown={(e) => { if (e.key === 'Enter') handleEmailCheck(); }}
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
                onClick={handleEmailCheck}
                disabled={loading || !email}
                style={{
                  padding: '0.85rem 1.75rem',
                  backgroundColor: loading || !email ? '#1E293B' : 'var(--color-info)',
                  color: loading || !email ? '#64748B' : '#fff',
                  border: '1px solid #0EA5E9',
                  borderRadius: '0.5rem',
                  fontWeight: 800,
                  fontSize: '0.9rem',
                  cursor: loading || !email ? 'not-allowed' : 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  boxShadow: loading || !email ? 'none' : '0 2px 10px rgba(2, 132, 199, 0.4)',
                  transition: 'all 0.15s ease'
                }}
              >
                {loading ? <RefreshCw className="animate-spin" size={18} /> : <Mail size={18} />}
                {loading ? 'Checking...' : 'Check Email'}
              </button>
            </div>
            <p style={{ fontSize: '0.75rem', color: '#94A3B8', marginTop: '0.65rem' }}>
              ℹ️ Checks major breach databases to see if accounts linked to this email were compromised.
            </p>
          </div>
        )}
      </div>

      {error && (
        <div style={{ padding: '1rem', backgroundColor: 'var(--color-danger-bg)', border: '1px solid var(--color-danger)', borderRadius: '0.5rem', color: '#FCA5A5', fontSize: '0.875rem' }}>
          ⚠️ <strong>Query Error:</strong> {error}
        </div>
      )}

      {/* Password Result Display */}
      {activeTab === 'password' && passwordResult && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <div
            className="cyber-card"
            style={{
              padding: '1.5rem',
              borderLeft: `5px solid ${isPasswordBreached ? '#EF4444' : '#10B981'}`,
              backgroundColor: isPasswordBreached ? 'rgba(239, 68, 68, 0.06)' : 'rgba(16, 185, 129, 0.05)'
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
                  backgroundColor: isPasswordBreached ? 'rgba(239, 68, 68, 0.2)' : 'rgba(16, 185, 129, 0.2)',
                  border: `2px solid ${isPasswordBreached ? '#EF4444' : '#10B981'}`
                }}
              >
                {isPasswordBreached ? <AlertOctagon size={32} color="#F87171" /> : <ShieldCheck size={32} color="#34D399" />}
              </div>
              <div>
                <div style={{ fontSize: '1.35rem', fontWeight: 900, color: isPasswordBreached ? '#F87171' : '#34D399' }}>
                  {isPasswordBreached ? '✗ This Password Has Been Leaked in a Breach!' : '✓ Good News! This Password Was Not Found in Known Leaks'}
                </div>
                <div style={{ fontSize: '0.92rem', color: '#CBD5E1', marginTop: '0.35rem' }}>
                  {isPasswordBreached
                    ? 'Cybercriminals and automated hacker bots have this password on record. It is unsafe to use.'
                    : 'This password does not appear in known public data leaks. Make sure you use a unique password for each account.'}
                </div>
              </div>
            </div>

            {/* Actionable Steps & Suggestions for Common Users */}
            {isPasswordBreached && (
              <div style={{ marginTop: '1.5rem', paddingTop: '1.25rem', borderTop: '1px solid rgba(239, 68, 68, 0.3)' }}>
                <h4 style={{ fontSize: '1rem', fontWeight: 800, color: '#FFFFFF', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  🛠️ What You Should Do Right Now (Steps to Secure Your Account):
                </h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.65rem', backgroundColor: '#152238', padding: '0.75rem', borderRadius: '0.5rem', border: '1px solid #263852' }}>
                    <CheckCircle2 size={18} color="#38BDF8" style={{ marginTop: '2px', flexShrink: 0 }} />
                    <span style={{ fontSize: '0.88rem', color: '#E2E8F0' }}>
                      <strong>1. Change this password immediately:</strong> If you use this password on email, banking, social media, or shopping sites, change it immediately to a new one.
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.65rem', backgroundColor: '#152238', padding: '0.75rem', borderRadius: '0.5rem', border: '1px solid #263852' }}>
                    <CheckCircle2 size={18} color="#38BDF8" style={{ marginTop: '2px', flexShrink: 0 }} />
                    <span style={{ fontSize: '0.88rem', color: '#E2E8F0' }}>
                      <strong>2. Turn on Two-Factor Authentication (2FA / OTP):</strong> Enable SMS or Authenticator App verification on all your important accounts. Even if hackers know your password, they cannot log in without the OTP.
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.65rem', backgroundColor: '#152238', padding: '0.75rem', borderRadius: '0.5rem', border: '1px solid #263852' }}>
                    <CheckCircle2 size={18} color="#38BDF8" style={{ marginTop: '2px', flexShrink: 0 }} />
                    <span style={{ fontSize: '0.88rem', color: '#E2E8F0' }}>
                      <strong>3. Never reuse passwords:</strong> Use a passphrase of 3 to 4 random words (e.g. <code>Coffee#Sun79Blue</code>) or a free password manager (like Bitwarden or Google Password Manager).
                    </span>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Email Result Display */}
      {activeTab === 'email' && emailResult && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <div
            className="cyber-card"
            style={{
              padding: '1.5rem',
              borderLeft: `5px solid ${isEmailBreached ? '#EF4444' : '#10B981'}`,
              backgroundColor: isEmailBreached ? 'rgba(239, 68, 68, 0.06)' : 'rgba(16, 185, 129, 0.05)'
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
                  backgroundColor: isEmailBreached ? 'rgba(239, 68, 68, 0.2)' : 'rgba(16, 185, 129, 0.2)',
                  border: `2px solid ${isEmailBreached ? '#EF4444' : '#10B981'}`
                }}
              >
                {isEmailBreached ? <AlertOctagon size={32} color="#F87171" /> : <ShieldCheck size={32} color="#34D399" />}
              </div>
              <div>
                <div style={{ fontSize: '1.35rem', fontWeight: 900, color: isEmailBreached ? '#F87171' : '#34D399' }}>
                  {isEmailBreached ? `✗ Warning: This Email Was Found in ${emailResult.breachCount || 1} Known Data Breach(es)!` : '✓ Great! No Breaches Found for this Email'}
                </div>
                <div style={{ fontSize: '0.92rem', color: '#CBD5E1', marginTop: '0.35rem' }}>
                  {isEmailBreached
                    ? 'A website or service where you registered this email suffered a security breach, exposing account details.'
                    : 'We found no record of this email address in our monitored public breach archives.'}
                </div>
              </div>
            </div>

            {/* Actionable Suggestions */}
            {isEmailBreached && (
              <div style={{ marginTop: '1.5rem', paddingTop: '1.25rem', borderTop: '1px solid rgba(239, 68, 68, 0.3)' }}>
                <h4 style={{ fontSize: '1rem', fontWeight: 800, color: '#FFFFFF', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  🛠️ Steps to Protect Your Email &amp; Online Accounts:
                </h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.65rem', backgroundColor: '#152238', padding: '0.75rem', borderRadius: '0.5rem', border: '1px solid #263852' }}>
                    <CheckCircle2 size={18} color="#38BDF8" style={{ marginTop: '2px', flexShrink: 0 }} />
                    <span style={{ fontSize: '0.88rem', color: '#E2E8F0' }}>
                      <strong>1. Change your email account password immediately:</strong> Your primary email account controls password resets for all other websites. Secure it first with a strong, fresh password.
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.65rem', backgroundColor: '#152238', padding: '0.75rem', borderRadius: '0.5rem', border: '1px solid #263852' }}>
                    <CheckCircle2 size={18} color="#38BDF8" style={{ marginTop: '2px', flexShrink: 0 }} />
                    <span style={{ fontSize: '0.88rem', color: '#E2E8F0' }}>
                      <strong>2. Check for suspicious forwarding rules:</strong> Open your email settings and ensure hackers have not added any automated rule forwarding your incoming emails.
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.65rem', backgroundColor: '#152238', padding: '0.75rem', borderRadius: '0.5rem', border: '1px solid #263852' }}>
                    <CheckCircle2 size={18} color="#38BDF8" style={{ marginTop: '2px', flexShrink: 0 }} />
                    <span style={{ fontSize: '0.88rem', color: '#E2E8F0' }}>
                      <strong>3. Beware of targeted phishing emails:</strong> Now that scammers have your email address, expect fake emails pretending to be banks, parcel deliveries, or tax refunds.
                    </span>
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
