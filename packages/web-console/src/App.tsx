import React, { useState, useEffect, useMemo } from 'react';
import { TrustShieldApiClient } from '@trustshield/verdict-core';
import { PhishingPanel } from './components/PhishingPanel.tsx';
import { BreachPanel } from './components/BreachPanel.tsx';
import { DeepfakePanel } from './components/DeepfakePanel.tsx';
import { FakeNewsPanel } from './components/FakeNewsPanel.tsx';
import {
  Shield,
  Globe,
  KeyRound,
  Film,
  Newspaper,
  Activity,
  ArrowLeft,
  ChevronRight,
  ShieldCheck
} from 'lucide-react';

type Tab = 'home' | 'phishing' | 'breach' | 'deepfake' | 'fakenews';
type ResultStatus = 'idle' | 'safe' | 'danger';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<Tab>('home');
  const [gatewayOnline, setGatewayOnline] = useState<boolean | null>(null);

  // Result state tracking per module for dynamic background switching
  const [phishStatus, setPhishStatus] = useState<ResultStatus>('idle');
  const [breachStatus, setBreachStatus] = useState<ResultStatus>('idle');
  const [deepfakeStatus, setDeepfakeStatus] = useState<ResultStatus>('idle');
  const [fakeNewsStatus, setFakeNewsStatus] = useState<ResultStatus>('idle');

  // Initialize TrustShield typed API client
  const client = useMemo(() => {
    const envUrl = (import.meta as any).env?.VITE_GATEWAY_URL;
    const origin = typeof window !== 'undefined' ? window.location.origin : '';
    const baseUrl = envUrl || (origin.includes('5173') ? 'http://localhost:8080' : origin || 'http://localhost:8080');
    return new TrustShieldApiClient({ baseUrl });
  }, []);

  useEffect(() => {
    client.getGatewayHealth()
      .then(() => setGatewayOnline(true))
      .catch(() => setGatewayOnline(false));
  }, [client]);

  const navItems = [
    {
      id: 'phishing',
      label: 'Phishing Shield',
      desc: 'Verify if website links, email URLs, or SMS offers are legitimate or dangerous login scams.',
      icon: Globe,
      color: '#38BDF8',
      accentBg: 'rgba(56, 189, 248, 0.15)',
      port: '8083'
    },
    {
      id: 'breach',
      label: 'Breach Monitor',
      desc: 'Check if your personal password or email was leaked in major hacker database breaches.',
      icon: KeyRound,
      color: '#FBBF24',
      accentBg: 'rgba(245, 158, 11, 0.15)',
      port: '8084'
    },
    {
      id: 'deepfake',
      label: 'Deepfake Forensics',
      desc: 'Detect AI-manipulated synthetic media, face swaps, and synthetic voice cloning.',
      icon: Film,
      color: '#C084FC',
      accentBg: 'rgba(192, 132, 252, 0.15)',
      port: '8085'
    },
    {
      id: 'fakenews',
      label: 'Fake News Firewall',
      desc: 'Check viral WhatsApp forwards, screenshots, rumors, and claims against fact-checkers.',
      icon: Newspaper,
      color: '#34D399',
      accentBg: 'rgba(52, 211, 153, 0.15)',
      port: '8086'
    }
  ];

  // Dynamic Background Image Computation based on Active Service & Live Result
  const currentBgImage = useMemo(() => {
    if (activeTab === 'home') {
      return '/backgrounds/hero-globe.svg';
    }

    if (activeTab === 'phishing') {
      if (phishStatus === 'danger') return '/backgrounds/phish-danger.svg';
      if (phishStatus === 'safe') return '/backgrounds/phish-safe.svg';
      return '/backgrounds/phish-idle.svg';
    }

    if (activeTab === 'breach') {
      if (breachStatus === 'danger') return '/backgrounds/breach-danger.svg';
      if (breachStatus === 'safe') return '/backgrounds/breach-safe.svg';
      return '/backgrounds/breach-idle.svg';
    }

    if (activeTab === 'deepfake') {
      if (deepfakeStatus === 'danger') return '/backgrounds/deepfake-danger.svg';
      if (deepfakeStatus === 'safe') return '/backgrounds/deepfake-safe.svg';
      return '/backgrounds/deepfake-idle.svg';
    }

    if (activeTab === 'fakenews') {
      if (fakeNewsStatus === 'danger') return '/backgrounds/fakenews-danger.svg';
      if (fakeNewsStatus === 'safe') return '/backgrounds/fakenews-safe.svg';
      return '/backgrounds/fakenews-idle.svg';
    }

    return '/backgrounds/hero-globe.svg';
  }, [activeTab, phishStatus, breachStatus, deepfakeStatus, fakeNewsStatus]);

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        flexDirection: 'column',
        backgroundImage: `url(${currentBgImage})`,
        backgroundSize: 'cover',
        backgroundPosition: 'center',
        backgroundRepeat: 'no-repeat',
        backgroundAttachment: 'fixed',
        transition: 'background-image 0.5s ease-in-out',
        color: '#FFFFFF'
      }}
    >
      {/* Frosted Glass Header */}
      <header
        className="glass-panel"
        style={{
          padding: '0.85rem 2.5rem',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '1rem',
          position: 'sticky',
          top: 0,
          zIndex: 50
        }}
      >
        <div
          onClick={() => setActiveTab('home')}
          style={{ display: 'flex', alignItems: 'center', gap: '0.85rem', cursor: 'pointer' }}
        >
          <div
            style={{
              width: '42px',
              height: '42px',
              borderRadius: '0.65rem',
              backgroundColor: '#0284C7',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: '0 0 20px rgba(2, 132, 199, 0.6)',
              border: '1px solid #38BDF8'
            }}
          >
            <Shield size={24} color="white" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <h1 style={{ fontSize: '1.4rem', fontWeight: 900, letterSpacing: '-0.025em', color: '#FFFFFF' }}>
                TrustShield
              </h1>
            </div>
            <p style={{ fontSize: '0.75rem', color: '#94A3B8', fontWeight: 500 }}>
              AI-Powered Citizen Cyber-Defense &amp; Fraud Neutralization
            </p>
          </div>
        </div>

        {/* System Health / Gateway status indicator & Navigation */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          {activeTab !== 'home' && (
            <button
              onClick={() => setActiveTab('home')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
                backgroundColor: 'rgba(255, 255, 255, 0.08)',
                border: '1px solid rgba(255, 255, 255, 0.15)',
                color: '#38BDF8',
                padding: '0.45rem 0.95rem',
                borderRadius: '0.5rem',
                fontSize: '0.82rem',
                fontWeight: 700,
                cursor: 'pointer',
                backdropFilter: 'blur(8px)'
              }}
            >
              <ArrowLeft size={16} /> Main Front
            </button>
          )}

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              padding: '0.4rem 0.85rem',
              borderRadius: '9999px',
              backgroundColor: 'rgba(21, 34, 56, 0.7)',
              border: '1px solid rgba(255, 255, 255, 0.1)',
              fontSize: '0.75rem',
              fontWeight: 600,
              backdropFilter: 'blur(8px)'
            }}
          >
            <Activity size={15} color="#38BDF8" />
            <span style={{ color: '#CBD5E1' }}>Gateway:</span>
            <span
              style={{
                color: gatewayOnline === true ? '#34D399' : gatewayOnline === false ? '#F87171' : '#FBBF24',
                fontWeight: 800
              }}
            >
              {gatewayOnline === true ? '● ONLINE' : gatewayOnline === false ? '● OFFLINE' : '○ CONNECTING...'}
            </span>
          </div>
        </div>
      </header>

      {/* Main View Area */}
      {activeTab === 'home' ? (
        /* Web Front Hero Landing with Center Web-Connected Globe, Attacks & Shield */
        <div
          style={{
            flex: 1,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '2.5rem 1.5rem',
            maxWidth: '1280px',
            margin: '0 auto',
            width: '100%',
            textAlign: 'center'
          }}
        >
          {/* Main Title Header Hero */}
          <div
            className="glass-card animate-pulse-subtle"
            style={{
              padding: '1rem 2rem',
              borderRadius: '9999px',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.65rem',
              marginBottom: '1.25rem',
              border: '1px solid rgba(56, 189, 248, 0.4)'
            }}
          >
            <ShieldCheck size={20} color="#38BDF8" />
            <span style={{ fontSize: '0.9rem', fontWeight: 800, color: '#38BDF8', letterSpacing: '0.04em' }}>
              NEXT-GEN CITIZEN CYBERSECURITY ECOSYSTEM
            </span>
          </div>

          <h1
            style={{
              fontSize: 'clamp(2.4rem, 5vw, 4.2rem)',
              fontWeight: 900,
              letterSpacing: '-0.03em',
              lineHeight: 1.15,
              marginBottom: '1rem',
              textShadow: '0 4px 20px rgba(0, 0, 0, 0.8)'
            }}
          >
            Shielding Every Citizen From <br />
            <span style={{ background: 'linear-gradient(90deg, #38BDF8 0%, #818CF8 50%, #34D399 100%)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              Phishing, Breaches, Deepfakes &amp; Fake News
            </span>
          </h1>

          <p
            style={{
              fontSize: 'clamp(1rem, 1.5vw, 1.25rem)',
              color: '#CBD5E1',
              maxWidth: '820px',
              lineHeight: 1.6,
              marginBottom: '3rem',
              textShadow: '0 2px 10px rgba(0,0,0,0.7)'
            }}
          >
            A unified, privacy-preserving defense workstation designed for everyday citizens. Instant safety verdicts, step-by-step security actions, and direct official reporting channels.
          </p>

          {/* Underneath Action Buttons to Access Each Service Dashboard */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
              gap: '1.5rem',
              width: '100%'
            }}
          >
            {navItems.map((item) => {
              const Icon = item.icon;
              return (
                <div
                  key={item.id}
                  onClick={() => setActiveTab(item.id as Tab)}
                  className="glass-card"
                  style={{
                    padding: '2rem 1.75rem',
                    textAlign: 'left',
                    cursor: 'pointer',
                    display: 'flex',
                    flexDirection: 'column',
                    justifyContent: 'space-between',
                    gap: '1.25rem',
                    position: 'relative',
                    overflow: 'hidden'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div
                      style={{
                        width: '54px',
                        height: '54px',
                        borderRadius: '0.75rem',
                        backgroundColor: item.accentBg,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        border: `1px solid ${item.color}`
                      }}
                    >
                      <Icon size={28} color={item.color} />
                    </div>
                    <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.75rem', color: '#94A3B8' }}>
                      PORT :{item.port}
                    </span>
                  </div>

                  <div>
                    <h3 style={{ fontSize: '1.25rem', fontWeight: 800, color: '#FFFFFF', marginBottom: '0.45rem' }}>
                      {item.label}
                    </h3>
                    <p style={{ fontSize: '0.88rem', color: '#94A3B8', lineHeight: 1.5 }}>
                      {item.desc}
                    </p>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: item.color, fontWeight: 800, fontSize: '0.9rem', marginTop: '0.5rem' }}>
                    <span>Launch Shield Dashboard</span>
                    <ChevronRight size={18} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      ) : (
        /* Dedicated Service Dashboard with Glass Screen Panels */
        <div style={{ flex: 1, display: 'flex', maxWidth: '1600px', width: '100%', margin: '0 auto' }}>
          {/* Frosted Glass Sidebar */}
          <aside
            className="glass-panel"
            style={{
              width: '260px',
              borderRight: '1px solid rgba(255, 255, 255, 0.12)',
              padding: '1.5rem 1rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '0.45rem'
            }}
          >
            <div style={{ fontSize: '0.7rem', fontWeight: 800, color: '#94A3B8', letterSpacing: '0.08em', padding: '0 0.5rem 0.6rem 0.5rem' }}>
              SERVICES DASHBOARD
            </div>

            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id as Tab)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '0.8rem 0.95rem',
                    borderRadius: '0.65rem',
                    border: isActive ? `1px solid ${item.color}` : '1px solid transparent',
                    backgroundColor: isActive ? 'rgba(21, 34, 56, 0.8)' : 'transparent',
                    color: isActive ? '#FFFFFF' : '#94A3B8',
                    fontWeight: isActive ? 800 : 500,
                    fontSize: '0.88rem',
                    cursor: 'pointer',
                    textAlign: 'left',
                    transition: 'all 0.15s ease',
                    boxShadow: isActive ? `0 2px 12px ${item.accentBg}` : 'none'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                    <Icon size={18} color={isActive ? item.color : '#64748B'} />
                    <span>{item.label}</span>
                  </div>
                  <span style={{ fontSize: '0.65rem', fontFamily: 'JetBrains Mono, monospace', color: isActive ? item.color : '#64748B' }}>
                    :{item.port}
                  </span>
                </button>
              );
            })}

            {/* Back to Web Front */}
            <button
              onClick={() => setActiveTab('home')}
              style={{
                marginTop: '1.5rem',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '0.5rem',
                padding: '0.75rem',
                borderRadius: '0.5rem',
                backgroundColor: 'rgba(255, 255, 255, 0.05)',
                border: '1px solid rgba(255, 255, 255, 0.12)',
                color: '#38BDF8',
                fontWeight: 700,
                fontSize: '0.85rem',
                cursor: 'pointer'
              }}
            >
              <ArrowLeft size={16} /> Return to Front
            </button>
          </aside>

          {/* Main Service Viewport */}
          <main style={{ flex: 1, padding: '2rem', overflowY: 'auto' }}>
            {activeTab === 'phishing' && (
              <PhishingPanel client={client} onResultChange={setPhishStatus} />
            )}
            {activeTab === 'breach' && (
              <BreachPanel client={client} onResultChange={setBreachStatus} />
            )}
            {activeTab === 'deepfake' && (
              <DeepfakePanel client={client} onResultChange={setDeepfakeStatus} />
            )}
            {activeTab === 'fakenews' && (
              <FakeNewsPanel client={client} onResultChange={setFakeNewsStatus} />
            )}
          </main>
        </div>
      )}

      {/* Frosted Glass Footer */}
      <footer
        className="glass-panel"
        style={{
          padding: '0.85rem 2.5rem',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          fontSize: '0.75rem',
          color: '#94A3B8'
        }}
      >
        <div>
          <strong style={{ color: '#CBD5E1' }}>TrustShield</strong> · Multi-Vector Citizen Cyber-Defense
        </div>
        <div style={{ display: 'flex', gap: '1.5rem' }}>
          <span>Security Chatbot: <a href="/chat.html" target="_blank" rel="noreferrer" style={{ color: '#38BDF8', textDecoration: 'none', fontWeight: 700 }}>/chat.html ↗</a></span>
          <span>OpenAPI Docs: <a href="/swagger-ui.html" target="_blank" rel="noreferrer" style={{ color: '#38BDF8', textDecoration: 'none', fontWeight: 700 }}>/swagger-ui.html ↗</a></span>
        </div>
      </footer>
    </div>
  );
};

export default App;
