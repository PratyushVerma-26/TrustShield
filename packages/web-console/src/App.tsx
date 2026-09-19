import React, { useState, useEffect, useMemo } from 'react';
import { TrustShieldApiClient } from '@trustshield/verdict-core';
import { PhishingPanel } from './components/PhishingPanel.tsx';
import { BreachPanel } from './components/BreachPanel.tsx';
import { DeepfakePanel } from './components/DeepfakePanel.tsx';
import { FakeNewsPanel } from './components/FakeNewsPanel.tsx';
import { FusionPanel } from './components/FusionPanel.tsx';
import { LedgerPanel } from './components/LedgerPanel.tsx';
import { BotSimulatorPanel } from './components/BotSimulatorPanel.tsx';
import {
  Shield,
  Globe,
  KeyRound,
  Film,
  Newspaper,
  Layers,
  Database,
  MessageSquare,
  Activity
} from 'lucide-react';

type Tab = 'phishing' | 'breach' | 'deepfake' | 'fakenews' | 'fusion' | 'ledger' | 'bot';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<Tab>('phishing');
  const [gatewayOnline, setGatewayOnline] = useState<boolean | null>(null);

  // Initialize TrustShield typed API client connecting to single-origin Gateway (:8080)
  const client = useMemo(() => new TrustShieldApiClient(), []);

  useEffect(() => {
    // Check gateway status
    client.getGatewayHealth()
      .then(() => setGatewayOnline(true))
      .catch(() => setGatewayOnline(false));
  }, [client]);

  const navItems = [
    { id: 'phishing', label: 'Phishing Shield', icon: Globe, port: '8083' },
    { id: 'breach', label: 'Breach Monitor', icon: KeyRound, port: '8084' },
    { id: 'deepfake', label: 'Deepfake Forensics', icon: Film, port: '8085' },
    { id: 'fakenews', label: 'Fake News Firewall', icon: Newspaper, port: '8086' },
    { id: 'fusion', label: 'Cross-Modal Fusion', icon: Layers, port: '8088' },
    { id: 'ledger', label: 'Integrity Ledger', icon: Database, port: '8087' },
    { id: 'bot', label: 'Bot Simulator', icon: MessageSquare, port: '8089' },
  ];

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* Top Navbar */}
      <header
        style={{
          backgroundColor: '#0F172A',
          borderBottom: '1px solid #1E293B',
          padding: '1rem 2rem',
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
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div
            style={{
              width: '40px',
              height: '40px',
              borderRadius: '0.5rem',
              backgroundColor: '#0284C7',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: '0 0 15px rgba(2, 132, 199, 0.4)'
            }}
          >
            <Shield size={24} color="white" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <h1 style={{ fontSize: '1.25rem', fontWeight: 800, letterSpacing: '-0.025em' }}>
                TrustShield
              </h1>
              <span
                style={{
                  fontSize: '0.65rem',
                  fontWeight: 800,
                  backgroundColor: '#0284C7',
                  color: 'white',
                  padding: '0.1rem 0.4rem',
                  borderRadius: '0.25rem'
                }}
              >
                CONSOLE v1.0
              </span>
            </div>
            <p style={{ fontSize: '0.75rem', color: '#94A3B8' }}>
              Multi-Vector Cyber-Defense & Forensic Threat Intelligence
            </p>
          </div>
        </div>

        {/* System Health / Gateway status indicator */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
              padding: '0.35rem 0.75rem',
              borderRadius: '9999px',
              backgroundColor: '#1E293B',
              fontSize: '0.75rem',
              fontWeight: 600
            }}
          >
            <Activity size={14} color="#38BDF8" />
            <span>API Gateway (Port 8080):</span>
            <span
              style={{
                color: gatewayOnline === true ? '#34D399' : gatewayOnline === false ? '#F87171' : '#FBBF24',
                fontWeight: 700
              }}
            >
              {gatewayOnline === true ? '● ONLINE' : gatewayOnline === false ? '● OFFLINE' : '○ CONNECTING...'}
            </span>
          </div>

          <div
            style={{
              padding: '0.35rem 0.75rem',
              borderRadius: '0.375rem',
              backgroundColor: '#0B0F19',
              border: '1px solid #1E293B',
              fontSize: '0.7rem',
              fontFamily: 'monospace',
              color: '#94A3B8'
            }}
          >
            Java 21 · Spring Boot 3.3.2 · H2
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <div style={{ flex: 1, display: 'flex', maxWidth: '1600px', width: '100%', margin: '0 auto' }}>
        {/* Sidebar Navigation */}
        <aside
          style={{
            width: '240px',
            backgroundColor: '#0B0F19',
            borderRight: '1px solid #1E293B',
            padding: '1.5rem 1rem',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.35rem'
          }}
        >
          <div style={{ fontSize: '0.7rem', fontWeight: 800, color: '#64748B', letterSpacing: '0.05em', padding: '0 0.5rem 0.5rem 0.5rem' }}>
            DEFENSE VECTORS
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
                  padding: '0.65rem 0.75rem',
                  borderRadius: '0.5rem',
                  border: 'none',
                  backgroundColor: isActive ? '#1E293B' : 'transparent',
                  color: isActive ? '#F8FAFC' : '#94A3B8',
                  fontWeight: isActive ? 700 : 500,
                  fontSize: '0.85rem',
                  cursor: 'pointer',
                  textAlign: 'left',
                  transition: 'background-color 0.15s ease'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                  <Icon size={18} color={isActive ? '#38BDF8' : '#64748B'} />
                  <span>{item.label}</span>
                </div>
                <span style={{ fontSize: '0.65rem', fontFamily: 'monospace', color: '#64748B' }}>
                  :{item.port}
                </span>
              </button>
            );
          })}

          {/* Invariant Reminder Box */}
          <div
            className="hatched-unmeasured"
            style={{
              marginTop: 'auto',
              padding: '0.85rem',
              borderRadius: '0.5rem',
              fontSize: '0.7rem',
              color: '#94A3B8'
            }}
          >
            <div style={{ fontWeight: 800, color: '#E2E8F0', marginBottom: '0.25rem' }}>
              🛡️ CORE INVARIANT
            </div>
            Absence of evidence is not evidence of absence. An unmeasured or inconclusive result is never certified as safe.
          </div>
        </aside>

        {/* Main Panel Viewport */}
        <main style={{ flex: 1, padding: '2rem', overflowY: 'auto' }}>
          {activeTab === 'phishing' && <PhishingPanel client={client} />}
          {activeTab === 'breach' && <BreachPanel client={client} />}
          {activeTab === 'deepfake' && <DeepfakePanel client={client} />}
          {activeTab === 'fakenews' && <FakeNewsPanel client={client} />}
          {activeTab === 'fusion' && <FusionPanel client={client} />}
          {activeTab === 'ledger' && <LedgerPanel client={client} />}
          {activeTab === 'bot' && <BotSimulatorPanel client={client} />}
        </main>
      </div>

      {/* Footer */}
      <footer
        style={{
          backgroundColor: '#0F172A',
          borderTop: '1px solid #1E293B',
          padding: '1rem 2rem',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          fontSize: '0.75rem',
          color: '#64748B'
        }}
      >
        <div>
          TrustShield Cyber-Defense Platform · Multi-Modal Defense & Audit Ledger
        </div>
        <div style={{ display: 'flex', gap: '1.5rem' }}>
          <span>Gateway: <code>http://localhost:8080</code></span>
          <span>OpenAPI / Swagger: <code>/swagger-ui.html</code></span>
        </div>
      </footer>
    </div>
  );
};

export default App;
