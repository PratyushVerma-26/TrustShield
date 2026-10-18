import React, { useState, useEffect, useMemo } from 'react';
import {
  SafeAreaView,
  ScrollView,
  View,
  Text,
  TextInput,
  TouchableOpacity,
  ActivityIndicator,
  StyleSheet,
  StatusBar,
  Linking
} from 'react-native';
import {
  TrustShieldApiClient
} from '@trustshield/verdict-core';
import { GATEWAY_BASE_URL } from './src/config';

type Tab = 'home' | 'phishing' | 'breach' | 'deepfake' | 'fakenews';

export default function App() {
  const [gatewayUrl, setGatewayUrl] = useState(GATEWAY_BASE_URL);
  const [activeTab, setActiveTab] = useState<Tab>('home');
  const [gatewayOnline, setGatewayOnline] = useState<boolean | null>(null);

  // Result state tracking per module for dynamic theme adaptation
  const [phishStatus, setPhishStatus] = useState<'idle' | 'safe' | 'danger'>('idle');
  const [breachStatus, setBreachStatus] = useState<'idle' | 'safe' | 'danger'>('idle');
  const [deepfakeStatus, setDeepfakeStatus] = useState<'idle' | 'safe' | 'danger'>('idle');
  const [fakeNewsStatus, setFakeNewsStatus] = useState<'idle' | 'safe' | 'danger'>('idle');

  // Dynamic API client bound to user-configured gateway URL (LAN IP or emulator)
  const client = useMemo(() => new TrustShieldApiClient({ baseUrl: gatewayUrl }), [gatewayUrl]);

  useEffect(() => {
    client.getGatewayHealth()
      .then(() => setGatewayOnline(true))
      .catch(() => setGatewayOnline(false));
  }, [client]);

  // Tab 1: Phishing State
  const [phishUrl, setPhishUrl] = useState('');
  const [phishLoading, setPhishLoading] = useState(false);
  const [phishResult, setPhishResult] = useState<any>(null);

  // Tab 2: Breach State
  const [breachMode, setBreachMode] = useState<'password' | 'email'>('password');
  const [password, setPassword] = useState('');
  const [email, setEmail] = useState('');
  const [breachLoading, setBreachLoading] = useState(false);
  const [breachResult, setBreachResult] = useState<any>(null);

  // Tab 3: Deepfake State
  const [deepfakeLoading, setDeepfakeLoading] = useState(false);
  const [deepfakeResult, setDeepfakeResult] = useState<any>(null);
  const [mediaFilename, setMediaFilename] = useState('');
  const [mediaBase64, setMediaBase64] = useState('');
  const [mediaType, setMediaType] = useState<'IMAGE' | 'VIDEO' | 'AUDIO'>('IMAGE');

  // Tab 4: Fake News State
  const [newsMode, setNewsMode] = useState<'text' | 'media'>('text');
  const [claimText, setClaimText] = useState('');
  const [newsMediaFilename, setNewsMediaFilename] = useState('');
  const [newsMediaBase64, setNewsMediaBase64] = useState('');
  const [claimLoading, setClaimLoading] = useState(false);
  const [claimResult, setClaimResult] = useState<any>(null);

  const handleScanUrl = async (urlToScan?: string) => {
    const target = urlToScan || phishUrl;
    if (!target.trim()) return;
    setPhishLoading(true);
    try {
      const res = await client.scanUrl(target.trim());
      setPhishResult(res);
      const isDangerous = res.verdict?.threatLevel === 'DANGEROUS' || res.verdict?.riskScore >= 70;
      const isSafe = res.verdict?.threatLevel === 'SAFE' || res.verdict?.threatLevel === 'LOW' || res.verdict?.riskScore < 40;
      setPhishStatus(isDangerous ? 'danger' : isSafe ? 'safe' : 'idle');
    } catch (e: any) {
      setPhishResult({ error: e.message || String(e) });
    } finally {
      setPhishLoading(false);
    }
  };

  const handleCheckBreach = async () => {
    if (breachMode === 'password') {
      if (!password) return;
      setBreachLoading(true);
      try {
        const res = await client.checkPassword(password);
        setBreachResult(res);
        const isBreached = res.verdict?.threatLevel === 'DANGEROUS' || res.verdict?.threatLevel === 'SUSPICIOUS' || res.verdict?.riskScore >= 50;
        setBreachStatus(isBreached ? 'danger' : 'safe');
      } catch (e: any) {
        setBreachResult({ error: e.message || String(e) });
      } finally {
        setBreachLoading(false);
      }
    } else {
      if (!email.trim()) return;
      setBreachLoading(true);
      try {
        const res = await client.checkEmail(email.trim());
        setBreachResult(res);
        const isBreached = res.breachCount > 0 || res.verdict?.threatLevel === 'DANGEROUS' || res.verdict?.threatLevel === 'SUSPICIOUS';
        setBreachStatus(isBreached ? 'danger' : 'safe');
      } catch (e: any) {
        setBreachResult({ error: e.message || String(e) });
      } finally {
        setBreachLoading(false);
      }
    }
  };

  const handleScanDeepfake = async () => {
    if (!mediaBase64) return;
    setDeepfakeLoading(true);
    try {
      const res = await client.scanMedia({
        filename: mediaFilename || 'uploaded_sample.dat',
        base64: mediaBase64,
        mediaType
      });
      setDeepfakeResult(res);
      const isDeepfakeRes = res.verdict?.threatLevel === 'DANGEROUS' || res.verdict?.riskScore >= 60;
      const isAuthenticRes = res.verdict?.threatLevel === 'SAFE' || res.verdict?.riskScore < 35;
      setDeepfakeStatus(isDeepfakeRes ? 'danger' : isAuthenticRes ? 'safe' : 'idle');
    } catch (e: any) {
      setDeepfakeResult({ error: e.message || String(e) });
    } finally {
      setDeepfakeLoading(false);
    }
  };

  const handleCheckClaim = async () => {
    if (newsMode === 'text') {
      if (!claimText.trim()) return;
      setClaimLoading(true);
      try {
        const res = await client.checkClaim({ claimText: claimText.trim() });
        setClaimResult(res);
        const isFake = res.verdict?.threatLevel === 'DANGEROUS' || res.verdict?.riskScore >= 60;
        const isTrue = res.verdict?.threatLevel === 'SAFE' || res.verdict?.riskScore < 35;
        setFakeNewsStatus(isFake ? 'danger' : isTrue ? 'safe' : 'idle');
      } catch (e: any) {
        setClaimResult({ error: e.message || String(e) });
      } finally {
        setClaimLoading(false);
      }
    } else {
      if (!newsMediaBase64) return;
      setClaimLoading(true);
      try {
        const res = await client.checkClaim({
          claimText: claimText.trim() || 'Forwarded media claim',
          mediaBase64: newsMediaBase64,
          mediaType: 'IMAGE',
          context: 'MOBILE_APP'
        });
        setClaimResult(res);
        const isFake = res.verdict?.threatLevel === 'DANGEROUS' || res.verdict?.riskScore >= 60;
        const isTrue = res.verdict?.threatLevel === 'SAFE' || res.verdict?.riskScore < 35;
        setFakeNewsStatus(isFake ? 'danger' : isTrue ? 'safe' : 'idle');
      } catch (e: any) {
        setClaimResult({ error: e.message || String(e) });
      } finally {
        setClaimLoading(false);
      }
    }
  };

  const isPhishSafe = phishStatus === 'safe';
  const isPhishDangerous = phishStatus === 'danger';

  const isBreached = breachStatus === 'danger';
  const isDeepfake = deepfakeStatus === 'danger';
  const isAuthentic = deepfakeStatus === 'safe';

  const isFakeNews = fakeNewsStatus === 'danger';
  const isTrueNews = fakeNewsStatus === 'safe';

  // Dynamic Ambient Card Tint depending on live result
  const activeBgTint = useMemo(() => {
    if (activeTab === 'phishing') {
      if (phishStatus === 'danger') return '#2D0A0A';
      if (phishStatus === 'safe') return '#072A1F';
      return '#0E1E36';
    }
    if (activeTab === 'breach') {
      if (breachStatus === 'danger') return '#2D0A0A';
      if (breachStatus === 'safe') return '#072A1F';
      return '#261C08';
    }
    if (activeTab === 'deepfake') {
      if (deepfakeStatus === 'danger') return '#2D0A0A';
      if (deepfakeStatus === 'safe') return '#072A1F';
      return '#1F0F2E';
    }
    if (activeTab === 'fakenews') {
      if (fakeNewsStatus === 'danger') return '#2D0A0A';
      if (fakeNewsStatus === 'safe') return '#072A1F';
      return '#111D30';
    }
    return '#0E1626';
  }, [activeTab, phishStatus, breachStatus, deepfakeStatus, fakeNewsStatus]);

  return (
    <SafeAreaView style={[styles.container, { backgroundColor: activeBgTint }]}>
      <StatusBar barStyle="light-content" backgroundColor="#0B111E" />

      {/* Header */}
      <View style={styles.header}>
        <View style={styles.headerRow}>
          <TouchableOpacity
            style={styles.brandGroup}
            onPress={() => setActiveTab('home')}
          >
            <View style={styles.shieldIcon}>
              <Text style={styles.shieldIconText}>🛡️</Text>
            </View>
            <Text style={styles.title}>TrustShield</Text>
          </TouchableOpacity>
          <View style={[styles.statusPill, { backgroundColor: gatewayOnline ? '#065F46' : '#7F1D1D' }]}>
            <Text style={styles.statusText}>
              {gatewayOnline === true ? '● GATEWAY ONLINE' : gatewayOnline === false ? '● GATEWAY OFFLINE' : '○ CONNECTING...'}
            </Text>
          </View>
        </View>

        {/* Gateway LAN URL configuration */}
        <View style={styles.urlConfigRow}>
          <Text style={styles.urlLabel}>Gateway:</Text>
          <TextInput
            style={styles.urlInput}
            value={gatewayUrl}
            onChangeText={setGatewayUrl}
            placeholder="http://192.168.1.X:8080"
            placeholderTextColor="#64748B"
            autoCapitalize="none"
            autoCorrect={false}
          />
        </View>
      </View>

      {/* Nav Tabs */}
      <View style={styles.tabBar}>
        <TouchableOpacity
          style={[styles.tabButton, activeTab === 'home' && styles.tabButtonActive]}
          onPress={() => setActiveTab('home')}
        >
          <Text style={[styles.tabButtonText, activeTab === 'home' && styles.tabButtonTextActive]}>
            🏠 Front
          </Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={[styles.tabButton, activeTab === 'phishing' && styles.tabButtonActive]}
          onPress={() => setActiveTab('phishing')}
        >
          <Text style={[styles.tabButtonText, activeTab === 'phishing' && styles.tabButtonTextActive]}>
            🌐 Link
          </Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={[styles.tabButton, activeTab === 'breach' && styles.tabButtonActive]}
          onPress={() => setActiveTab('breach')}
        >
          <Text style={[styles.tabButtonText, activeTab === 'breach' && styles.tabButtonTextActive]}>
            🔑 Breach
          </Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={[styles.tabButton, activeTab === 'deepfake' && styles.tabButtonActive]}
          onPress={() => setActiveTab('deepfake')}
        >
          <Text style={[styles.tabButtonText, activeTab === 'deepfake' && styles.tabButtonTextActive]}>
            🖼️ Media
          </Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={[styles.tabButton, activeTab === 'fakenews' && styles.tabButtonActive]}
          onPress={() => setActiveTab('fakenews')}
        >
          <Text style={[styles.tabButtonText, activeTab === 'fakenews' && styles.tabButtonTextActive]}>
            📰 News
          </Text>
        </TouchableOpacity>
      </View>

      <ScrollView style={styles.content}>
        {/* Main Web Front Hero Screen */}
        {activeTab === 'home' && (
          <View style={styles.frontContainer}>
            <View style={styles.heroGlassCard}>
              {/* Globe / Attacks vs Shield Symbolic Art Container */}
              <View style={styles.artBanner}>
                <Text style={{ fontSize: 26 }}>⚡ ☠ ☣</Text>
                <View style={styles.globeCenter}>
                  <Text style={{ fontSize: 40 }}>🌐</Text>
                </View>
                <Text style={{ fontSize: 32 }}>🛡️ ✨</Text>
              </View>

              <Text style={styles.frontBadge}>CITIZEN FRAUD &amp; CYBER-DEFENSE</Text>
              <Text style={styles.frontTitle}>Defending Every Citizen Online</Text>
              <Text style={styles.frontSubtitle}>
                Instant safety verification, step-by-step account recovery actions, and direct official reporting channels.
              </Text>
            </View>

            {/* Service Access Launcher Cards */}
            <View style={styles.launcherGrid}>
              <TouchableOpacity
                style={[styles.launcherCard, { borderColor: '#38BDF8' }]}
                onPress={() => setActiveTab('phishing')}
              >
                <View style={styles.launcherIconBox}>
                  <Text style={{ fontSize: 24 }}>🌐</Text>
                </View>
                <View style={{ flex: 1 }}>
                  <Text style={styles.launcherTitle}>Phishing Shield</Text>
                  <Text style={styles.launcherDesc}>Check if website links or SMS URLs are fraudulent or safe.</Text>
                </View>
                <Text style={styles.launcherArrow}>→</Text>
              </TouchableOpacity>

              <TouchableOpacity
                style={[styles.launcherCard, { borderColor: '#F59E0B' }]}
                onPress={() => setActiveTab('breach')}
              >
                <View style={styles.launcherIconBox}>
                  <Text style={{ fontSize: 24 }}>🔑</Text>
                </View>
                <View style={{ flex: 1 }}>
                  <Text style={styles.launcherTitle}>Breach Monitor</Text>
                  <Text style={styles.launcherDesc}>Verify if passwords or email IDs were leaked in known hacks.</Text>
                </View>
                <Text style={styles.launcherArrow}>→</Text>
              </TouchableOpacity>

              <TouchableOpacity
                style={[styles.launcherCard, { borderColor: '#C084FC' }]}
                onPress={() => setActiveTab('deepfake')}
              >
                <View style={styles.launcherIconBox}>
                  <Text style={{ fontSize: 24 }}>🖼️</Text>
                </View>
                <View style={{ flex: 1 }}>
                  <Text style={styles.launcherTitle}>Deepfake Forensics</Text>
                  <Text style={styles.launcherDesc}>Detect AI-generated faces, video edits, and voice clones.</Text>
                </View>
                <Text style={styles.launcherArrow}>→</Text>
              </TouchableOpacity>

              <TouchableOpacity
                style={[styles.launcherCard, { borderColor: '#34D399' }]}
                onPress={() => setActiveTab('fakenews')}
              >
                <View style={styles.launcherIconBox}>
                  <Text style={{ fontSize: 24 }}>📰</Text>
                </View>
                <View style={{ flex: 1 }}>
                  <Text style={styles.launcherTitle}>Fake News Firewall</Text>
                  <Text style={styles.launcherDesc}>Verify viral claims, WhatsApp forwards, and rumors.</Text>
                </View>
                <Text style={styles.launcherArrow}>→</Text>
              </TouchableOpacity>
            </View>
          </View>
        )}

        {/* Phishing Tab */}
        {activeTab === 'phishing' && (
          <View style={styles.card}>
            <Text style={styles.cardTitle}>Website Safety &amp; Link Checker</Text>
            <Text style={styles.cardSubtitle}>Check whether any link or SMS website is safe or dangerous</Text>

            <TextInput
              style={styles.input}
              value={phishUrl}
              onChangeText={setPhishUrl}
              placeholder="Enter the URL"
              placeholderTextColor="#64748B"
              autoCapitalize="none"
              autoCorrect={false}
            />

            <View style={styles.buttonRow}>
              <TouchableOpacity
                style={styles.primaryButton}
                onPress={() => handleScanUrl()}
                disabled={phishLoading}
              >
                {phishLoading ? <ActivityIndicator color="#FFF" /> : <Text style={styles.primaryButtonText}>Check Link Safety</Text>}
              </TouchableOpacity>
            </View>

            {phishResult && (
              <View style={[styles.resultCard, { borderLeftColor: isPhishSafe ? '#10B981' : isPhishDangerous ? '#EF4444' : '#F59E0B' }]}>
                {phishResult.error ? (
                  <Text style={styles.errorText}>Error: {phishResult.error}</Text>
                ) : (
                  <>
                    <View style={styles.outcomeRow}>
                      <Text style={{ fontSize: 28 }}>{isPhishSafe ? '✅' : isPhishDangerous ? '🚨' : '⚠️'}</Text>
                      <View style={{ flex: 1 }}>
                        <Text style={[styles.outcomeTitle, { color: isPhishSafe ? '#34D399' : isPhishDangerous ? '#F87171' : '#FBBF24' }]}>
                          {isPhishSafe ? 'Link is Safe & Secure' : isPhishDangerous ? 'Dangerous Phishing Link Detected!' : 'Caution: Unverified Link'}
                        </Text>
                        <Text style={styles.outcomeDesc}>
                          {isPhishSafe
                            ? 'No malicious patterns or deceptive login clones detected.'
                            : isPhishDangerous
                            ? 'Do NOT enter passwords, OTPs, or bank details on this website!'
                            : 'This website lacks public verification. Be careful before proceeding.'}
                        </Text>
                      </View>
                    </View>

                    {/* Preview box */}
                    <View style={styles.previewBox}>
                      <Text style={styles.previewLabel}>🔗 Link Preview:</Text>
                      <Text style={styles.previewUrl} numberOfLines={1}>{phishResult.url}</Text>
                      <TouchableOpacity
                        style={styles.openLinkBtn}
                        onPress={() => {
                          const u = phishResult.url.startsWith('http') ? phishResult.url : `https://${phishResult.url}`;
                          Linking.openURL(u).catch(() => {});
                        }}
                      >
                        <Text style={styles.openLinkText}>Open in Browser ↗</Text>
                      </TouchableOpacity>
                    </View>

                    {isPhishDangerous && (
                      <TouchableOpacity
                        style={styles.reportBtn}
                        onPress={() => Linking.openURL('https://cybercrime.gov.in').catch(() => {})}
                      >
                        <Text style={styles.reportBtnText}>🚨 Report to Cyber Crime Portal (cybercrime.gov.in) ↗</Text>
                      </TouchableOpacity>
                    )}
                  </>
                )}
              </View>
            )}
          </View>
        )}

        {/* Breach Tab */}
        {activeTab === 'breach' && (
          <View style={styles.card}>
            <Text style={styles.cardTitle}>Password &amp; Email Breach Monitor</Text>
            <Text style={styles.cardSubtitle}>Check if your password or email was leaked in public breaches</Text>

            {/* Toggle Mode */}
            <View style={styles.subToggleRow}>
              <TouchableOpacity
                style={[styles.subToggleButton, breachMode === 'password' && styles.subToggleButtonActive]}
                onPress={() => setBreachMode('password')}
              >
                <Text style={[styles.subToggleText, breachMode === 'password' && styles.subToggleTextActive]}>Password Check</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={[styles.subToggleButton, breachMode === 'email' && styles.subToggleButtonActive]}
                onPress={() => setBreachMode('email')}
              >
                <Text style={[styles.subToggleText, breachMode === 'email' && styles.subToggleTextActive]}>Email Breach Check</Text>
              </TouchableOpacity>
            </View>

            {breachMode === 'password' ? (
              <TextInput
                style={styles.input}
                value={password}
                onChangeText={setPassword}
                secureTextEntry
                placeholder="Enter the password"
                placeholderTextColor="#64748B"
              />
            ) : (
              <TextInput
                style={styles.input}
                value={email}
                onChangeText={setEmail}
                keyboardType="email-address"
                autoCapitalize="none"
                placeholder="Enter the Email"
                placeholderTextColor="#64748B"
              />
            )}

            <TouchableOpacity
              style={[styles.primaryButton, { backgroundColor: '#F59E0B' }]}
              onPress={handleCheckBreach}
              disabled={breachLoading}
            >
              {breachLoading ? <ActivityIndicator color="#000" /> : <Text style={[styles.primaryButtonText, { color: '#000' }]}>{breachMode === 'password' ? 'Check Password Safety' : 'Check Email Breaches'}</Text>}
            </TouchableOpacity>

            {breachResult && (
              <View style={[styles.resultCard, { borderLeftColor: isBreached ? '#EF4444' : '#10B981' }]}>
                {breachResult.error ? (
                  <Text style={styles.errorText}>Error: {breachResult.error}</Text>
                ) : (
                  <>
                    <View style={styles.outcomeRow}>
                      <Text style={{ fontSize: 28 }}>{isBreached ? '🚨' : '✅'}</Text>
                      <View style={{ flex: 1 }}>
                        <Text style={[styles.outcomeTitle, { color: isBreached ? '#F87171' : '#34D399' }]}>
                          {isBreached ? 'Compromised in Data Breach!' : 'No Breaches Found'}
                        </Text>
                        <Text style={styles.outcomeDesc}>
                          {isBreached
                            ? 'This credential appears in hacker leak databases. Take immediate protective action.'
                            : 'This credential was not found in known public leak databases.'}
                        </Text>
                      </View>
                    </View>

                    {/* Step by Step Action Guide */}
                    {isBreached && (
                      <View style={styles.actionGuide}>
                        <Text style={styles.actionGuideTitle}>🛠️ Steps to Secure Your Account:</Text>
                        <Text style={styles.actionStep}>• 1. Change this password immediately on all accounts where you use it.</Text>
                        <Text style={styles.actionStep}>• 2. Enable 2-Factor Authentication (2FA / OTP) for banking &amp; email.</Text>
                        <Text style={styles.actionStep}>• 3. Never reuse this password for new registrations.</Text>
                      </View>
                    )}
                  </>
                )}
              </View>
            )}
          </View>
        )}

        {/* Deepfake Tab */}
        {activeTab === 'deepfake' && (
          <View style={styles.card}>
            <Text style={styles.cardTitle}>Deepfake &amp; Fake Media Detector</Text>
            <Text style={styles.cardSubtitle}>Check if photos, videos, or audio are AI-generated / deepfaked</Text>

            <View style={styles.subToggleRow}>
              {(['IMAGE', 'VIDEO', 'AUDIO'] as const).map(t => (
                <TouchableOpacity
                  key={t}
                  style={[styles.subToggleButton, mediaType === t && styles.subToggleButtonActive]}
                  onPress={() => setMediaType(t)}
                >
                  <Text style={[styles.subToggleText, mediaType === t && styles.subToggleTextActive]}>{t}</Text>
                </TouchableOpacity>
              ))}
            </View>

            <TextInput
              style={styles.input}
              value={mediaFilename}
              onChangeText={setMediaFilename}
              placeholder="Filename (e.g. photo.jpg, clip.mp4)"
              placeholderTextColor="#64748B"
            />

            <TextInput
              style={[styles.input, { minHeight: 60 }]}
              value={mediaBase64}
              onChangeText={setMediaBase64}
              multiline
              placeholder="Paste Base64 encoded media payload or file data..."
              placeholderTextColor="#64748B"
            />

            <TouchableOpacity
              style={[styles.primaryButton, { backgroundColor: '#0284C7' }]}
              onPress={handleScanDeepfake}
              disabled={deepfakeLoading || !mediaBase64}
            >
              {deepfakeLoading ? <ActivityIndicator color="#FFF" /> : <Text style={styles.primaryButtonText}>Analyze Media</Text>}
            </TouchableOpacity>

            {deepfakeResult && (
              <View style={[styles.resultCard, { borderLeftColor: isAuthentic ? '#10B981' : isDeepfake ? '#EF4444' : '#F59E0B' }]}>
                {deepfakeResult.error ? (
                  <Text style={styles.errorText}>Error: {deepfakeResult.error}</Text>
                ) : (
                  <>
                    <View style={styles.outcomeRow}>
                      <Text style={{ fontSize: 28 }}>{isAuthentic ? '✅' : isDeepfake ? '🚨' : '⚠️'}</Text>
                      <View style={{ flex: 1 }}>
                        <Text style={[styles.outcomeTitle, { color: isAuthentic ? '#34D399' : isDeepfake ? '#F87171' : '#FBBF24' }]}>
                          {isAuthentic ? 'Genuine / Natural Media' : isDeepfake ? 'AI Deepfake Detected!' : 'Inconclusive / Compressed'}
                        </Text>
                        <Text style={styles.outcomeDesc}>
                          {isAuthentic
                            ? 'Natural biometric patterns and organic camera sensor traces confirmed.'
                            : isDeepfake
                            ? 'Signs of synthetic face swapping or generative AI voice synthesis detected.'
                            : 'Heavy compression over messaging apps obscured natural forensic traces.'}
                        </Text>
                      </View>
                    </View>

                    {/* Reporting Guidelines */}
                    {isDeepfake && (
                      <View style={styles.actionGuide}>
                        <Text style={styles.actionGuideTitle}>📢 How to Report this Deepfake:</Text>
                        <Text style={styles.actionStep}>• 1. Dial National Cyber Helpline: 1930 (Toll-Free, 24x7).</Text>
                        <Text style={styles.actionStep}>• 2. File an official complaint on cybercrime.gov.in.</Text>
                        <Text style={styles.actionStep}>• 3. Report the post on the social media platform as "Impersonation / Deepfake".</Text>
                        <TouchableOpacity
                          style={[styles.reportBtn, { marginTop: 8 }]}
                          onPress={() => Linking.openURL('https://cybercrime.gov.in').catch(() => {})}
                        >
                          <Text style={styles.reportBtnText}>Open Cyber Crime Portal ↗</Text>
                        </TouchableOpacity>
                      </View>
                    )}
                  </>
                )}
              </View>
            )}
          </View>
        )}

        {/* Fake News Tab */}
        {activeTab === 'fakenews' && (
          <View style={styles.card}>
            <Text style={styles.cardTitle}>Fake News &amp; Rumor Fact-Checker</Text>
            <Text style={styles.cardSubtitle}>Verify viral WhatsApp forwards, screenshots, and rumors</Text>

            {/* Sub-mode selector */}
            <View style={styles.subToggleRow}>
              <TouchableOpacity
                style={[styles.subToggleButton, newsMode === 'text' && styles.subToggleButtonActive]}
                onPress={() => setNewsMode('text')}
              >
                <Text style={[styles.subToggleText, newsMode === 'text' && styles.subToggleTextActive]}>Text Claim</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={[styles.subToggleButton, newsMode === 'media' && styles.subToggleButtonActive]}
                onPress={() => setNewsMode('media')}
              >
                <Text style={[styles.subToggleText, newsMode === 'media' && styles.subToggleTextActive]}>Image / Video News</Text>
              </TouchableOpacity>
            </View>

            {newsMode === 'text' ? (
              <TextInput
                style={[styles.input, { minHeight: 70 }]}
                value={claimText}
                onChangeText={setClaimText}
                multiline
                placeholder="Paste the news message or viral rumor you want to check..."
                placeholderTextColor="#64748B"
              />
            ) : (
              <View>
                <TextInput
                  style={styles.input}
                  value={newsMediaFilename}
                  onChangeText={setNewsMediaFilename}
                  placeholder="News screenshot/video filename (e.g. news_clip.jpg)"
                  placeholderTextColor="#64748B"
                />
                <TextInput
                  style={[styles.input, { minHeight: 60 }]}
                  value={newsMediaBase64}
                  onChangeText={setNewsMediaBase64}
                  multiline
                  placeholder="Paste Base64 data of screenshot or clipping..."
                  placeholderTextColor="#64748B"
                />
                <TextInput
                  style={styles.input}
                  value={claimText}
                  onChangeText={setClaimText}
                  placeholder="Optional claim caption or context text"
                  placeholderTextColor="#64748B"
                />
              </View>
            )}

            <TouchableOpacity
              style={[styles.primaryButton, { backgroundColor: '#8B5CF6' }]}
              onPress={handleCheckClaim}
              disabled={claimLoading}
            >
              {claimLoading ? <ActivityIndicator color="#FFF" /> : <Text style={styles.primaryButtonText}>Verify Claim</Text>}
            </TouchableOpacity>

            {claimResult && (
              <View style={[styles.resultCard, { borderLeftColor: isTrueNews ? '#10B981' : isFakeNews ? '#EF4444' : '#F59E0B' }]}>
                {claimResult.error ? (
                  <Text style={styles.errorText}>Error: {claimResult.error}</Text>
                ) : (
                  <>
                    <View style={styles.outcomeRow}>
                      <Text style={{ fontSize: 28 }}>{isTrueNews ? '✅' : isFakeNews ? '🚨' : '⚠️'}</Text>
                      <View style={{ flex: 1 }}>
                        <Text style={[styles.outcomeTitle, { color: isTrueNews ? '#34D399' : isFakeNews ? '#F87171' : '#FBBF24' }]}>
                          {isTrueNews ? 'Verified Authentic News' : isFakeNews ? 'False / Debunked Fake News!' : 'Unverified Viral Rumor'}
                        </Text>
                        <Text style={styles.outcomeDesc}>
                          {isTrueNews
                            ? 'This claim matches verified news sources and official records.'
                            : isFakeNews
                            ? 'Debunked by verified fact-checkers. Do not forward this in chat groups!'
                            : 'Unconfirmed rumor without corroboration from news agencies.'}
                        </Text>
                      </View>
                    </View>

                    {/* How to Report Fake News */}
                    {isFakeNews && (
                      <View style={styles.actionGuide}>
                        <Text style={styles.actionGuideTitle}>📢 How to Report this Fake News:</Text>
                        <Text style={styles.actionStep}>• 1. WhatsApp to PIB Fact Check: +91 8799711259.</Text>
                        <Text style={styles.actionStep}>• 2. Email Govt Fact-Checkers: pibfactcheck@gmail.com.</Text>
                        <Text style={styles.actionStep}>• 3. Tell the sender in group chats that this is debunked fake news.</Text>
                        <TouchableOpacity
                          style={[styles.reportBtn, { marginTop: 8 }]}
                          onPress={() => Linking.openURL('https://factcheck.pib.gov.in').catch(() => {})}
                        >
                          <Text style={styles.reportBtnText}>Open PIB Fact-Check Website ↗</Text>
                        </TouchableOpacity>
                      </View>
                    )}
                  </>
                )}
              </View>
            )}
          </View>
        )}

        {/* Footer Note */}
        <View style={styles.footer}>
          <Text style={styles.footerText}>
            TrustShield Cyber-Defense Platform · Citizen Shield
          </Text>
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1
  },
  header: {
    padding: 16,
    backgroundColor: 'rgba(15, 23, 42, 0.85)',
    borderBottomWidth: 1,
    borderBottomColor: 'rgba(255, 255, 255, 0.12)'
  },
  headerRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 8
  },
  brandGroup: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8
  },
  shieldIcon: {
    width: 32,
    height: 32,
    borderRadius: 8,
    backgroundColor: '#0284C7',
    alignItems: 'center',
    justifyContent: 'center',
    borderWidth: 1,
    borderColor: '#38BDF8'
  },
  shieldIconText: {
    fontSize: 18
  },
  title: {
    fontSize: 18,
    fontWeight: '900',
    color: '#F8FAFC'
  },
  statusPill: {
    paddingHorizontal: 8,
    paddingVertical: 4,
    borderRadius: 999
  },
  statusText: {
    fontSize: 10,
    fontWeight: '700',
    color: '#FFFFFF'
  },
  urlConfigRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8
  },
  urlLabel: {
    fontSize: 12,
    color: '#94A3B8',
    fontWeight: '600'
  },
  urlInput: {
    flex: 1,
    backgroundColor: 'rgba(11, 17, 30, 0.8)',
    borderWidth: 1,
    borderColor: 'rgba(255, 255, 255, 0.15)',
    borderRadius: 6,
    paddingHorizontal: 8,
    paddingVertical: 4,
    color: '#F8FAFC',
    fontSize: 12,
    fontFamily: 'monospace'
  },
  tabBar: {
    flexDirection: 'row',
    backgroundColor: 'rgba(15, 23, 42, 0.85)',
    borderBottomWidth: 1,
    borderBottomColor: 'rgba(255, 255, 255, 0.12)',
    paddingHorizontal: 4
  },
  tabButton: {
    flex: 1,
    paddingVertical: 12,
    alignItems: 'center',
    borderBottomWidth: 2,
    borderBottomColor: 'transparent'
  },
  tabButtonActive: {
    borderBottomColor: '#0284C7'
  },
  tabButtonText: {
    fontSize: 11,
    color: '#94A3B8',
    fontWeight: '600'
  },
  tabButtonTextActive: {
    color: '#38BDF8',
    fontWeight: '800'
  },
  content: {
    flex: 1,
    padding: 16
  },
  frontContainer: {
    gap: 16,
    marginBottom: 20
  },
  heroGlassCard: {
    backgroundColor: 'rgba(21, 34, 56, 0.75)',
    borderWidth: 1,
    borderColor: 'rgba(56, 189, 248, 0.3)',
    borderRadius: 16,
    padding: 20,
    alignItems: 'center'
  },
  artBanner: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 16,
    marginBottom: 12
  },
  globeCenter: {
    width: 64,
    height: 64,
    borderRadius: 32,
    backgroundColor: 'rgba(2, 132, 199, 0.2)',
    borderWidth: 1.5,
    borderColor: '#38BDF8',
    alignItems: 'center',
    justifyContent: 'center'
  },
  frontBadge: {
    fontSize: 11,
    fontWeight: '800',
    color: '#38BDF8',
    letterSpacing: 1,
    marginBottom: 6
  },
  frontTitle: {
    fontSize: 22,
    fontWeight: '900',
    color: '#FFFFFF',
    textAlign: 'center',
    marginBottom: 8
  },
  frontSubtitle: {
    fontSize: 13,
    color: '#CBD5E1',
    textAlign: 'center',
    lineHeight: 18
  },
  launcherGrid: {
    gap: 12
  },
  launcherCard: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: 'rgba(21, 34, 56, 0.75)',
    borderWidth: 1,
    borderRadius: 12,
    padding: 14,
    gap: 12
  },
  launcherIconBox: {
    width: 44,
    height: 44,
    borderRadius: 8,
    backgroundColor: 'rgba(255, 255, 255, 0.08)',
    alignItems: 'center',
    justifyContent: 'center'
  },
  launcherTitle: {
    fontSize: 15,
    fontWeight: '800',
    color: '#FFFFFF'
  },
  launcherDesc: {
    fontSize: 11,
    color: '#94A3B8',
    marginTop: 2
  },
  launcherArrow: {
    fontSize: 18,
    color: '#38BDF8',
    fontWeight: '800'
  },
  card: {
    backgroundColor: 'rgba(21, 34, 56, 0.75)',
    borderWidth: 1,
    borderColor: 'rgba(255, 255, 255, 0.12)',
    borderRadius: 12,
    padding: 16,
    marginBottom: 16
  },
  cardTitle: {
    fontSize: 16,
    fontWeight: '700',
    color: '#F8FAFC',
    marginBottom: 4
  },
  cardSubtitle: {
    fontSize: 12,
    color: '#94A3B8',
    marginBottom: 12
  },
  subToggleRow: {
    flexDirection: 'row',
    backgroundColor: 'rgba(11, 17, 30, 0.8)',
    borderRadius: 8,
    padding: 4,
    marginBottom: 12,
    borderWidth: 1,
    borderColor: 'rgba(255, 255, 255, 0.12)',
    gap: 4
  },
  subToggleButton: {
    flex: 1,
    paddingVertical: 8,
    alignItems: 'center',
    borderRadius: 6
  },
  subToggleButtonActive: {
    backgroundColor: 'rgba(30, 41, 59, 0.9)'
  },
  subToggleText: {
    fontSize: 12,
    color: '#94A3B8',
    fontWeight: '600'
  },
  subToggleTextActive: {
    color: '#38BDF8',
    fontWeight: '700'
  },
  input: {
    backgroundColor: 'rgba(11, 17, 30, 0.85)',
    borderWidth: 1,
    borderColor: 'rgba(255, 255, 255, 0.15)',
    borderRadius: 8,
    padding: 12,
    color: '#F8FAFC',
    fontSize: 13,
    marginBottom: 12
  },
  buttonRow: {
    marginBottom: 12
  },
  primaryButton: {
    backgroundColor: '#0284C7',
    borderRadius: 8,
    paddingVertical: 12,
    alignItems: 'center',
    justifyContent: 'center'
  },
  primaryButtonText: {
    color: '#FFFFFF',
    fontWeight: '700',
    fontSize: 14
  },
  resultCard: {
    backgroundColor: 'rgba(11, 17, 30, 0.85)',
    borderWidth: 1,
    borderColor: 'rgba(255, 255, 255, 0.12)',
    borderLeftWidth: 4,
    borderRadius: 8,
    padding: 14,
    marginTop: 8
  },
  outcomeRow: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: 12
  },
  outcomeTitle: {
    fontSize: 15,
    fontWeight: '800'
  },
  outcomeDesc: {
    fontSize: 12,
    color: '#CBD5E1',
    marginTop: 4,
    lineHeight: 18
  },
  previewBox: {
    marginTop: 12,
    padding: 10,
    backgroundColor: 'rgba(21, 34, 56, 0.9)',
    borderRadius: 6,
    borderWidth: 1,
    borderColor: 'rgba(255, 255, 255, 0.12)'
  },
  previewLabel: {
    fontSize: 11,
    color: '#94A3B8',
    fontWeight: '700'
  },
  previewUrl: {
    fontSize: 11,
    color: '#38BDF8',
    fontFamily: 'monospace',
    marginTop: 2
  },
  openLinkBtn: {
    marginTop: 8,
    alignSelf: 'flex-start',
    backgroundColor: 'rgba(30, 41, 59, 0.9)',
    paddingHorizontal: 8,
    paddingVertical: 4,
    borderRadius: 4,
    borderWidth: 1,
    borderColor: '#334E68'
  },
  openLinkText: {
    fontSize: 11,
    color: '#38BDF8',
    fontWeight: '700'
  },
  reportBtn: {
    marginTop: 10,
    backgroundColor: 'rgba(239, 68, 68, 0.2)',
    borderWidth: 1,
    borderColor: '#EF4444',
    padding: 8,
    borderRadius: 6,
    alignItems: 'center'
  },
  reportBtnText: {
    color: '#FCA5A5',
    fontSize: 12,
    fontWeight: '700'
  },
  actionGuide: {
    marginTop: 12,
    paddingTop: 10,
    borderTopWidth: 1,
    borderTopColor: 'rgba(255, 255, 255, 0.12)'
  },
  actionGuideTitle: {
    fontSize: 12,
    fontWeight: '800',
    color: '#F8FAFC',
    marginBottom: 6
  },
  actionStep: {
    fontSize: 11,
    color: '#CBD5E1',
    lineHeight: 18,
    marginBottom: 4
  },
  errorText: {
    color: '#F87171',
    fontSize: 12
  },
  footer: {
    paddingVertical: 24,
    alignItems: 'center'
  },
  footerText: {
    fontSize: 11,
    color: '#64748B'
  }
});
