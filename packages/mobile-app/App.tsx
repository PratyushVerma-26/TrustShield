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
  StatusBar
} from 'react-native';
import {
  TrustShieldApiClient,
  Verdict,
  normalizeVerdict,
  getBadgePresentation,
  formatDisplayScore,
  ThreatLevel
} from '@trustshield/verdict-core';

type Tab = 'phishing' | 'breach' | 'deepfake' | 'fakenews' | 'fusion' | 'ledger';

export default function App() {
  const [gatewayUrl, setGatewayUrl] = useState('http://localhost:8080');
  const [activeTab, setActiveTab] = useState<Tab>('phishing');
  const [gatewayOnline, setGatewayOnline] = useState<boolean | null>(null);

  // Dynamic API client bound to user-configured gateway URL (LAN IP or emulator)
  const client = useMemo(() => new TrustShieldApiClient(gatewayUrl), [gatewayUrl]);

  useEffect(() => {
    client.getGatewayHealth()
      .then(() => setGatewayOnline(true))
      .catch(() => setGatewayOnline(false));
  }, [client]);

  // Tab 1: Phishing State
  const [phishUrl, setPhishUrl] = useState('https://sbi-verification-login.tk/auth');
  const [phishLoading, setPhishLoading] = useState(false);
  const [phishResult, setPhishResult] = useState<any>(null);

  // Tab 2: Breach State
  const [password, setPassword] = useState('Password123!');
  const [breachLoading, setBreachLoading] = useState(false);
  const [breachResult, setBreachResult] = useState<any>(null);

  // Tab 3: Deepfake State
  const [deepfakeLoading, setDeepfakeLoading] = useState(false);
  const [deepfakeResult, setDeepfakeResult] = useState<any>(null);

  // Tab 4: Fake News State
  const [claimText, setClaimText] = useState('UNESCO declared Indian national anthem best in the world');
  const [claimLoading, setClaimLoading] = useState(false);
  const [claimResult, setClaimResult] = useState<any>(null);

  // Tab 5: Fusion State
  const [fusionLoading, setFusionLoading] = useState(false);
  const [fusionResult, setFusionResult] = useState<any>(null);

  // Tab 6: Ledger State
  const [ledgerLoading, setLedgerLoading] = useState(false);
  const [ledgerResult, setLedgerResult] = useState<any>(null);

  const handleScanUrl = async (urlToScan?: string) => {
    const target = urlToScan || phishUrl;
    if (!target) return;
    setPhishLoading(true);
    try {
      const res = await client.scanUrl(target);
      setPhishResult(res);
    } catch (e: any) {
      setPhishResult({ error: e.message || String(e) });
    } finally {
      setPhishLoading(false);
    }
  };

  const handleCheckPassword = async () => {
    if (!password) return;
    setBreachLoading(true);
    try {
      const res = await client.checkPassword(password);
      setBreachResult(res);
    } catch (e: any) {
      setBreachResult({ error: e.message || String(e) });
    } finally {
      setBreachLoading(false);
    }
  };

  const handleDeepfakeSample = async (sample: { filename: string; base64: string; mediaType: string }) => {
    setDeepfakeLoading(true);
    try {
      const res = await client.scanMedia(sample);
      setDeepfakeResult(res);
    } catch (e: any) {
      setDeepfakeResult({ error: e.message || String(e) });
    } finally {
      setDeepfakeLoading(false);
    }
  };

  const handleCheckClaim = async () => {
    if (!claimText) return;
    setClaimLoading(true);
    try {
      const res = await client.checkClaim({ text: claimText });
      setClaimResult(res);
    } catch (e: any) {
      setClaimResult({ error: e.message || String(e) });
    } finally {
      setClaimLoading(false);
    }
  };

  const handleFusionDemo = async () => {
    setFusionLoading(true);
    try {
      const res = await client.evaluateFusion([
        {
          module: 'PHISHING',
          riskScore: 65,
          threatLevel: 'SUSPICIOUS',
          verdict: 'SUSPICIOUS_DOMAIN_ENTROPY',
          explanation: 'Elevated character entropy in subdomain',
          signals: [],
          latencyMs: 3,
          degraded: false
        },
        {
          module: 'DEEPFAKE',
          riskScore: 60,
          threatLevel: 'SUSPICIOUS',
          verdict: 'UNNATURAL_SMOOTHNESS',
          explanation: 'Spatial noise residual lacks organic sensor variance',
          signals: [],
          latencyMs: 14,
          degraded: false
        }
      ], true);
      setFusionResult(res);
    } catch (e: any) {
      setFusionResult({ error: e.message || String(e) });
    } finally {
      setFusionLoading(false);
    }
  };

  const handleVerifyLedger = async () => {
    setLedgerLoading(true);
    try {
      const res = await client.verifyLedger();
      setLedgerResult(res);
    } catch (e: any) {
      setLedgerResult({ error: e.message || String(e) });
    } finally {
      setLedgerLoading(false);
    }
  };

  const renderBadge = (v: any) => {
    if (!v) return null;
    const norm = 'isConclusive' in v ? v : normalizeVerdict(v);
    const badge = getBadgePresentation(norm);

    let bgColor = '#475569';
    if (norm.isConclusive) {
      switch (norm.threatLevel) {
        case 'DANGEROUS': bgColor = '#DC2626'; break;
        case 'SUSPICIOUS': bgColor = '#D97706'; break;
        case 'SAFE': bgColor = '#16A34A'; break;
        case 'LOW': bgColor = '#0284C7'; break;
      }
    }

    return (
      <View style={[styles.badge, { backgroundColor: bgColor }]}>
        <Text style={styles.badgeText}>
          {badge.badgeEmoji} {badge.badgeText} ({badge.scoreDisplay})
        </Text>
      </View>
    );
  };

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor="#0B0F19" />

      {/* Header */}
      <View style={styles.header}>
        <View style={styles.headerRow}>
          <Text style={styles.title}>TrustShield Mobile</Text>
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
        {(['phishing', 'breach', 'deepfake', 'fakenews', 'fusion', 'ledger'] as Tab[]).map((tab) => (
          <TouchableOpacity
            key={tab}
            style={[styles.tabButton, activeTab === tab && styles.tabButtonActive]}
            onPress={() => setActiveTab(tab)}
          >
            <Text style={[styles.tabButtonText, activeTab === tab && styles.tabButtonTextActive]}>
              {tab === 'phishing' && '🌐 Phish'}
              {tab === 'breach' && '🔑 Breach'}
              {tab === 'deepfake' && '🖼️ Media'}
              {tab === 'fakenews' && '📰 Claims'}
              {tab === 'fusion' && '⚡ Fusion'}
              {tab === 'ledger' && '⛓️ Ledger'}
            </Text>
          </TouchableOpacity>
        ))}
      </View>

      <ScrollView style={styles.content}>
        {/* Phishing Tab */}
        {activeTab === 'phishing' && (
          <View style={styles.card}>
            <Text style={styles.cardTitle}>Phishing URL Scanner</Text>
            <Text style={styles.cardSubtitle}>26-Feature Lexical Classifier + Safe Browsing</Text>

            <TextInput
              style={styles.input}
              value={phishUrl}
              onChangeText={setPhishUrl}
              placeholder="Enter URL to assess..."
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
                {phishLoading ? <ActivityIndicator color="#FFF" /> : <Text style={styles.primaryButtonText}>Scan URL</Text>}
              </TouchableOpacity>
            </View>

            {/* Presets */}
            <View style={styles.presetRow}>
              <Text style={styles.presetLabel}>Presets:</Text>
              <TouchableOpacity
                style={styles.presetChip}
                onPress={() => { setPhishUrl('https://sbi-verification-login.tk/auth'); handleScanUrl('https://sbi-verification-login.tk/auth'); }}
              >
                <Text style={styles.presetChipText}>SBI Phish</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={styles.presetChip}
                onPress={() => { setPhishUrl('https://google.com'); handleScanUrl('https://google.com'); }}
              >
                <Text style={styles.presetChipText}>Google</Text>
              </TouchableOpacity>
            </View>

            {phishResult && (
              <View style={styles.resultBox}>
                {phishResult.error ? (
                  <Text style={styles.errorText}>Error: {phishResult.error}</Text>
                ) : (
                  <>
                    <View style={styles.resultHeader}>
                      <Text style={styles.resultUrl} numberOfLines={1}>{phishResult.url}</Text>
                      {renderBadge(phishResult.verdict)}
                    </View>
                    <Text style={styles.explanationText}>{phishResult.verdict?.explanation}</Text>
                    <Text style={styles.metaText}>
                      Model: {phishResult.model?.version} ({phishResult.model?.provenance})
                    </Text>
                  </>
                )}
              </View>
            )}
          </View>
        )}

        {/* Breach Tab */}
        {activeTab === 'breach' && (
          <View style={styles.card}>
            <Text style={styles.cardTitle}>Personal Breach Monitor</Text>
            <Text style={styles.cardSubtitle}>k-Anonymity (5-character SHA-1 prefix)</Text>

            <TextInput
              style={styles.input}
              value={password}
              onChangeText={setPassword}
              secureTextEntry
              placeholder="Enter password..."
              placeholderTextColor="#64748B"
            />

            <TouchableOpacity
              style={[styles.primaryButton, { backgroundColor: '#F59E0B' }]}
              onPress={handleCheckPassword}
              disabled={breachLoading}
            >
              {breachLoading ? <ActivityIndicator color="#000" /> : <Text style={[styles.primaryButtonText, { color: '#000' }]}>Verify Password Exposure</Text>}
            </TouchableOpacity>

            {breachResult && (
              <View style={styles.resultBox}>
                {breachResult.error ? (
                  <Text style={styles.errorText}>Error: {breachResult.error}</Text>
                ) : (
                  <>
                    <View style={styles.resultHeader}>
                      <Text style={styles.resultTitle}>{breachResult.verdict?.verdict}</Text>
                      {renderBadge(breachResult.verdict)}
                    </View>
                    <Text style={styles.explanationText}>{breachResult.recommendation}</Text>
                    <Text style={styles.kAnonBox}>
                      🔒 Sent SHA-1 prefix: {breachResult.bucketPrefix} (5 of 40 chars)
                    </Text>
                    <Text style={styles.metaText}>
                      Structural length: {breachResult.strength?.length} chars · Entropy: {breachResult.strength?.entropy?.toFixed(1)} bits
                    </Text>
                  </>
                )}
              </View>
            )}
          </View>
        )}

        {/* Deepfake Tab */}
        {activeTab === 'deepfake' && (
          <View style={styles.card}>
            <Text style={styles.cardTitle}>Synthetic Media Forensics</Text>
            <Text style={styles.cardSubtitle}>ELA, DQT Fingerprint, Noise Residual, C2PA Presence</Text>

            <View style={styles.sampleButtonGroup}>
              <TouchableOpacity
                style={styles.sampleButton}
                onPress={() => handleDeepfakeSample({
                  filename: 'voice_clone_deepfake.mp4',
                  base64: 'AAAAIGZ0eXBtcDQyAAAAAG1wNDJpc29tYXZjMQAA',
                  mediaType: 'VIDEO'
                })}
              >
                <Text style={styles.sampleButtonText}>📹 Deepfake Video (Acoustic Spectral Roll-off)</Text>
              </TouchableOpacity>

              <TouchableOpacity
                style={styles.sampleButton}
                onPress={() => handleDeepfakeSample({
                  filename: 'whatsapp_recompressed.jpg',
                  base64: '/9j/4AAQSkZJRgABAgAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQN',
                  mediaType: 'IMAGE'
                })}
              >
                <Text style={styles.sampleButtonText}>📷 Recompressed Photo (UNKNOWN Failure Case)</Text>
              </TouchableOpacity>
            </View>

            {deepfakeLoading && <ActivityIndicator style={{ marginTop: 15 }} color="#38BDF8" />}

            {deepfakeResult && (
              <View style={styles.resultBox}>
                {deepfakeResult.error ? (
                  <Text style={styles.errorText}>Error: {deepfakeResult.error}</Text>
                ) : (
                  <>
                    <View style={styles.resultHeader}>
                      <Text style={styles.resultTitle}>{deepfakeResult.filename}</Text>
                      {renderBadge(deepfakeResult.verdict)}
                    </View>
                    <Text style={styles.explanationText}>{deepfakeResult.verdict?.explanation}</Text>
                    {deepfakeResult.verdict?.threatLevel === 'UNKNOWN' && (
                      <View style={styles.unknownWarning}>
                        <Text style={styles.unknownWarningText}>
                          ⚠️ Core Invariant: Recompressed media traces destroyed. Never certified safe.
                        </Text>
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
            <Text style={styles.cardTitle}>Misinformation Firewall</Text>
            <Text style={styles.cardSubtitle}>ClaimReview Directory + 64-bit SimHash Matching</Text>

            <TextInput
              style={[styles.input, { minHeight: 60 }]}
              value={claimText}
              onChangeText={setClaimText}
              multiline
              placeholder="Enter news claim to verify..."
              placeholderTextColor="#64748B"
            />

            <TouchableOpacity
              style={[styles.primaryButton, { backgroundColor: '#8B5CF6' }]}
              onPress={handleCheckClaim}
              disabled={claimLoading}
            >
              {claimLoading ? <ActivityIndicator color="#FFF" /> : <Text style={styles.primaryButtonText}>Verify Claim</Text>}
            </TouchableOpacity>

            {claimResult && (
              <View style={styles.resultBox}>
                {claimResult.error ? (
                  <Text style={styles.errorText}>Error: {claimResult.error}</Text>
                ) : (
                  <>
                    <View style={styles.resultHeader}>
                      <Text style={styles.resultTitle}>Verification Result</Text>
                      {renderBadge(claimResult.verdict)}
                    </View>
                    <Text style={styles.explanationText}>{claimResult.verdict?.explanation}</Text>
                    <Text style={styles.metaText}>
                      Match Source: {claimResult.matchedDebunk ? 'SimHash Fact-Check Match' : 'Unindexed / Local Style (Capped)'}
                    </Text>
                  </>
                )}
              </View>
            )}
          </View>
        )}

        {/* Fusion Tab */}
        {activeTab === 'fusion' && (
          <View style={styles.card}>
            <Text style={styles.cardTitle}>Cross-Modal Fusion Engine</Text>
            <Text style={styles.cardSubtitle}>Canonical Rules R1–R5 + Ledger Override</Text>

            <TouchableOpacity
              style={[styles.primaryButton, { backgroundColor: '#0284C7' }]}
              onPress={handleFusionDemo}
              disabled={fusionLoading}
            >
              {fusionLoading ? <ActivityIndicator color="#FFF" /> : <Text style={styles.primaryButtonText}>Evaluate Rule R2 (Compound Escalation)</Text>}
            </TouchableOpacity>

            {fusionResult && (
              <View style={styles.resultBox}>
                {fusionResult.error ? (
                  <Text style={styles.errorText}>Error: {fusionResult.error}</Text>
                ) : (
                  <>
                    <View style={styles.resultHeader}>
                      <Text style={styles.resultTitle}>Composite Verdict</Text>
                      {renderBadge(fusionResult.aggregateVerdict)}
                    </View>
                    <Text style={styles.explanationText}>{fusionResult.aggregateVerdict?.explanation}</Text>
                    <Text style={styles.metaText}>
                      Fired Rules: {fusionResult.firedRules?.filter((r: any) => r.fired).map((r: any) => r.ruleId).join(', ') || 'None'}
                    </Text>
                  </>
                )}
              </View>
            )}
          </View>
        )}

        {/* Ledger Tab */}
        {activeTab === 'ledger' && (
          <View style={styles.card}>
            <Text style={styles.cardTitle}>Cryptographic Integrity Ledger</Text>
            <Text style={styles.cardSubtitle}>Append-only SHA-256 Chaining with Ed25519 Signatures</Text>

            <TouchableOpacity
              style={[styles.primaryButton, { backgroundColor: '#10B981' }]}
              onPress={handleVerifyLedger}
              disabled={ledgerLoading}
            >
              {ledgerLoading ? <ActivityIndicator color="#FFF" /> : <Text style={styles.primaryButtonText}>Verify Hash Chain</Text>}
            </TouchableOpacity>

            {ledgerResult && (
              <View style={styles.resultBox}>
                {ledgerResult.error ? (
                  <Text style={styles.errorText}>Error: {ledgerResult.error}</Text>
                ) : (
                  <>
                    <Text style={[styles.resultTitle, { color: ledgerResult.valid ? '#34D399' : '#F87171' }]}>
                      {ledgerResult.valid ? '✓ CHAIN INTEGRITY AUTHENTIC' : '✗ TAMPERING DETECTED'}
                    </Text>
                    <Text style={styles.explanationText}>{ledgerResult.message}</Text>
                    <Text style={styles.metaText}>
                      Total Verified Blocks: {ledgerResult.totalEntries}
                    </Text>
                  </>
                )}
              </View>
            )}
          </View>
        )}

        {/* Footer Note */}
        <View style={styles.footer}>
          <Text style={styles.footerText}>
            TrustShield Cyber-Defense Platform · Mobile Client (React Native / Expo)
          </Text>
          <Text style={styles.footerInvariant}>
            🛡️ Core Invariant: An unknown result is never a safe result.
          </Text>
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0B0F19'
  },
  header: {
    padding: 16,
    backgroundColor: '#0F172A',
    borderBottomWidth: 1,
    borderBottomColor: '#1E293B'
  },
  headerRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 8
  },
  title: {
    fontSize: 18,
    fontWeight: '800',
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
    backgroundColor: '#0B0F19',
    borderWidth: 1,
    borderColor: '#334155',
    borderRadius: 6,
    paddingHorizontal: 8,
    paddingVertical: 4,
    color: '#F8FAFC',
    fontSize: 12,
    fontFamily: 'monospace'
  },
  tabBar: {
    flexDirection: 'row',
    backgroundColor: '#0F172A',
    borderBottomWidth: 1,
    borderBottomColor: '#1E293B',
    paddingHorizontal: 4
  },
  tabButton: {
    flex: 1,
    paddingVertical: 10,
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
    fontWeight: '700'
  },
  content: {
    flex: 1,
    padding: 16
  },
  card: {
    backgroundColor: '#111827',
    borderWidth: 1,
    borderColor: '#1F2937',
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
  input: {
    backgroundColor: '#0B0F19',
    borderWidth: 1,
    borderColor: '#334155',
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
  presetRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    marginBottom: 12
  },
  presetLabel: {
    fontSize: 11,
    color: '#94A3B8'
  },
  presetChip: {
    backgroundColor: '#1E293B',
    paddingHorizontal: 8,
    paddingVertical: 4,
    borderRadius: 4,
    borderWidth: 1,
    borderColor: '#334155'
  },
  presetChipText: {
    color: '#CBD5E1',
    fontSize: 11
  },
  resultBox: {
    backgroundColor: '#0B0F19',
    borderWidth: 1,
    borderColor: '#1F2937',
    borderRadius: 8,
    padding: 12,
    marginTop: 8
  },
  resultHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 8
  },
  resultTitle: {
    fontSize: 13,
    fontWeight: '700',
    color: '#F8FAFC'
  },
  resultUrl: {
    fontSize: 12,
    color: '#38BDF8',
    fontFamily: 'monospace',
    flex: 1,
    marginRight: 8
  },
  explanationText: {
    fontSize: 12,
    color: '#CBD5E1',
    lineHeight: 18,
    marginBottom: 8
  },
  metaText: {
    fontSize: 11,
    color: '#64748B'
  },
  kAnonBox: {
    backgroundColor: '#1E293B',
    padding: 8,
    borderRadius: 4,
    color: '#38BDF8',
    fontSize: 11,
    fontFamily: 'monospace',
    marginBottom: 8
  },
  sampleButtonGroup: {
    gap: 8
  },
  sampleButton: {
    backgroundColor: '#1E293B',
    padding: 12,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: '#334155'
  },
  sampleButtonText: {
    color: '#E2E8F0',
    fontSize: 12,
    fontWeight: '600'
  },
  unknownWarning: {
    backgroundColor: 'rgba(245, 158, 11, 0.1)',
    borderWidth: 1,
    borderColor: '#F59E0B',
    padding: 8,
    borderRadius: 4,
    marginTop: 6
  },
  unknownWarningText: {
    color: '#FBBF24',
    fontSize: 11
  },
  errorText: {
    color: '#F87171',
    fontSize: 12
  },
  badge: {
    paddingHorizontal: 8,
    paddingVertical: 4,
    borderRadius: 12
  },
  badgeText: {
    color: '#FFFFFF',
    fontSize: 11,
    fontWeight: '700'
  },
  footer: {
    paddingVertical: 24,
    alignItems: 'center',
    gap: 4
  },
  footerText: {
    fontSize: 11,
    color: '#64748B'
  },
  footerInvariant: {
    fontSize: 11,
    color: '#94A3B8',
    fontWeight: '600'
  }
});
