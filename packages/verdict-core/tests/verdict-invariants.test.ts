import { describe, it, expect } from 'vitest';
import {
  normalizeVerdict,
  assertCanRenderSafe,
  formatDisplayScore,
  getBadgePresentation,
  ModuleVerdict,
  Verdict
} from '../src/index.js';

describe('TrustShield Verdict Core Invariants', () => {
  const dangerousRaw: ModuleVerdict = {
    module: 'PHISHING',
    riskScore: 92,
    threatLevel: 'DANGEROUS',
    verdict: 'PHISHING_DETECTED',
    explanation: 'Brand impersonation detected.',
    signals: [],
    latencyMs: 12,
    evaluatedAt: new Date().toISOString(),
    degraded: false
  };

  const unknownRaw: ModuleVerdict = {
    module: 'DEEPFAKE',
    riskScore: 0,
    threatLevel: 'UNKNOWN',
    verdict: 'IMAGE_RECOMPRESSED',
    explanation: 'Compression removed fine sensor noise.',
    signals: [],
    latencyMs: 6,
    evaluatedAt: new Date().toISOString(),
    degraded: true
  };

  const safeRaw: ModuleVerdict = {
    module: 'PHISHING',
    riskScore: 5,
    threatLevel: 'SAFE',
    verdict: 'BENIGN',
    explanation: 'Clean lexical features and reputation.',
    signals: [],
    latencyMs: 10,
    evaluatedAt: new Date().toISOString(),
    degraded: false
  };

  it('normalizes verdicts into correct discriminated union variants', () => {
    const dangerous = normalizeVerdict(dangerousRaw);
    expect(dangerous.isConclusive).toBe(true);
    expect(dangerous.threatLevel).toBe('DANGEROUS');

    const unknown = normalizeVerdict(unknownRaw);
    expect(unknown.isConclusive).toBe(false);
    expect(unknown.threatLevel).toBe('UNKNOWN');

    const safe = normalizeVerdict(safeRaw);
    expect(safe.isConclusive).toBe(true);
    expect(safe.threatLevel).toBe('SAFE');
  });

  it('prohibits inconclusive verdicts from rendering through the safe path', () => {
    const unknown = normalizeVerdict(unknownRaw);

    expect(() => {
      assertCanRenderSafe(unknown);
    }).toThrow(/TrustShield Violation: Attempted to render inconclusive verdict as SAFE/);
  });

  it('allows conclusive safe verdicts to pass safety assertion', () => {
    const safe = normalizeVerdict(safeRaw);
    expect(() => {
      assertCanRenderSafe(safe);
    }).not.toThrow();
  });

  it('displays an em-dash for unmeasured/inconclusive score, never 0/100', () => {
    const unknown = normalizeVerdict(unknownRaw);
    expect(formatDisplayScore(unknown)).toBe('—');

    const safe = normalizeVerdict(safeRaw);
    expect(formatDisplayScore(safe)).toBe('5/100');

    const dangerous = normalizeVerdict(dangerousRaw);
    expect(formatDisplayScore(dangerous)).toBe('92/100');
  });

  it('generates distinctive visual badges for each threat level', () => {
    const dangerousBadge = getBadgePresentation(normalizeVerdict(dangerousRaw));
    expect(dangerousBadge.badgeEmoji).toBe('🚨');
    expect(dangerousBadge.colorHex).toBe('#DC2626');
    expect(dangerousBadge.isConclusive).toBe(true);

    const unknownBadge = getBadgePresentation(normalizeVerdict(unknownRaw));
    expect(unknownBadge.badgeEmoji).toBe('❓');
    expect(unknownBadge.badgeText).toContain('INCONCLUSIVE');
    expect(unknownBadge.isConclusive).toBe(false);

    const safeBadge = getBadgePresentation(normalizeVerdict(safeRaw));
    expect(safeBadge.badgeEmoji).toBe('🛡️');
    expect(safeBadge.badgeText).toBe('NO THREATS DETECTED');
    expect(safeBadge.isConclusive).toBe(true);
  });
});
