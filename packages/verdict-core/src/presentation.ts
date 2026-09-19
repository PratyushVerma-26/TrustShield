import { ThreatLevel, Verdict, ConclusiveVerdict } from './types.js';

export interface BadgePresentation {
  label: string;
  badgeEmoji: string;
  badgeText: string;
  colorHex: string;
  tailwindClass: string;
  isConclusive: boolean;
  scoreDisplay: string;
  description: string;
}

/**
 * Type-level invariant: Assert that a verdict is conclusive before allowing
 * rendering via safe/clean visual representations.
 *
 * Calling this on an UNKNOWN verdict throws an error, mirroring the Java
 * invariant that absence of evidence is not evidence of absence.
 */
export function assertCanRenderSafe(verdict: Verdict): asserts verdict is ConclusiveVerdict {
  if (!verdict.isConclusive) {
    throw new Error(
      `TrustShield Violation: Attempted to render inconclusive verdict as SAFE. ` +
      `Unknown/missing evidence cannot be certified as clean.`
    );
  }
}

/**
 * Formats the score display.
 * An unmeasured or inconclusive verdict NEVER displays "0/100" (which implies safe);
 * it displays an em-dash "—" indicating unmeasured state.
 */
export function formatDisplayScore(verdict: Verdict): string {
  if (!verdict.isConclusive) {
    return '—';
  }
  return `${verdict.riskScore}/100`;
}

/**
 * Returns complete visual presentation metadata for a normalized verdict.
 */
export function getBadgePresentation(verdict: Verdict): BadgePresentation {
  const scoreText = formatDisplayScore(verdict);

  if (!verdict.isConclusive) {
    return {
      label: 'UNVERIFIED',
      badgeEmoji: '❓',
      badgeText: 'INCONCLUSIVE / UNVERIFIED',
      colorHex: '#64748B',
      tailwindClass: 'bg-slate-100 text-slate-800 border-dashed border-slate-400',
      isConclusive: false,
      scoreDisplay: scoreText,
      description: 'Traces destroyed by recompression or external source unindexed. TrustShield strictly refuses to falsely certify unverified content as clean.'
    };
  }

  const conclusive = verdict as ConclusiveVerdict;
  switch (conclusive.threatLevel) {
    case 'DANGEROUS':
      return {
        label: 'DANGEROUS',
        badgeEmoji: '🚨',
        badgeText: 'DANGEROUS THREAT',
        colorHex: '#DC2626',
        tailwindClass: 'bg-red-50 text-red-700 border-red-300',
        isConclusive: true,
        scoreDisplay: scoreText,
        description: 'Confirmed threat detected. Do not interact, click, forward, or enter credentials.'
      };

    case 'SUSPICIOUS':
      return {
        label: 'SUSPICIOUS',
        badgeEmoji: '⚠️',
        badgeText: 'SUSPICIOUS CONTENT',
        colorHex: '#D97706',
        tailwindClass: 'bg-amber-50 text-amber-700 border-amber-300',
        isConclusive: true,
        scoreDisplay: scoreText,
        description: 'Anomalous or synthetic indicators detected. Exercise caution and verify via independent sources.'
      };

    case 'LOW':
      return {
        label: 'LOW RISK',
        badgeEmoji: 'ℹ️',
        badgeText: 'LOW RISK',
        colorHex: '#2563EB',
        tailwindClass: 'bg-blue-50 text-blue-700 border-blue-300',
        isConclusive: true,
        scoreDisplay: scoreText,
        description: 'Minimal threat signals detected.'
      };

    case 'SAFE':
      return {
        label: 'SAFE',
        badgeEmoji: '🛡️',
        badgeText: 'NO THREATS DETECTED',
        colorHex: '#16A34A',
        tailwindClass: 'bg-emerald-50 text-emerald-700 border-emerald-300',
        isConclusive: true,
        scoreDisplay: scoreText,
        description: 'Content passed all automated threat heuristic and reputation scans.'
      };

    default: {
      const exhaustiveLevel: never = conclusive.threatLevel;
      throw new Error(`Unhandled threat level: ${exhaustiveLevel}`);
    }
  }
}

/**
 * Returns primary theme color hex for a threat level.
 */
export function getThreatLevelColor(level: ThreatLevel): string {
  switch (level) {
    case 'DANGEROUS': return '#DC2626';
    case 'SUSPICIOUS': return '#D97706';
    case 'LOW': return '#2563EB';
    case 'SAFE': return '#16A34A';
    case 'UNKNOWN': return '#64748B';
  }
}
