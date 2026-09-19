import React from 'react';
import { Verdict, normalizeVerdict, ModuleVerdict, getBadgePresentation } from '@trustshield/verdict-core';

interface Props {
  verdict: Verdict | ModuleVerdict;
  showScore?: boolean;
}

export const VerdictBadge: React.FC<Props> = ({ verdict, showScore = true }) => {
  const norm = 'isConclusive' in verdict ? verdict : normalizeVerdict(verdict);
  const badge = getBadgePresentation(norm);

  const getBadgeClass = () => {
    if (!norm.isConclusive) return 'badge-unknown';
    switch (norm.threatLevel) {
      case 'DANGEROUS': return 'badge-dangerous';
      case 'SUSPICIOUS': return 'badge-suspicious';
      case 'SAFE': return 'badge-safe';
      case 'LOW': return 'badge-low';
    }
  };

  return (
    <div className={`badge-pill ${getBadgeClass()} ${!norm.isConclusive ? 'hatched-unmeasured' : ''}`}>
      <span>{badge.badgeEmoji}</span>
      <span>{badge.badgeText}</span>
      {showScore && (
        <span className="ml-1 opacity-80 font-mono text-xs">
          ({badge.scoreDisplay})
        </span>
      )}
    </div>
  );
};
