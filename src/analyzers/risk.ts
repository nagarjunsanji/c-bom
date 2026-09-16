import type { RiskLevel } from '../types';

export const RISK_ORDER: RiskLevel[] = ['none', 'low', 'medium', 'high', 'critical'];

export function riskScore(risk: RiskLevel): number {
  const index = RISK_ORDER.indexOf(risk);
  return index === -1 ? 0 : index;
}

export function maxRisk(...risks: RiskLevel[]): RiskLevel {
  return risks.reduce<RiskLevel>(
    (highest, current) => (riskScore(current) > riskScore(highest) ? current : highest),
    'none',
  );
}

export function isAtLeast(risk: RiskLevel, threshold: RiskLevel): boolean {
  return riskScore(risk) >= riskScore(threshold);
}

export function isRiskLevel(value: string): value is RiskLevel {
  return (RISK_ORDER as string[]).includes(value);
}

export function emptyRiskBreakdown(): Record<RiskLevel, number> {
  return { none: 0, low: 0, medium: 0, high: 0, critical: 0 };
}
