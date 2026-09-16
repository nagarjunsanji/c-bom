import { describe, expect, it } from 'vitest';

import { RISK_ORDER, isAtLeast, isRiskLevel, maxRisk, riskScore } from '../../src/analyzers/risk';

describe('risk helpers', () => {
  it('orders risk levels from none to critical', () => {
    expect(RISK_ORDER).toEqual(['none', 'low', 'medium', 'high', 'critical']);
    expect(riskScore('critical')).toBeGreaterThan(riskScore('high'));
  });

  it('returns the highest risk of a list', () => {
    expect(maxRisk('low', 'high', 'medium')).toBe('high');
    expect(maxRisk()).toBe('none');
  });

  it('compares against a threshold', () => {
    expect(isAtLeast('high', 'medium')).toBe(true);
    expect(isAtLeast('low', 'medium')).toBe(false);
  });

  it('validates risk level strings', () => {
    expect(isRiskLevel('critical')).toBe(true);
    expect(isRiskLevel('extreme')).toBe(false);
  });
});
