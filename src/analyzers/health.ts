import type { CbomComponent, CryptoHealth, CryptoHealthStatus, CryptoPrimitive, RiskLevel } from '../types';

const QUANTUM_MIGRATION_PRIMITIVES = new Set<CryptoPrimitive>(['pke', 'signature', 'key-agree']);

function isHighRisk(risk: RiskLevel): boolean {
  return risk === 'high' || risk === 'critical';
}

function packageNames(components: CbomComponent[]): string[] {
  return components.map((component) => component.package).sort((a, b) => a.localeCompare(b));
}

function hasQuantumMigrationCandidate(component: CbomComponent): boolean {
  return component.algorithmDetails.some(
    (algorithm) => algorithm.quantumVulnerable && QUANTUM_MIGRATION_PRIMITIVES.has(algorithm.primitive),
  );
}

export function assessCryptoHealth(components: CbomComponent[]): CryptoHealth {
  const deprecatedDependencies = packageNames(components.filter((component) => component.deprecated));
  const highRiskProductionComponents = packageNames(
    components.filter((component) => component.scope === 'dependencies' && isHighRisk(component.risk)),
  );
  const highRiskDevelopmentComponents = packageNames(
    components.filter((component) => component.scope === 'devDependencies' && isHighRisk(component.risk)),
  );
  const mediumRiskComponents = packageNames(components.filter((component) => component.risk === 'medium'));
  const quantumMigrationCandidates = packageNames(components.filter(hasQuantumMigrationCandidate));
  const unreviewedQuantumFindings = packageNames(
    components.filter((component) => component.quantumVulnerable && !hasQuantumMigrationCandidate(component)),
  );

  const score = Math.max(
    0,
    100
      - deprecatedDependencies.length * 30
      - highRiskProductionComponents.length * 25
      - highRiskDevelopmentComponents.length * 10
      - mediumRiskComponents.length * 5
      - quantumMigrationCandidates.length * 10
      - unreviewedQuantumFindings.length * 5,
  );

  const status: CryptoHealthStatus = deprecatedDependencies.length || highRiskProductionComponents.length
    ? 'at-risk'
    : quantumMigrationCandidates.length
      ? 'migration-needed'
      : highRiskDevelopmentComponents.length || mediumRiskComponents.length || unreviewedQuantumFindings.length
        ? 'needs-attention'
        : 'healthy';

  return {
    score,
    status,
    deprecatedDependencies,
    highRiskProductionComponents,
    highRiskDevelopmentComponents,
    mediumRiskComponents,
    quantumMigrationCandidates,
    unreviewedQuantumFindings,
  };
}