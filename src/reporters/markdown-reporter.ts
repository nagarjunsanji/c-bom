import type { AlgorithmFinding, Cbom, CbomComponent, CryptoPrimitive, RiskLevel } from '../types';
import { RISK_ORDER } from '../analyzers/risk';
import type { Reporter } from './reporter';

const RISK_LABEL: Record<RiskLevel, string> = {
  none: 'None',
  low: 'Low',
  medium: 'Medium',
  high: 'High',
  critical: 'Critical',
};

const HEALTH_LABEL = {
  healthy: 'Healthy',
  'needs-attention': 'Needs attention',
  'at-risk': 'At risk',
  'migration-needed': 'Migration needed',
};

function escapeCell(value: string): string {
  return value.replace(/\|/g, '\\|');
}

function list(values: string[]): string {
  return values.length ? values.map((value) => `\`${value}\``).join(', ') : '_none_';
}

function componentDescription(component: CbomComponent): string {
  return component.description ?? `${component.category} cryptographic package.`;
}

function databaseLabel(version: string): string {
  return /^\d/.test(version) ? `v${version}` : version;
}

const QUANTUM_VULNERABLE_PRIMITIVES = new Set<CryptoPrimitive>(['pke', 'signature', 'key-agree']);

function isHighRisk(risk: RiskLevel): boolean {
  return risk === 'critical' || risk === 'high';
}

function isPostQuantumMigrationCandidate(algorithm: AlgorithmFinding): boolean {
  return algorithm.quantumVulnerable && QUANTUM_VULNERABLE_PRIMITIVES.has(algorithm.primitive);
}

function algorithmAction(algorithm: AlgorithmFinding): string {
  if (isHighRisk(algorithm.risk)) return 'Replace or disable the weak algorithm.';
  if (isPostQuantumMigrationCandidate(algorithm)) return 'Assess a post-quantum migration.';
  if (algorithm.quantumVulnerable) return 'Validate the quantum-vulnerability classification.';
  return 'None.';
}

function componentAction(component: CbomComponent): string {
  if (component.deprecated) return 'Replace deprecated dependency.';
  if (component.algorithmDetails.some((algorithm) => isHighRisk(algorithm.risk))) {
    return 'Replace weak algorithms and upgrade the dependency.';
  }
  if (component.algorithmDetails.some(isPostQuantumMigrationCandidate)) {
    return 'Assess a post-quantum migration.';
  }
  if (component.quantumVulnerable) return 'Validate the quantum-vulnerability classification.';
  if (isHighRisk(component.risk)) return 'Review the dependency configuration.';
  return 'None.';
}

function componentRow(component: CbomComponent): string {
  const cells = [
    `\`${component.package}\``,
    component.parentPackages.length
      ? component.parentPackages.map((parent) => `\`${parent}\``).join(', ')
      : '_unknown_',
    component.version,
    escapeCell(component.declaredVersion),
    component.category,
    escapeCell(component.algorithms.join(', ')),
    RISK_LABEL[component.risk],
    component.quantumVulnerable ? 'Yes' : 'No',
    component.scope === 'devDependencies' ? 'dev' : 'prod',
    escapeCell(componentDescription(component)),
    componentAction(component),
  ];
  return `| ${cells.join(' | ')} |`;
}

function algorithmRows(components: CbomComponent): string[] {
  return components.algorithmDetails.map((algorithm) => {
    const parents = `\`${components.package}\``;
    return [
      `\`${algorithm.name}\``,
      algorithm.primitive,
      RISK_LABEL[algorithm.risk],
      algorithm.quantumVulnerable ? 'Yes' : 'No',
      parents,
      algorithm.nistQuantumSecurityLevel ? String(algorithm.nistQuantumSecurityLevel) : '_not rated_',
      algorithm.oid ?? '_none_',
      `${algorithm.type} cryptographic primitive.`,
      algorithmAction(algorithm),
    ].join(' | ');
  });
}

export const markdownReporter: Reporter = {
  id: 'md',
  fileName: 'cbom.md',
  render(cbom: Cbom): string {
    const { metadata, summary, components } = cbom;
    const lines: string[] = [];

    lines.push('# Cryptography Bill of Materials');
    lines.push('');
    lines.push(`**Project:** ${metadata.project.name}@${metadata.project.version}`);
    lines.push(`**Generated:** ${metadata.generatedAt}`);
    lines.push(`**Tool:** ${metadata.tool.name} v${metadata.tool.version}`);
    lines.push(`**Database:** ${databaseLabel(metadata.database.version)} (${metadata.database.updated})`);
    lines.push('');

    lines.push('## Summary');
    lines.push('');
    lines.push('| Metric | Value |');
    lines.push('| --- | --- |');
    lines.push(`| Total dependencies | ${summary.totalDependencies} |`);
    lines.push(`| Crypto dependencies | ${summary.cryptoDependencies} |`);
    lines.push(`| High-risk algorithms | ${summary.highRiskAlgorithms.length} |`);
    lines.push(`| Quantum-vulnerable algorithms | ${summary.quantumVulnerableAlgorithms.length} |`);
    lines.push(`| Highest component risk | ${RISK_LABEL[summary.highestRisk]} |`);
    lines.push(`| Crypto health | ${HEALTH_LABEL[summary.health.status]} (${summary.health.score}/100) |`);
    lines.push('');
    lines.push(`**High-risk algorithms:** ${list(summary.highRiskAlgorithms)}`);
    lines.push('');
    lines.push(`**Quantum-vulnerable algorithms:** ${list(summary.quantumVulnerableAlgorithms)}`);
    lines.push('');

    lines.push('## Crypto health');
    lines.push('');
    lines.push(`**Status:** ${HEALTH_LABEL[summary.health.status]}`);
    lines.push(`**Score:** ${summary.health.score}/100`);
    lines.push('');
    lines.push(`**Deprecated dependencies:** ${list(summary.health.deprecatedDependencies)}`);
    lines.push(`**High-risk production components:** ${list(summary.health.highRiskProductionComponents)}`);
    lines.push(`**High-risk development components:** ${list(summary.health.highRiskDevelopmentComponents)}`);
    lines.push(`**Medium-risk components:** ${list(summary.health.mediumRiskComponents)}`);
    lines.push(`**Post-quantum migration candidates:** ${list(summary.health.quantumMigrationCandidates)}`);
    lines.push(`**Quantum findings to validate:** ${list(summary.health.unreviewedQuantumFindings)}`);
    lines.push('');

    lines.push('## Interpretation');
    lines.push('');
    lines.push('- Findings describe known package capabilities, not confirmed runtime usage.');
    lines.push('- Resolved versions are best-effort values derived from declared ranges unless live dependency resolution is used.');
    lines.push('- Next actions prioritize deprecated dependencies and high-risk algorithms; post-quantum guidance applies only to public-key, signature, and key-agreement primitives.');
    lines.push('');

    lines.push('## Risk breakdown');
    lines.push('');
    lines.push('| Risk | Components |');
    lines.push('| --- | --- |');
    for (const risk of [...RISK_ORDER].reverse()) {
      lines.push(`| ${RISK_LABEL[risk]} | ${summary.riskBreakdown[risk]} |`);
    }
    lines.push('');

    lines.push('## Cryptographic components');
    lines.push('');
    if (components.length === 0) {
      lines.push('_No cryptographic dependencies were identified._');
      lines.push('');
    } else {
      lines.push('| Package | Parent package(s) | Resolved version | Declared version | Category | Algorithms | Risk | Quantum-vulnerable | Scope | Description | Next action |');
      lines.push('| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |');
      for (const component of components) {
        lines.push(componentRow(component));
      }
      lines.push('');

      const algorithms = new Map<string, string>();
      for (const component of components) {
        for (const row of algorithmRows(component)) {
          const name = row.slice(1, row.indexOf('`', 1));
          algorithms.set(`${name}:${component.package}`, row);
        }
      }
      lines.push('## Cryptographic assets');
      lines.push('');
      lines.push('| Algorithm | Primitive | Risk | Quantum-vulnerable | Parent package | NIST PQ level | OID | Description | Next action |');
      lines.push('| --- | --- | --- | --- | --- | --- | --- | --- | --- |');
      for (const row of algorithms.values()) {
        lines.push(`| ${row} |`);
      }
      lines.push('');

      const notable = components.filter(
        (component) => component.deprecated || component.description,
      );
      if (notable.length > 0) {
        lines.push('## Notes');
        lines.push('');
        for (const component of notable) {
          const flag = component.deprecated ? ' **(deprecated)**' : '';
          lines.push(`- \`${component.package}\`${flag} — ${component.description ?? ''}`.trimEnd());
        }
        lines.push('');
      }
    }

    return `${lines.join('\n')}`;
  },
};
