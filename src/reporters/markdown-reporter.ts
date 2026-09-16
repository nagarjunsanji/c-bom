import type { Cbom, CbomComponent, RiskLevel } from '../types';
import { RISK_ORDER } from '../analyzers/risk';
import type { Reporter } from './reporter';

const RISK_LABEL: Record<RiskLevel, string> = {
  none: 'None',
  low: 'Low',
  medium: 'Medium',
  high: 'High',
  critical: 'Critical',
};

function escapeCell(value: string): string {
  return value.replace(/\|/g, '\\|');
}

function list(values: string[]): string {
  return values.length ? values.map((value) => `\`${value}\``).join(', ') : '_none_';
}

function componentRow(component: CbomComponent): string {
  const cells = [
    `\`${component.package}\``,
    component.version,
    component.category,
    escapeCell(component.algorithms.join(', ')),
    RISK_LABEL[component.risk],
    component.quantumVulnerable ? 'Yes' : 'No',
    component.scope === 'devDependencies' ? 'dev' : 'prod',
  ];
  return `| ${cells.join(' | ')} |`;
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
    lines.push(`**Database:** v${metadata.database.version} (${metadata.database.updated})`);
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
    lines.push('');
    lines.push(`**High-risk algorithms:** ${list(summary.highRiskAlgorithms)}`);
    lines.push('');
    lines.push(`**Quantum-vulnerable algorithms:** ${list(summary.quantumVulnerableAlgorithms)}`);
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
      lines.push('| Package | Version | Category | Algorithms | Risk | Quantum-vulnerable | Scope |');
      lines.push('| --- | --- | --- | --- | --- | --- | --- |');
      for (const component of components) {
        lines.push(componentRow(component));
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
