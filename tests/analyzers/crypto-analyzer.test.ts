import { describe, expect, it } from 'vitest';

import {
  analyzeDependencies,
  analyzeDependency,
  assessCryptoHealth,
  buildCbom,
  resolveAlgorithm,
  summarize,
} from '../../src/analyzers';
import { createIndex } from '../../src/database';
import type { DependencyRecord, ScanResult } from '../../src/types';
import { TEST_DATABASE } from '../fixtures/crypto-database';

const index = createIndex(TEST_DATABASE);

function dep(name: string, version = '1.0.0'): DependencyRecord {
  return { name, declaredVersion: `^${version}`, version, scope: 'dependencies' };
}

describe('analyzeDependency', () => {
  it('returns undefined for non-crypto packages', () => {
    expect(analyzeDependency(dep('express', '4.19.2'), index)).toBeUndefined();
  });

  it('maps a known crypto package to a CBOM component', () => {
    const component = analyzeDependency(dep('bcrypt', '5.1.1'), index);
    expect(component).toMatchObject({
      package: 'bcrypt',
      version: '5.1.1',
      category: 'password-hashing',
      risk: 'low',
    });
    expect(component?.algorithms).toContain('bcrypt');
  });

  it('resolves aliases to their canonical entry', () => {
    const component = analyzeDependency(dep('bcryptjs', '2.4.3'), index);
    expect(component?.category).toBe('password-hashing');
    expect(component?.package).toBe('bcryptjs');
  });

  it('matches package names case-insensitively', () => {
    expect(analyzeDependency(dep('Crypto-JS', '4.2.0'), index)).toBeDefined();
  });

  it('escalates risk to the worst algorithm in the package', () => {
    const component = analyzeDependency(dep('crypto-js', '4.2.0'), index);
    expect(component?.risk).toBe('critical');
    expect(component?.deprecated).toBe(true);
  });

  it('flags quantum-vulnerable packages', () => {
    expect(analyzeDependency(dep('node-rsa'), index)?.quantumVulnerable).toBe(true);
    expect(analyzeDependency(dep('argon2'), index)?.quantumVulnerable).toBe(false);
  });
});

describe('resolveAlgorithm', () => {
  it('reads metadata from the database', () => {
    expect(resolveAlgorithm('RSA', index)).toEqual({
      name: 'RSA',
      type: 'public-key',
      risk: 'medium',
      quantumVulnerable: true,
      primitive: 'pke',
      nistQuantumSecurityLevel: 0,
      oid: '1.2.840.113549.1.1.1',
    });
  });

  it('derives the CycloneDX primitive from the algorithm family', () => {
    expect(resolveAlgorithm('SHA-256', index).primitive).toBe('hash');
    expect(resolveAlgorithm('ML-KEM', index).primitive).toBe('kem');
    expect(resolveAlgorithm('RC4', index).primitive).toBe('stream-cipher');
    expect(resolveAlgorithm('AES-GCM', index).primitive).toBe('ae');
  });

  it('falls back for unknown algorithms', () => {
    expect(resolveAlgorithm('SOME-NEW-ALG', index)).toMatchObject({
      type: 'unknown',
      risk: 'medium',
      primitive: 'unknown',
    });
  });
});

describe('analyzeDependencies', () => {
  it('keeps only crypto packages, sorted by descending risk', () => {
    const components = analyzeDependencies(
      [dep('express'), dep('bcrypt'), dep('crypto-js'), dep('lodash')],
      index,
    );
    expect(components.map((component) => component.package)).toEqual(['crypto-js', 'bcrypt']);
  });
});

describe('summarize', () => {
  it('computes counts, algorithm sets and risk breakdown', () => {
    const components = analyzeDependencies([dep('bcrypt'), dep('node-rsa'), dep('md5')], index);
    const summary = summarize(10, components);

    expect(summary.totalDependencies).toBe(10);
    expect(summary.cryptoDependencies).toBe(3);
    expect(summary.highRiskAlgorithms).toContain('MD5');
    expect(summary.quantumVulnerableAlgorithms).toContain('RSA');
    expect(summary.highestRisk).toBe('critical');
    expect(summary.riskBreakdown.low).toBe(1);
  });

  it('handles projects without crypto dependencies', () => {
    const summary = summarize(4, []);
    expect(summary).toMatchObject({
      cryptoDependencies: 0,
      highRiskAlgorithms: [],
      quantumVulnerableAlgorithms: [],
      highestRisk: 'none',
    });
  });
});

describe('assessCryptoHealth', () => {
  it('reports a healthy score for modern cryptography', () => {
    const health = assessCryptoHealth(analyzeDependencies([dep('bcrypt')], index));
    expect(health).toMatchObject({ score: 100, status: 'healthy' });
  });

  it('reports deprecated and production high-risk cryptography as at risk', () => {
    const health = assessCryptoHealth(analyzeDependencies([dep('crypto-js')], index));
    expect(health).toMatchObject({ score: 45, status: 'at-risk' });
    expect(health.deprecatedDependencies).toEqual(['crypto-js']);
    expect(health.highRiskProductionComponents).toEqual(['crypto-js']);
  });

  it('separates post-quantum migration from immediate risk', () => {
    const component = analyzeDependency(dep('node-rsa'), index)!;
    const health = assessCryptoHealth([{
      ...component,
      risk: 'medium',
      algorithmDetails: component.algorithmDetails.map((algorithm) => ({ ...algorithm, risk: 'medium' })),
    }]);

    expect(health).toMatchObject({ score: 85, status: 'migration-needed' });
    expect(health.quantumMigrationCandidates).toEqual(['node-rsa']);
  });

  it('flags medium risk cryptography for attention', () => {
    const health = assessCryptoHealth(analyzeDependencies([dep('jsonwebtoken')], index));
    expect(health).toMatchObject({ score: 95, status: 'needs-attention' });
  });
});

describe('buildCbom', () => {
  const scan: ScanResult = {
    projectName: 'demo',
    projectVersion: '1.0.0',
    manifestPath: '/tmp/demo/package.json',
    dependencies: [dep('express'), dep('jsonwebtoken', '9.0.2')],
  };

  it('produces a complete document', () => {
    const cbom = buildCbom(scan, { index, generatedAt: '2026-01-01T00:00:00.000Z' });

    expect(cbom.bomFormat).toBe('CBOM');
    expect(cbom.metadata.generatedAt).toBe('2026-01-01T00:00:00.000Z');
    expect(cbom.metadata.project.name).toBe('demo');
    expect(cbom.summary.totalDependencies).toBe(2);
    expect(cbom.summary.cryptoDependencies).toBe(1);
    expect(cbom.summary.health).toMatchObject({ status: 'needs-attention', score: 95 });
    expect(cbom.components[0]?.package).toBe('jsonwebtoken');
  });
});
