import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { buildCbom } from '../../src/analyzers';
import { createIndex } from '../../src/database';
import { getReporters, jsonReporter, markdownReporter, writeReports } from '../../src/reporters';
import type { ScanResult } from '../../src/types';
import { withTempDir } from '../helpers';
import { TEST_DATABASE } from '../fixtures/crypto-database';

const scan: ScanResult = {
  projectName: 'demo',
  projectVersion: '1.0.0',
  manifestPath: '/tmp/demo/package.json',
  dependencies: [
    { name: 'express', declaredVersion: '^4.19.2', version: '4.19.2', scope: 'dependencies' },
    { name: 'crypto-js', declaredVersion: '^4.2.0', version: '4.2.0', scope: 'dependencies' },
    { name: 'md5', declaredVersion: '^2.3.0', version: '2.3.0', scope: 'devDependencies' },
  ],
};

const cbom = buildCbom(scan, { index: createIndex(TEST_DATABASE), generatedAt: '2026-01-01T00:00:00.000Z' });

describe('jsonReporter', () => {
  it('emits parseable, newline-terminated JSON', () => {
    const output = jsonReporter.render(cbom);
    expect(output.endsWith('\n')).toBe(true);
    expect(JSON.parse(output)).toEqual(cbom);
  });
});

describe('markdownReporter', () => {
  const output = markdownReporter.render(cbom);

  it('includes the summary metrics', () => {
    expect(output).toContain('# Cryptography Bill of Materials');
    expect(output).toContain('| Total dependencies | 3 |');
    expect(output).toContain('| Crypto dependencies | 2 |');
    expect(output).toContain('High-risk algorithms');
    expect(output).toContain('Quantum-vulnerable algorithms');
    expect(output).toContain('Crypto health');
    expect(output).toContain('At risk');
  });

  it('lists each crypto component', () => {
    expect(output).toContain('`crypto-js`');
    expect(output).toContain('`md5`');
    expect(output).not.toContain('`express`');
  });

  it('includes descriptions and recommended actions for components and assets', () => {
    expect(output).toContain('| Description | Next action |');
    expect(output).toContain('hash cryptographic primitive.');
    expect(output).toContain('Replace deprecated dependency.');
    expect(output).toContain('Replace or disable the weak algorithm.');
  });

  it('limits post-quantum migration advice to vulnerable asymmetric primitives', () => {
    const outputWithQuantumFindings = markdownReporter.render({
      ...cbom,
      components: [
        {
          ...cbom.components[0]!,
          deprecated: false,
          risk: 'medium',
          quantumVulnerable: true,
          algorithmDetails: [
            {
              ...cbom.components[0]!.algorithmDetails[0]!,
              risk: 'medium',
              quantumVulnerable: true,
              primitive: 'hash',
            },
          ],
        },
        {
          ...cbom.components[1]!,
          deprecated: false,
          risk: 'medium',
          quantumVulnerable: true,
          algorithmDetails: [
            {
              ...cbom.components[1]!.algorithmDetails[0]!,
              risk: 'medium',
              quantumVulnerable: true,
              primitive: 'pke',
            },
          ],
        },
      ],
    });

    expect(outputWithQuantumFindings).toContain('Validate the quantum-vulnerability classification.');
    expect(outputWithQuantumFindings).toContain('Assess a post-quantum migration.');
  });

  it('renders an empty-state message', () => {
    const empty = buildCbom(
      { ...scan, dependencies: [] },
      { index: createIndex(TEST_DATABASE), generatedAt: '2026-01-01T00:00:00.000Z' },
    );
    expect(markdownReporter.render(empty)).toContain('No cryptographic dependencies');
  });
});

describe('writeReports', () => {
  it('writes the requested formats to disk', () => {
    withTempDir((dir) => {
      const files = writeReports(cbom, join(dir, 'reports'), ['json', 'md']);
      expect(files).toHaveLength(2);
      expect(JSON.parse(readFileSync(files[0]!, 'utf8')).bomFormat).toBe('CBOM');
      expect(readFileSync(files[1]!, 'utf8')).toContain('Cryptography Bill of Materials');
    });
  });

  it('rejects unknown formats', () => {
    expect(() => getReporters(['xml'])).toThrowError(/Unknown report format/);
  });
});
