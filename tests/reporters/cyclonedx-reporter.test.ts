import { describe, expect, it } from 'vitest';

import { buildCbom } from '../../src/analyzers';
import { createIndex } from '../../src/database';
import { cycloneDxReporter, toCycloneDx, toPurl } from '../../src/reporters';
import type { CycloneDxBom } from '../../src/reporters';
import type { ScanResult } from '../../src/types';

const scan: ScanResult = {
  projectName: 'demo',
  projectVersion: '1.0.0',
  manifestPath: '/tmp/demo/package.json',
  dependencies: [
    { name: 'express', declaredVersion: '^4.19.2', version: '4.19.2', scope: 'dependencies' },
    { name: 'node-rsa', declaredVersion: '^1.1.1', version: '1.1.1', scope: 'dependencies' },
    { name: '@noble/curves', declaredVersion: '^1.4.0', version: '1.4.0', scope: 'dependencies' },
    { name: 'md5', declaredVersion: '^2.3.0', version: '2.3.0', scope: 'devDependencies' },
  ],
};

const cbom = buildCbom(scan, { index: createIndex(), generatedAt: '2026-01-01T00:00:00.000Z' });
const bom: CycloneDxBom = toCycloneDx(cbom);

function componentByRef(ref: string) {
  return bom.components.find((component) => component['bom-ref'] === ref);
}

describe('toPurl', () => {
  it('builds npm purls', () => {
    expect(toPurl('md5', '2.3.0')).toBe('pkg:npm/md5@2.3.0');
  });

  it('percent-encodes scoped packages', () => {
    expect(toPurl('@noble/curves', '1.4.0')).toBe('pkg:npm/%40noble/curves@1.4.0');
  });

  it('omits unknown versions', () => {
    expect(toPurl('md5', 'unknown')).toBe('pkg:npm/md5');
  });
});

describe('CycloneDX document', () => {
  it('declares the CycloneDX 1.6 envelope', () => {
    expect(bom.bomFormat).toBe('CycloneDX');
    expect(bom.specVersion).toBe('1.6');
    expect(bom.version).toBe(1);
    expect(bom.serialNumber).toMatch(
      /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
  });

  it('is deterministic for identical input', () => {
    expect(toCycloneDx(cbom).serialNumber).toBe(bom.serialNumber);
  });

  it('describes the scanned project and the tool', () => {
    expect(bom.metadata.timestamp).toBe('2026-01-01T00:00:00.000Z');
    expect(bom.metadata.component).toMatchObject({
      type: 'application',
      name: 'demo',
      purl: 'pkg:npm/demo@1.0.0',
    });
    expect(bom.metadata.tools.components[0]?.name).toBe('cbom-builder');
  });

  it('carries the summary as metadata properties', () => {
    const properties = Object.fromEntries(
      bom.metadata.properties.map((property) => [property.name, property.value]),
    );
    expect(properties['cbom:summary:totalDependencies']).toBe('4');
    expect(properties['cbom:summary:cryptoDependencies']).toBe('3');
    expect(properties['cbom:summary:quantumVulnerableAlgorithms']).toContain('RSA');
    expect(properties['cbom:summary:highRiskAlgorithms']).toContain('MD5');
    expect(properties['cbom:summary:highestRisk']).toBe('critical');
  });

  it('emits library components only for crypto dependencies', () => {
    const libraries = bom.components.filter((component) => component.type === 'library');
    expect(libraries.map((library) => library.name).sort()).toEqual([
      '@noble/curves',
      'md5',
      'node-rsa',
    ]);
  });

  it('marks devDependencies as optional', () => {
    const md5 = componentByRef('pkg:npm/md5@2.3.0');
    expect(md5?.scope).toBe('optional');
    expect(md5?.properties).toContainEqual({ name: 'cdx:npm:package:development', value: 'true' });
  });

  it('emits deduplicated cryptographic-asset components', () => {
    const assets = bom.components.filter((component) => component.type === 'cryptographic-asset');
    const refs = assets.map((asset) => asset['bom-ref']);
    expect(new Set(refs).size).toBe(refs.length);
    expect(refs).toContain('crypto/algorithm/rsa');
    expect(refs).toContain('crypto/algorithm/md5');
  });

  it('populates algorithmProperties for each asset', () => {
    const rsa = componentByRef('crypto/algorithm/rsa');
    expect(rsa?.cryptoProperties).toMatchObject({
      assetType: 'algorithm',
      oid: '1.2.840.113549.1.1.1',
      algorithmProperties: {
        primitive: 'pke',
        cryptoFunctions: ['encrypt', 'decrypt', 'keygen'],
        nistQuantumSecurityLevel: 0,
      },
    });

    const sha256 = componentByRef('crypto/algorithm/sha-256');
    expect(sha256?.cryptoProperties?.algorithmProperties).toMatchObject({
      primitive: 'hash',
      cryptoFunctions: ['digest'],
      nistQuantumSecurityLevel: 2,
    });
  });

  it('links libraries to their algorithms in the dependency graph', () => {
    const root = bom.dependencies.find((entry) => entry.ref === 'pkg:npm/demo@1.0.0');
    expect(root?.dependsOn).toContain('pkg:npm/node-rsa@1.1.1');

    const nodeRsa = bom.dependencies.find((entry) => entry.ref === 'pkg:npm/node-rsa@1.1.1');
    expect(nodeRsa?.dependsOn).toContain('crypto/algorithm/rsa');

    const everyRefIsDeclared = bom.dependencies.every((entry) =>
      entry.dependsOn.every(
        (ref) =>
          bom.components.some((component) => component['bom-ref'] === ref) ||
          ref === bom.metadata.component['bom-ref'],
      ),
    );
    expect(everyRefIsDeclared).toBe(true);
  });
});

describe('cycloneDxReporter', () => {
  it('renders parseable JSON to cbom.cdx.json', () => {
    expect(cycloneDxReporter.fileName).toBe('cbom.cdx.json');
    const output = cycloneDxReporter.render(cbom);
    expect(output.endsWith('\n')).toBe(true);
    expect(JSON.parse(output)).toEqual(bom);
  });
});
