import { writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  extractDependencies,
  normalizeVersion,
  resolveManifestPath,
  scanPackageJson,
} from '../../src/scanners';
import { CbomError } from '../../src/errors';
import { withTempDir, writeManifest } from '../helpers';

describe('normalizeVersion', () => {
  it.each([
    ['^1.2.3', '1.2.3'],
    ['~4.0.0', '4.0.0'],
    ['>=2.1', '2.1'],
    ['1.0.0-beta.1', '1.0.0-beta.1'],
    ['*', 'unknown'],
    ['', 'unknown'],
    ['workspace:*', 'unknown'],
    ['file:../local', 'unknown'],
    ['git+https://github.com/a/b.git', 'unknown'],
    ['npm:other-pkg@2.3.4', '2.3.4'],
  ])('normalizes %s to %s', (input, expected) => {
    expect(normalizeVersion(input)).toBe(expected);
  });
});

describe('extractDependencies', () => {
  const manifest = {
    dependencies: { bcrypt: '^5.1.1', express: '^4.19.2' },
    devDependencies: { md5: '2.3.0' },
  };

  it('returns dependencies and devDependencies sorted by name', () => {
    const records = extractDependencies(manifest);
    expect(records.map((record) => record.name)).toEqual(['bcrypt', 'express', 'md5']);
    expect(records[2]?.scope).toBe('devDependencies');
  });

  it('can skip devDependencies', () => {
    const records = extractDependencies(manifest, { includeDev: false });
    expect(records).toHaveLength(2);
    expect(records.every((record) => record.scope === 'dependencies')).toBe(true);
  });

  it('tolerates a manifest without dependency sections', () => {
    expect(extractDependencies({})).toEqual([]);
  });
});

describe('scanPackageJson', () => {
  it('scans a directory containing a package.json', () => {
    withTempDir((dir) => {
      writeManifest(dir, { name: 'demo', version: '1.0.0', dependencies: { bcrypt: '^5.0.0' } });
      const result = scanPackageJson(dir);
      expect(result.projectName).toBe('demo');
      expect(result.projectVersion).toBe('1.0.0');
      expect(result.dependencies).toHaveLength(1);
    });
  });

  it('scans a direct package.json path', () => {
    withTempDir((dir) => {
      const manifestPath = writeManifest(dir, { name: 'demo' });
      const result = scanPackageJson(manifestPath);
      expect(result.manifestPath).toBe(manifestPath);
      expect(result.projectVersion).toBe('0.0.0');
    });
  });

  it('throws when the path does not exist', () => {
    expect(() => resolveManifestPath('./definitely-not-here-123')).toThrowError(CbomError);
  });

  it('throws on invalid JSON', () => {
    withTempDir((dir) => {
      const path = join(dir, 'package.json');
      writeFileSync(path, '{ not json', 'utf8');
      expect(() => scanPackageJson(dir)).toThrowError(/Invalid package.json/);
    });
  });
});
