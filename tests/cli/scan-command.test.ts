import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { parseFormats, runScan } from '../../src/cli/scan-command';
import { withTempDir, writeManifest } from '../helpers';

const manifest = {
  name: 'cli-demo',
  version: '2.0.0',
  dependencies: { bcrypt: '^5.1.1', express: '^4.19.2', 'node-rsa': '^1.1.1' },
  devDependencies: { md5: '^2.3.0' },
};

describe('parseFormats', () => {
  it('defaults to json, md and cyclonedx', () => {
    expect(parseFormats()).toEqual(['json', 'md', 'cyclonedx']);
  });

  it('trims, lowercases, resolves aliases and de-duplicates', () => {
    expect(parseFormats(' JSON , md ,json')).toEqual(['json', 'md']);
    expect(parseFormats('cdx,cyclonedx')).toEqual(['cyclonedx']);
  });

  it('rejects an empty format list', () => {
    expect(() => parseFormats(',')).toThrowError(/No output format/);
  });
});

describe('runScan', () => {
  it('writes every default report next to the manifest', () => {
    withTempDir((dir) => {
      writeManifest(dir, manifest);
      const result = runScan(dir);

      expect(existsSync(join(dir, 'cbom.json'))).toBe(true);
      expect(existsSync(join(dir, 'cbom.md'))).toBe(true);
      expect(existsSync(join(dir, 'cbom.cdx.json'))).toBe(true);
      expect(JSON.parse(readFileSync(join(dir, 'cbom.cdx.json'), 'utf8')).specVersion).toBe('1.6');
      expect(result.cbom.summary.totalDependencies).toBe(4);
      expect(result.cbom.summary.cryptoDependencies).toBe(3);
      expect(result.exitCode).toBe(0);
    });
  });

  it('honours --out and --format', () => {
    withTempDir((dir) => {
      writeManifest(dir, manifest);
      const out = join(dir, 'reports');
      const result = runScan(dir, { out, format: 'json' });

      expect(result.files).toEqual([join(out, 'cbom.json')]);
      expect(existsSync(join(out, 'cbom.md'))).toBe(false);
      expect(JSON.parse(readFileSync(result.files[0]!, 'utf8')).specVersion).toBe('1.0');
    });
  });

  it('ignores devDependencies when dev is false', () => {
    withTempDir((dir) => {
      writeManifest(dir, manifest);
      const result = runScan(dir, { dev: false });
      expect(result.cbom.components.some((c) => c.package === 'md5')).toBe(false);
    });
  });

  it('exits non-zero when the fail-on threshold is reached', () => {
    withTempDir((dir) => {
      writeManifest(dir, manifest);
      expect(runScan(dir, { failOn: 'critical' }).exitCode).toBe(1);
      expect(runScan(dir, { failOn: 'critical', dev: false }).exitCode).toBe(0);
    });
  });

  it('rejects an invalid fail-on value', () => {
    withTempDir((dir) => {
      writeManifest(dir, manifest);
      expect(() => runScan(dir, { failOn: 'extreme' })).toThrowError(/Invalid --fail-on/);
    });
  });

  it('loads a custom database file', () => {
    withTempDir((dir) => {
      writeManifest(dir, { name: 'custom', dependencies: { 'my-crypto': '1.0.0' } });
      const dbPath = join(dir, 'db.json');
      writeFileSync(
        dbPath,
        JSON.stringify({
          version: '9.9.9',
          updated: '2026-01-01',
          algorithms: { 'AES-256': { type: 'symmetric', risk: 'low', quantumVulnerable: false } },
          packages: [
            {
              name: 'my-crypto',
              category: 'symmetric-encryption',
              algorithms: ['AES-256'],
              risk: 'low',
            },
          ],
        }),
        'utf8',
      );

      const result = runScan(dir, { db: dbPath, format: 'json' });
      expect(result.cbom.metadata.database.version).toBe('9.9.9');
      expect(result.cbom.components[0]?.package).toBe('my-crypto');
    });
  });
});
