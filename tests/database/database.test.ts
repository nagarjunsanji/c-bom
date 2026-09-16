import { describe, expect, it } from 'vitest';

import { primitiveFor } from '../../src/analyzers/crypto-analyzer';
import { BUNDLED_DATABASE, assertDatabase, createIndex, loadDatabase } from '../../src/database';

describe('crypto package database', () => {
  const index = createIndex();

  it('ships a non-empty catalog', () => {
    expect(BUNDLED_DATABASE.packages.length).toBeGreaterThan(20);
    expect(Object.keys(BUNDLED_DATABASE.algorithms).length).toBeGreaterThan(20);
  });

  it('references only known algorithms', () => {
    const unknown = BUNDLED_DATABASE.packages.flatMap((pkg) =>
      pkg.algorithms.filter((algorithm) => !(algorithm in BUNDLED_DATABASE.algorithms)),
    );
    expect(unknown).toEqual([]);
  });

  it('has no duplicate package names or aliases', () => {
    const names = BUNDLED_DATABASE.packages.flatMap((pkg) => [pkg.name, ...(pkg.aliases ?? [])]);
    expect(names.length).toBe(new Set(names.map((name) => name.toLowerCase())).size);
  });

  it('maps every algorithm to a CycloneDX primitive', () => {
    const unmapped = Object.entries(BUNDLED_DATABASE.algorithms)
      .filter(([, definition]) => primitiveFor(definition) === 'unknown')
      .map(([name]) => name);
    expect(unmapped).toEqual([]);
  });

  it('looks up packages by name and alias', () => {
    expect(index.find('tweetnacl')?.name).toBe('tweetnacl');
    expect(index.find('libsodium-wrappers')?.name).toBe('sodium-native');
    expect(index.find('not-a-crypto-package')).toBeUndefined();
  });

  it('returns the bundled database when no path is given', () => {
    expect(loadDatabase()).toBe(BUNDLED_DATABASE);
  });

  it('rejects malformed databases', () => {
    expect(() => assertDatabase(null)).toThrowError(/Invalid crypto database/);
    expect(() => assertDatabase({ algorithms: {} })).toThrowError(/packages/);
    expect(() => assertDatabase({ packages: [] })).toThrowError(/algorithms/);
  });
});
