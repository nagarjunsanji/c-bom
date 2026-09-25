import { describe, expect, it } from 'vitest';

import { assertDatabase, createIndex, EMPTY_DATABASE, loadDatabase } from '../../src/database';
import { TEST_DATABASE } from '../fixtures/crypto-database';

describe('crypto package database', () => {
  it('has an empty production default for live-only analysis', () => {
    expect(EMPTY_DATABASE.packages).toEqual([]);
    expect(EMPTY_DATABASE.algorithms).toEqual({});
    expect(loadDatabase()).toBe(EMPTY_DATABASE);
  });

  it('validates and indexes an explicit database', () => {
    const index = createIndex(TEST_DATABASE);
    expect(index.find('bcrypt')?.name).toBe('bcrypt');
    expect(index.find('bcryptjs')?.name).toBe('bcrypt');
    expect(index.find('not-a-crypto-package')).toBeUndefined();
  });

  it('rejects malformed databases', () => {
    expect(() => assertDatabase(null)).toThrowError(/Invalid crypto database/);
    expect(() => assertDatabase({ algorithms: {} })).toThrowError(/packages/);
    expect(() => assertDatabase({ packages: [] })).toThrowError(/algorithms/);
  });
});
