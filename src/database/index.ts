import { readFileSync } from 'node:fs';

import type { CryptoDatabase, CryptoPackageDefinition } from '../types';
import bundled from './crypto-packages.json';

export const BUNDLED_DATABASE = bundled as unknown as CryptoDatabase;

/**
 * Case-insensitive lookup over package names and their aliases.
 */
export class CryptoPackageIndex {
  private readonly byName = new Map<string, CryptoPackageDefinition>();

  constructor(private readonly database: CryptoDatabase) {
    for (const pkg of database.packages) {
      this.byName.set(pkg.name.toLowerCase(), pkg);
      for (const alias of pkg.aliases ?? []) {
        this.byName.set(alias.toLowerCase(), pkg);
      }
    }
  }

  get db(): CryptoDatabase {
    return this.database;
  }

  find(packageName: string): CryptoPackageDefinition | undefined {
    return this.byName.get(packageName.toLowerCase());
  }

  get size(): number {
    return this.database.packages.length;
  }
}

export function loadDatabase(databasePath?: string): CryptoDatabase {
  if (!databasePath) {
    return BUNDLED_DATABASE;
  }
  const raw = readFileSync(databasePath, 'utf8');
  return assertDatabase(JSON.parse(raw));
}

export function assertDatabase(value: unknown): CryptoDatabase {
  const db = value as Partial<CryptoDatabase> | null;
  if (!db || typeof db !== 'object') {
    throw new Error('Invalid crypto database: expected an object.');
  }
  if (!Array.isArray(db.packages)) {
    throw new Error('Invalid crypto database: "packages" must be an array.');
  }
  if (!db.algorithms || typeof db.algorithms !== 'object') {
    throw new Error('Invalid crypto database: "algorithms" must be an object.');
  }
  return db as CryptoDatabase;
}

export function createIndex(database: CryptoDatabase = BUNDLED_DATABASE): CryptoPackageIndex {
  return new CryptoPackageIndex(database);
}
