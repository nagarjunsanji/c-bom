import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export function withTempDir<T>(fn: (dir: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), 'cbom-test-'));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

export function writeManifest(dir: string, manifest: unknown): string {
  const path = join(dir, 'package.json');
  writeFileSync(path, JSON.stringify(manifest, null, 2), 'utf8');
  return path;
}
