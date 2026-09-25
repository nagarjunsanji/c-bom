import { existsSync, readFileSync, statSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';

import { CbomError } from '../errors';
import type { DependencyRecord, DependencyScope, ScanResult } from '../types';

export interface PackageManifest {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

export interface ScanOptions {
  /** Set to false to skip devDependencies. Defaults to true. */
  includeDev?: boolean;
}

const SCOPES: DependencyScope[] = ['dependencies', 'devDependencies'];

/** Resolves a user supplied path (directory or file) to a package.json path. */
export function resolveManifestPath(target: string): string {
  const absolute = isAbsolute(target) ? target : resolve(process.cwd(), target);

  if (!existsSync(absolute)) {
    throw new CbomError(`Path not found: ${absolute}`, 'ENOENT');
  }

  const manifestPath = statSync(absolute).isDirectory() ? join(absolute, 'package.json') : absolute;

  if (basename(manifestPath) !== 'package.json') {
    throw new CbomError(`Expected a package.json file, received: ${manifestPath}`, 'EINVALIDTARGET');
  }
  if (!existsSync(manifestPath)) {
    throw new CbomError(`No package.json found in ${dirname(manifestPath)}`, 'ENOMANIFEST');
  }
  return manifestPath;
}

export function readManifest(manifestPath: string): PackageManifest {
  let raw: string;
  try {
    raw = readFileSync(manifestPath, 'utf8');
  } catch (error) {
    throw new CbomError(`Unable to read ${manifestPath}: ${(error as Error).message}`, 'EREAD');
  }

  try {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('manifest is not a JSON object');
    }
    return parsed as PackageManifest;
  } catch (error) {
    throw new CbomError(`Invalid package.json at ${manifestPath}: ${(error as Error).message}`, 'EPARSE');
  }
}

/**
 * Best-effort concrete version from a declared range.
 * Non-registry specifiers (git, file, workspace, link) resolve to "unknown".
 */
export function normalizeVersion(declared: string): string {
  const value = declared.trim();
  if (!value) {
    return 'unknown';
  }
  if (/^(git|github|file|link|workspace|portal|https?):/i.test(value) || value.includes('/')) {
    return 'unknown';
  }
  if (value.startsWith('npm:')) {
    const aliased = value.slice(4);
    const at = aliased.lastIndexOf('@');
    return at > 0 ? normalizeVersion(aliased.slice(at + 1)) : 'unknown';
  }
  const match = value.match(/\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?/);
  return match ? match[0] : 'unknown';
}

export function extractDependencies(
  manifest: PackageManifest,
  options: ScanOptions = {},
): DependencyRecord[] {
  const includeDev = options.includeDev ?? true;
  const scopes = includeDev ? SCOPES : ['dependencies' as const];
  const records: DependencyRecord[] = [];

  for (const scope of scopes) {
    const entries = manifest[scope];
    if (!entries || typeof entries !== 'object') {
      continue;
    }
    for (const [name, declaredVersion] of Object.entries(entries)) {
      const declared = typeof declaredVersion === 'string' ? declaredVersion : '';
      records.push({
        name,
        declaredVersion: declared,
        version: normalizeVersion(declared),
        scope,
      });
    }
  }

  return records.sort((a, b) => a.name.localeCompare(b.name));
}

export function scanPackageJson(target: string, options: ScanOptions = {}): ScanResult {
  const manifestPath = resolveManifestPath(target);
  const manifest = readManifest(manifestPath);

  const dependencies = extractDependencies(manifest, options);
  const projectName = manifest.name ?? basename(dirname(manifestPath));

  return {
    projectName,
    projectVersion: manifest.version ?? '0.0.0',
    manifestPath,
    dependencies: dependencies.map((dependency) => ({
      ...dependency,
      parentPackages: [projectName],
    })),
  };
}
