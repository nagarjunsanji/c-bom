import { buildCbom } from './analyzers';
import { createIndex, loadDatabase } from './database';
import { toCycloneDx, type CycloneDxBom } from './reporters';
import { scanPackageJson } from './scanners';
import type { Cbom } from './types';

export * from './types';
export { CbomError } from './errors';
export { TOOL_NAME, TOOL_VERSION, CBOM_SPEC_VERSION } from './version';
export * from './analyzers';
export * from './scanners';
export * from './reporters';
export { EMPTY_DATABASE, CryptoPackageIndex, createIndex, loadDatabase } from './database';

export interface GenerateCbomOptions {
  includeDev?: boolean;
  databasePath?: string;
  generatedAt?: string;
}

/** Scans a project path and returns the complete CBOM document. */
export function generateCbom(target: string, options: GenerateCbomOptions = {}): Cbom {
  const scan = scanPackageJson(target, { includeDev: options.includeDev });
  const index = createIndex(loadDatabase(options.databasePath));
  return buildCbom(scan, { index, generatedAt: options.generatedAt });
}

/** Same as {@link generateCbom}, rendered as a CycloneDX 1.6 CBOM document. */
export function generateCycloneDxBom(
  target: string,
  options: GenerateCbomOptions = {},
): CycloneDxBom {
  return toCycloneDx(generateCbom(target, options));
}
