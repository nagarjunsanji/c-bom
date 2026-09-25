import { dirname } from 'node:path';

import { buildCbom } from '../analyzers';
import { isAtLeast, isRiskLevel } from '../analyzers/risk';
import { createIndex, loadDatabase } from '../database';
import { CbomError } from '../errors';
import { writeReports, resolveFormatId } from '../reporters';
import { scanPackageJson } from '../scanners';
import type { Cbom, RiskLevel } from '../types';
import { buildLiveDatabase } from '../live/groq-client';
import { resolveLiveDependencies } from '../live/npm-client';

export interface ScanCommandOptions {
  out?: string;
  format?: string;
  dev?: boolean;
  db?: string;
  failOn?: string;
  live?: boolean;
}

export interface ScanCommandResult {
  cbom: Cbom;
  files: string[];
  exitCode: number;
}

export const DEFAULT_FORMATS = 'md,cyclonedx';

export function parseFormats(format = DEFAULT_FORMATS): string[] {
  const ids = format
    .split(',')
    .map((value) => resolveFormatId(value.trim().toLowerCase()))
    .filter(Boolean);
  if (ids.length === 0) {
    throw new CbomError('No output format specified.', 'EFORMAT');
  }
  return [...new Set(ids)];
}

function parseFailOn(value: string | undefined): RiskLevel | undefined {
  if (!value) {
    return undefined;
  }
  const normalized = value.trim().toLowerCase();
  if (!isRiskLevel(normalized)) {
    throw new CbomError(`Invalid --fail-on value "${value}". Use one of: low, medium, high, critical.`, 'EFAILON');
  }
  return normalized;
}

export function runScan(target: string, options: ScanCommandOptions = {}): ScanCommandResult {
  const formats = parseFormats(options.format);
  const threshold = parseFailOn(options.failOn);

  const scan = scanPackageJson(target, { includeDev: options.dev ?? true });
  const index = createIndex(loadDatabase(options.db));
  const cbom = buildCbom(scan, { index });

  const outputDir = options.out ?? dirname(scan.manifestPath);
  const files = writeReports(cbom, outputDir, formats);

  const exitCode = threshold && isAtLeast(cbom.summary.highestRisk, threshold) ? 1 : 0;

  return { cbom, files, exitCode };
}

export async function runLiveScan(target: string, options: ScanCommandOptions = {}): Promise<ScanCommandResult> {
  if (!process.env.GROQ_API_KEY) {
    throw new CbomError('Live scanning requires GROQ_API_KEY.', 'ELIVECONFIG');
  }
  const formats = parseFormats(options.format);
  const threshold = parseFailOn(options.failOn);
  const initialScan = scanPackageJson(target, { includeDev: options.dev ?? true });
  const dependencies = await resolveLiveDependencies(initialScan.dependencies);
  const scan = { ...initialScan, dependencies };
  const fallback = loadDatabase(options.db);
  const database = await buildLiveDatabase(
    scan.dependencies.map(({ name, version }) => ({ name, version })),
    fallback,
  );
  const index = createIndex(database);
  const cbom = buildCbom(scan, { index });
  const outputDir = options.out ?? dirname(scan.manifestPath);
  const files = writeReports(cbom, outputDir, formats);
  const exitCode = threshold && isAtLeast(cbom.summary.highestRisk, threshold) ? 1 : 0;
  return { cbom, files, exitCode };
}
