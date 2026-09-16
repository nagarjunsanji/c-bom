import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import type { Cbom } from '../types';
import { cycloneDxReporter } from './cyclonedx-reporter';
import { jsonReporter } from './json-reporter';
import { markdownReporter } from './markdown-reporter';
import type { Reporter } from './reporter';

export { cycloneDxReporter, toCycloneDx, toPurl } from './cyclonedx-reporter';
export type { CycloneDxBom } from './cyclonedx-reporter';
export { jsonReporter } from './json-reporter';
export { markdownReporter } from './markdown-reporter';
export type { Reporter } from './reporter';

export const reporters: Record<string, Reporter> = {
  [jsonReporter.id]: jsonReporter,
  [markdownReporter.id]: markdownReporter,
  [cycloneDxReporter.id]: cycloneDxReporter,
};

/** Accepted spellings for a format id. */
const FORMAT_ALIASES: Record<string, string> = {
  cdx: cycloneDxReporter.id,
  'cyclone-dx': cycloneDxReporter.id,
  markdown: markdownReporter.id,
};

export function resolveFormatId(id: string): string {
  return FORMAT_ALIASES[id] ?? id;
}

export function getReporters(ids: string[]): Reporter[] {
  return ids.map((id) => {
    const reporter = reporters[resolveFormatId(id)];
    if (!reporter) {
      throw new Error(`Unknown report format "${id}". Available: ${Object.keys(reporters).join(', ')}`);
    }
    return reporter;
  });
}

export function writeReports(cbom: Cbom, outputDir: string, ids: string[]): string[] {
  const directory = resolve(outputDir);
  mkdirSync(directory, { recursive: true });

  return getReporters(ids).map((reporter) => {
    const filePath = join(directory, reporter.fileName);
    writeFileSync(filePath, reporter.render(cbom), 'utf8');
    return filePath;
  });
}
