import { relative } from 'node:path';

import { Command } from 'commander';

import { CbomError } from '../errors';
import { TOOL_NAME, TOOL_VERSION } from '../version';
import { runLiveScan, runScan, DEFAULT_FORMATS, type ScanCommandOptions } from './scan-command';

export interface CliIO {
  log(message: string): void;
  error(message: string): void;
}

const defaultIO: CliIO = {
  log: (message) => console.log(message),
  error: (message) => console.error(message),
};

function printSummary(io: CliIO, result: ReturnType<typeof runScan>): void {
  const { summary, metadata } = result.cbom;
  io.log(`CBOM for ${metadata.project.name}@${metadata.project.version}`);
  io.log(`  Total dependencies:           ${summary.totalDependencies}`);
  io.log(`  Crypto dependencies:          ${summary.cryptoDependencies}`);
  io.log(`  High-risk algorithms:         ${summary.highRiskAlgorithms.length}`);
  io.log(`  Quantum-vulnerable algorithms: ${summary.quantumVulnerableAlgorithms.length}`);
  io.log(`  Highest component risk:       ${summary.highestRisk}`);
  io.log(`  Crypto health:                ${summary.health.status} (${summary.health.score}/100)`);
  for (const file of result.files) {
    io.log(`  Wrote ${relative(process.cwd(), file) || file}`);
  }
}

export function createProgram(io: CliIO = defaultIO): Command {
  const program = new Command();

  program
    .name('cbom')
    .description('Generate a Cryptography Bill of Materials from a package.json')
    .version(TOOL_VERSION, '-v, --version', `output ${TOOL_NAME} version`);

  program
    .command('scan')
    .argument('<path>', 'path to a project directory or package.json')
    .description('scan a project and emit cbom.json / cbom.md / cbom.cdx.json')
    .option('-o, --out <dir>', 'output directory (defaults to the scanned project directory)')
    .option(
      '-f, --format <formats>',
      'comma separated output formats: md,cyclonedx (json remains available explicitly)',
      DEFAULT_FORMATS,
    )
    .option('--no-dev', 'ignore devDependencies')
    .option('--db <path>', 'path to a custom crypto package database')
    .option('--fail-on <risk>', 'exit with code 1 when the highest risk reaches this level')
    .option('--live', 'use Groq for crypto classification and transitive dependency analysis')
    .option('-q, --quiet', 'suppress the console summary', false)
    .action(async (target: string, options: ScanCommandOptions & { quiet?: boolean }) => {
      const result = options.live ? await runLiveScan(target, options) : runScan(target, options);
      if (!options.quiet) {
        printSummary(io, result);
      }
      if (result.exitCode !== 0) {
        io.error(`Risk threshold "${options.failOn}" reached.`);
        process.exitCode = result.exitCode;
      }
    });

  return program;
}

export async function run(argv: string[] = process.argv, io: CliIO = defaultIO): Promise<void> {
  try {
    await createProgram(io).parseAsync(argv);
  } catch (error) {
    if (error instanceof CbomError) {
      io.error(`error: ${error.message}`);
      process.exitCode = 2;
      return;
    }
    throw error;
  }
}
