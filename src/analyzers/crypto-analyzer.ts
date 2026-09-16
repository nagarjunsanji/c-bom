import { CryptoPackageIndex, createIndex } from '../database';
import type {
  AlgorithmDefinition,
  AlgorithmFinding,
  Cbom,
  CbomComponent,
  CbomSummary,
  CryptoPrimitive,
  DependencyRecord,
  ScanResult,
} from '../types';
import { CBOM_SPEC_VERSION, TOOL_NAME, TOOL_VERSION } from '../version';
import { emptyRiskBreakdown, isAtLeast, maxRisk, riskScore } from './risk';

const UNKNOWN_ALGORITHM: AlgorithmDefinition = {
  type: 'unknown',
  risk: 'medium',
  quantumVulnerable: false,
};

/** Maps the database algorithm family onto the CycloneDX `primitive` enum. */
const PRIMITIVE_BY_TYPE: Record<string, CryptoPrimitive> = {
  hash: 'hash',
  checksum: 'other',
  mac: 'mac',
  symmetric: 'block-cipher',
  aead: 'ae',
  'public-key': 'pke',
  signature: 'signature',
  'key-exchange': 'key-agree',
  kdf: 'kdf',
  'password-hash': 'kdf',
  'post-quantum-kem': 'kem',
  'post-quantum-signature': 'signature',
  token: 'other',
  protocol: 'other',
  random: 'drbg',
  encoding: 'other',
};

export function primitiveFor(definition: AlgorithmDefinition): CryptoPrimitive {
  return definition.primitive ?? PRIMITIVE_BY_TYPE[definition.type] ?? 'unknown';
}

export interface AnalyzeOptions {
  index?: CryptoPackageIndex;
  /** Overrides the generation timestamp; useful for deterministic snapshots. */
  generatedAt?: string;
}

export function resolveAlgorithm(name: string, index: CryptoPackageIndex): AlgorithmFinding {
  const definition = index.db.algorithms[name] ?? UNKNOWN_ALGORITHM;
  return {
    name,
    type: definition.type,
    risk: definition.risk,
    quantumVulnerable: definition.quantumVulnerable,
    primitive: primitiveFor(definition),
    nistQuantumSecurityLevel: definition.nistQuantumSecurityLevel ?? 0,
    ...(definition.oid ? { oid: definition.oid } : {}),
  };
}

export function analyzeDependency(
  dependency: DependencyRecord,
  index: CryptoPackageIndex,
): CbomComponent | undefined {
  const definition = index.find(dependency.name);
  if (!definition) {
    return undefined;
  }

  const algorithmDetails = definition.algorithms.map((name) => resolveAlgorithm(name, index));

  return {
    package: dependency.name,
    version: dependency.version,
    category: definition.category,
    algorithms: [...definition.algorithms],
    risk: maxRisk(definition.risk, ...algorithmDetails.map((a) => a.risk)),
    scope: dependency.scope,
    declaredVersion: dependency.declaredVersion,
    deprecated: definition.deprecated ?? false,
    quantumVulnerable: algorithmDetails.some((a) => a.quantumVulnerable),
    algorithmDetails,
    ...(definition.description ? { description: definition.description } : {}),
    ...(definition.url ? { url: definition.url } : {}),
  };
}

export function analyzeDependencies(
  dependencies: DependencyRecord[],
  index: CryptoPackageIndex,
): CbomComponent[] {
  return dependencies
    .map((dependency) => analyzeDependency(dependency, index))
    .filter((component): component is CbomComponent => component !== undefined)
    .sort(
      (a, b) => riskScore(b.risk) - riskScore(a.risk) || a.package.localeCompare(b.package),
    );
}

export function summarize(
  totalDependencies: number,
  components: CbomComponent[],
): CbomSummary {
  const highRisk = new Set<string>();
  const quantumVulnerable = new Set<string>();
  const riskBreakdown = emptyRiskBreakdown();

  for (const component of components) {
    riskBreakdown[component.risk] += 1;
    for (const algorithm of component.algorithmDetails) {
      if (isAtLeast(algorithm.risk, 'high')) {
        highRisk.add(algorithm.name);
      }
      if (algorithm.quantumVulnerable) {
        quantumVulnerable.add(algorithm.name);
      }
    }
  }

  return {
    totalDependencies,
    cryptoDependencies: components.length,
    highRiskAlgorithms: [...highRisk].sort(),
    quantumVulnerableAlgorithms: [...quantumVulnerable].sort(),
    riskBreakdown,
    highestRisk: maxRisk(...components.map((component) => component.risk)),
  };
}

export function buildCbom(scan: ScanResult, options: AnalyzeOptions = {}): Cbom {
  const index = options.index ?? createIndex();
  const components = analyzeDependencies(scan.dependencies, index);

  return {
    bomFormat: 'CBOM',
    specVersion: CBOM_SPEC_VERSION,
    metadata: {
      generatedAt: options.generatedAt ?? new Date().toISOString(),
      tool: { name: TOOL_NAME, version: TOOL_VERSION },
      database: { version: index.db.version, updated: index.db.updated },
      project: {
        name: scan.projectName,
        version: scan.projectVersion,
        manifestPath: scan.manifestPath,
      },
    },
    summary: summarize(scan.dependencies.length, components),
    components,
  };
}
