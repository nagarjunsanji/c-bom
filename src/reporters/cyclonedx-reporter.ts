import { createHash } from 'node:crypto';

import type { AlgorithmFinding, Cbom, CbomComponent, CryptoPrimitive } from '../types';
import type { Reporter } from './reporter';

export const CYCLONEDX_SPEC_VERSION = '1.6';

type CycloneDxCryptoFunction =
  | 'generate'
  | 'keygen'
  | 'encrypt'
  | 'decrypt'
  | 'digest'
  | 'tag'
  | 'keyderive'
  | 'sign'
  | 'verify'
  | 'encapsulate'
  | 'decapsulate'
  | 'other';

interface CycloneDxProperty {
  name: string;
  value: string;
}

interface CycloneDxComponent {
  type: 'application' | 'library' | 'cryptographic-asset';
  'bom-ref': string;
  name: string;
  version?: string;
  description?: string;
  purl?: string;
  scope?: 'required' | 'optional' | 'excluded';
  externalReferences?: { type: string; url: string }[];
  properties?: CycloneDxProperty[];
  cryptoProperties?: {
    assetType: 'algorithm';
    algorithmProperties: {
      primitive: CryptoPrimitive;
      executionEnvironment: string;
      implementationPlatform: string;
      cryptoFunctions: CycloneDxCryptoFunction[];
      nistQuantumSecurityLevel: number;
    };
    oid?: string;
  };
}

interface CycloneDxDependency {
  ref: string;
  dependsOn: string[];
}

export interface CycloneDxBom {
  bomFormat: 'CycloneDX';
  specVersion: string;
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools: { components: CycloneDxComponent[] };
    component: CycloneDxComponent;
    properties: CycloneDxProperty[];
  };
  components: CycloneDxComponent[];
  dependencies: CycloneDxDependency[];
}

const CRYPTO_FUNCTIONS: Record<CryptoPrimitive, CycloneDxCryptoFunction[]> = {
  hash: ['digest'],
  xof: ['digest'],
  mac: ['tag'],
  'block-cipher': ['encrypt', 'decrypt'],
  'stream-cipher': ['encrypt', 'decrypt'],
  ae: ['encrypt', 'decrypt', 'tag'],
  pke: ['encrypt', 'decrypt', 'keygen'],
  signature: ['sign', 'verify', 'keygen'],
  'key-agree': ['keygen', 'other'],
  kem: ['encapsulate', 'decapsulate', 'keygen'],
  kdf: ['keyderive'],
  drbg: ['generate'],
  combiner: ['other'],
  other: ['other'],
  unknown: ['other'],
};

/** UUID derived from the BOM content so repeated runs of the same input are byte-identical. */
export function deterministicSerialNumber(seed: string): string {
  const hex = createHash('sha256').update(seed).digest('hex').slice(0, 32);
  const bytes = hex.split('');
  bytes[12] = '4';
  bytes[16] = (((parseInt(hex[16]!, 16) & 0x3) | 0x8) >>> 0).toString(16);
  const uuid = bytes.join('');
  return `urn:uuid:${uuid.slice(0, 8)}-${uuid.slice(8, 12)}-${uuid.slice(12, 16)}-${uuid.slice(16, 20)}-${uuid.slice(20, 32)}`;
}

export function toPurl(name: string, version: string): string {
  const encodedName = name.startsWith('@')
    ? `%40${name.slice(1).split('/').map(encodeURIComponent).join('/')}`
    : encodeURIComponent(name);
  return version && version !== 'unknown'
    ? `pkg:npm/${encodedName}@${encodeURIComponent(version)}`
    : `pkg:npm/${encodedName}`;
}

function algorithmRef(name: string): string {
  return `crypto/algorithm/${name.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;
}

function algorithmComponent(algorithm: AlgorithmFinding): CycloneDxComponent {
  return {
    type: 'cryptographic-asset',
    'bom-ref': algorithmRef(algorithm.name),
    name: algorithm.name,
    cryptoProperties: {
      assetType: 'algorithm',
      algorithmProperties: {
        primitive: algorithm.primitive,
        executionEnvironment: 'software-plain-ram',
        implementationPlatform: 'generic',
        cryptoFunctions: CRYPTO_FUNCTIONS[algorithm.primitive],
        nistQuantumSecurityLevel: algorithm.nistQuantumSecurityLevel,
      },
      ...(algorithm.oid ? { oid: algorithm.oid } : {}),
    },
    properties: [
      { name: 'cbom:algorithm:type', value: algorithm.type },
      { name: 'cbom:algorithm:risk', value: algorithm.risk },
      { name: 'cbom:algorithm:quantumVulnerable', value: String(algorithm.quantumVulnerable) },
    ],
  };
}

function libraryComponent(component: CbomComponent): CycloneDxComponent {
  const properties: CycloneDxProperty[] = [
    { name: 'cbom:category', value: component.category },
    { name: 'cbom:risk', value: component.risk },
    { name: 'cbom:quantumVulnerable', value: String(component.quantumVulnerable) },
    { name: 'cbom:declaredVersion', value: component.declaredVersion },
  ];
  if (component.deprecated) {
    properties.push({ name: 'cbom:deprecated', value: 'true' });
  }
  if (component.scope === 'devDependencies') {
    properties.push({ name: 'cdx:npm:package:development', value: 'true' });
  }
  if (component.vulnerabilities?.length) {
    properties.push({ name: 'cbom:cveCount', value: String(component.vulnerabilities.length) });
    properties.push({
      name: 'cbom:cveIds',
      value: component.vulnerabilities.map((vulnerability) => vulnerability.id).join(','),
    });
  }

  return {
    type: 'library',
    'bom-ref': toPurl(component.package, component.version),
    name: component.package,
    version: component.version,
    purl: toPurl(component.package, component.version),
    scope: component.scope === 'devDependencies' ? 'optional' : 'required',
    ...(component.description ? { description: component.description } : {}),
    ...(component.url ? { externalReferences: [{ type: 'website', url: component.url }] } : {}),
    properties,
  };
}

export function toCycloneDx(cbom: Cbom): CycloneDxBom {
  const { metadata, summary, components } = cbom;
  const rootRef = toPurl(metadata.project.name, metadata.project.version);

  const libraries = components.map(libraryComponent);

  const algorithms = new Map<string, CycloneDxComponent>();
  for (const component of components) {
    for (const algorithm of component.algorithmDetails) {
      const ref = algorithmRef(algorithm.name);
      if (!algorithms.has(ref)) {
        algorithms.set(ref, algorithmComponent(algorithm));
      }
    }
  }

  const dependencies: CycloneDxDependency[] = [
    { ref: rootRef, dependsOn: libraries.map((library) => library['bom-ref']) },
    ...components.map((component, i) => ({
      ref: libraries[i]!['bom-ref'],
      dependsOn: component.algorithms.map(algorithmRef),
    })),
    ...[...algorithms.keys()].map((ref) => ({ ref, dependsOn: [] })),
  ];

  const bom: Omit<CycloneDxBom, 'serialNumber'> = {
    bomFormat: 'CycloneDX',
    specVersion: CYCLONEDX_SPEC_VERSION,
    version: 1,
    metadata: {
      timestamp: metadata.generatedAt,
      tools: {
        components: [
          {
            type: 'application',
            'bom-ref': toPurl(metadata.tool.name, metadata.tool.version),
            name: metadata.tool.name,
            version: metadata.tool.version,
          },
        ],
      },
      component: {
        type: 'application',
        'bom-ref': rootRef,
        name: metadata.project.name,
        version: metadata.project.version,
        purl: rootRef,
      },
      properties: [
        { name: 'cbom:database:version', value: metadata.database.version },
        { name: 'cbom:database:updated', value: metadata.database.updated },
        { name: 'cbom:summary:totalDependencies', value: String(summary.totalDependencies) },
        { name: 'cbom:summary:cryptoDependencies', value: String(summary.cryptoDependencies) },
        { name: 'cbom:summary:highRiskAlgorithms', value: summary.highRiskAlgorithms.join(',') },
        {
          name: 'cbom:summary:quantumVulnerableAlgorithms',
          value: summary.quantumVulnerableAlgorithms.join(','),
        },
        { name: 'cbom:summary:highestRisk', value: summary.highestRisk },
      ],
    },
    components: [...libraries, ...algorithms.values()],
    dependencies,
  };

  return {
    ...bom,
    serialNumber: deterministicSerialNumber(JSON.stringify(bom)),
  };
}

export const cycloneDxReporter: Reporter = {
  id: 'cyclonedx',
  fileName: 'cbom.cdx.json',
  render(cbom: Cbom): string {
    return `${JSON.stringify(toCycloneDx(cbom), null, 2)}\n`;
  },
};
