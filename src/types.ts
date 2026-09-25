export type RiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical';

export type CryptoHealthStatus = 'healthy' | 'needs-attention' | 'at-risk' | 'migration-needed';

export type DependencyScope = 'dependencies' | 'devDependencies';

export type CryptoCategory =
  | 'general-purpose'
  | 'password-hashing'
  | 'hashing'
  | 'symmetric-encryption'
  | 'public-key'
  | 'tls'
  | 'token'
  | 'key-derivation'
  | 'random'
  | 'protocol'
  | 'post-quantum'
  | 'wallet'
  | 'unknown';

export type CryptoPrimitive =
  | 'drbg'
  | 'mac'
  | 'block-cipher'
  | 'stream-cipher'
  | 'signature'
  | 'hash'
  | 'pke'
  | 'xof'
  | 'kdf'
  | 'key-agree'
  | 'kem'
  | 'ae'
  | 'combiner'
  | 'other'
  | 'unknown';

export interface AlgorithmDefinition {
  /** Algorithm family, e.g. `hash`, `symmetric`, `signature`. */
  type: string;
  risk: RiskLevel;
  /** True when a cryptographically relevant quantum computer breaks the primitive. */
  quantumVulnerable: boolean;
  /** CycloneDX crypto primitive; derived from `type` when omitted. */
  primitive?: CryptoPrimitive;
  /** NIST post-quantum security category (0-6). */
  nistQuantumSecurityLevel?: number;
  oid?: string;
  notes?: string;
}

export interface CryptoPackageDefinition {
  name: string;
  /** Alternative published names that map to the same entry. */
  aliases?: string[];
  category: CryptoCategory;
  algorithms: string[];
  /** Baseline risk of the package itself, independent of its algorithms. */
  risk: RiskLevel;
  deprecated?: boolean;
  description?: string;
  url?: string;
}

export interface CryptoDatabase {
  version: string;
  updated: string;
  algorithms: Record<string, AlgorithmDefinition>;
  packages: CryptoPackageDefinition[];
}

export interface DependencyRecord {
  name: string;
  /** Version range exactly as declared in package.json. */
  declaredVersion: string;
  /** Best-effort concrete version parsed from the range. */
  version: string;
  scope: DependencyScope;
  parentPackages?: string[];
}

export interface ScanResult {
  projectName: string;
  projectVersion: string;
  manifestPath: string;
  dependencies: DependencyRecord[];
}

export interface AlgorithmFinding {
  name: string;
  type: string;
  risk: RiskLevel;
  quantumVulnerable: boolean;
  primitive: CryptoPrimitive;
  nistQuantumSecurityLevel: number;
  oid?: string;
}

export interface CbomComponent {
  package: string;
  version: string;
  category: CryptoCategory;
  algorithms: string[];
  risk: RiskLevel;
  scope: DependencyScope;
  declaredVersion: string;
  deprecated: boolean;
  quantumVulnerable: boolean;
  algorithmDetails: AlgorithmFinding[];
  parentPackages: string[];
  description?: string;
  url?: string;
}

export interface CbomSummary {
  totalDependencies: number;
  cryptoDependencies: number;
  highRiskAlgorithms: string[];
  quantumVulnerableAlgorithms: string[];
  riskBreakdown: Record<RiskLevel, number>;
  highestRisk: RiskLevel;
  health: CryptoHealth;
}

export interface CryptoHealth {
  score: number;
  status: CryptoHealthStatus;
  deprecatedDependencies: string[];
  highRiskProductionComponents: string[];
  highRiskDevelopmentComponents: string[];
  mediumRiskComponents: string[];
  quantumMigrationCandidates: string[];
  unreviewedQuantumFindings: string[];
}

export interface CbomMetadata {
  generatedAt: string;
  tool: { name: string; version: string };
  database: { version: string; updated: string };
  project: { name: string; version: string; manifestPath: string };
}

export interface Cbom {
  bomFormat: 'CBOM';
  specVersion: string;
  metadata: CbomMetadata;
  summary: CbomSummary;
  components: CbomComponent[];
}
