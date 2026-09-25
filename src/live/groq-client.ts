import 'dotenv/config';

import type { CryptoCategory, CryptoPackageDefinition, CryptoDatabase, RiskLevel } from '../types';

const DEFAULT_MODEL = 'openai/gpt-oss-120b';
const RISK_LEVELS: RiskLevel[] = ['none', 'low', 'medium', 'high', 'critical'];
const CATEGORIES: CryptoCategory[] = [
  'general-purpose',
  'password-hashing',
  'hashing',
  'symmetric-encryption',
  'public-key',
  'tls',
  'token',
  'key-derivation',
  'random',
  'protocol',
  'post-quantum',
  'wallet',
  'unknown',
];

function isCryptoCandidate(name: string): boolean {
  return /crypto|crypt|hash|sha|md5|blake|argon|bcrypt|scrypt|random|uuid|nanoid|nacl|sodium|cipher|encrypt|decrypt|rsa|ecdsa|ecdh|elliptic|curve|jose|jwt|token|tls|ssl|ssh|pgp|password|digest|hmac|key|secure|murmur|crc/i.test(name);
}

function candidateScore(name: string): number {
  if (/crypto|crypt|bcrypt|argon|scrypt|nacl|sodium|rsa|ecdsa|ecdh|elliptic|jose|jwt|tls|ssl|ssh|pgp/i.test(name)) return 3;
  if (/uuid|nanoid|hash|sha|md5|blake|random|cipher|encrypt|decrypt|hmac|password|digest|secure|murmur|crc/i.test(name)) return 2;
  return 1;
}

export interface GroqAlgorithmAssessment {
  name: string;
  type: string;
  risk: RiskLevel;
  quantumVulnerable: boolean;
  primitive?: CryptoPackageDefinition['category'];
  nistQuantumSecurityLevel?: number;
}

export interface GroqPackageAssessment {
  isCryptographicPackage: boolean;
  category: CryptoCategory;
  algorithms: GroqAlgorithmAssessment[];
  risk: RiskLevel;
  deprecated: boolean;
  description?: string;
}

interface GroqResponse {
  choices?: Array<{ message?: { content?: string } }>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function parseAssessment(value: unknown): GroqPackageAssessment {
  if (!isRecord(value)) {
    throw new Error('Groq returned a non-object assessment.');
  }

  const algorithms = Array.isArray(value.algorithms) ? value.algorithms : [];
  const categoryAliases: Record<string, CryptoCategory> = {
    none: 'unknown',
    'random number generation': 'random',
    'randomness': 'random',
    'symmetric encryption': 'symmetric-encryption',
    'public key': 'public-key',
    'password hashing': 'password-hashing',
    'key derivation': 'key-derivation',
    'post quantum': 'post-quantum',
  };
  const rawCategory = typeof value.category === 'string' ? value.category.toLowerCase() : '';
  const category = categoryAliases[rawCategory] ?? value.category;
  const risk = value.risk;
  if (typeof value.isCryptographicPackage !== 'boolean' || typeof category !== 'string' || !CATEGORIES.includes(category as CryptoCategory)) {
    throw new Error('Groq returned an invalid package assessment.');
  }
  if (typeof risk !== 'string' || !RISK_LEVELS.includes(risk as RiskLevel)) {
    throw new Error('Groq returned an invalid risk level.');
  }

  const parsedAlgorithms = algorithms.map((algorithm): GroqAlgorithmAssessment => {
    if (!isRecord(algorithm) || typeof algorithm.name !== 'string' || typeof algorithm.type !== 'string') {
      throw new Error('Groq returned an invalid algorithm assessment.');
    }
    if (typeof algorithm.risk !== 'string' || !RISK_LEVELS.includes(algorithm.risk as RiskLevel)) {
      throw new Error('Groq returned an invalid algorithm risk.');
    }
    if (typeof algorithm.quantumVulnerable !== 'boolean') {
      throw new Error('Groq returned an invalid quantum vulnerability flag.');
    }
    const normalizedName = /^(crypto\.)?(randombytes|getrandomvalues)$/i.test(algorithm.name)
      ? 'CSPRNG'
      : algorithm.name;
    const normalizedRisk = /^md5$/i.test(normalizedName)
      ? 'critical'
      : /^sha-?1$/i.test(normalizedName)
        ? 'high'
        : algorithm.risk;
    return {
      name: normalizedName,
      type: /^csprng$/i.test(normalizedName) ? 'random' : algorithm.type,
      risk: normalizedRisk as RiskLevel,
      quantumVulnerable: /^md5$|^sha-?1$/i.test(normalizedName) ? false : algorithm.quantumVulnerable,
      ...(typeof algorithm.nistQuantumSecurityLevel === 'number'
        ? { nistQuantumSecurityLevel: algorithm.nistQuantumSecurityLevel }
        : {}),
    };
  });

  return {
    isCryptographicPackage: value.isCryptographicPackage,
    category: category as CryptoCategory,
    algorithms: parsedAlgorithms,
    risk: risk as RiskLevel,
    deprecated: value.deprecated === true,
    ...(typeof value.description === 'string' ? { description: value.description } : {}),
  };
}

export async function assessPackageWithGroq(
  packageName: string,
  version: string,
  options: { apiKey?: string; model?: string; fetchImpl?: typeof fetch } = {},
): Promise<GroqPackageAssessment> {
  const apiKey = options.apiKey ?? process.env.GROQ_API_KEY;
  if (!apiKey) {
    throw new Error('GROQ_API_KEY is required for live scanning.');
  }

  const fetchImpl = options.fetchImpl ?? fetch;
  const response = await fetchImpl('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: options.model ?? process.env.GROQ_MODEL ?? DEFAULT_MODEL,
      temperature: 0,
      response_format: { type: 'json_object' },
      messages: [
        {
          role: 'system',
          content:
            'Classify npm package cryptographic capabilities. Return only JSON. Treat hashing, checksums, random number generation, encryption, key derivation, signatures, key exchange, tokens, TLS, wallets, and crypto protocols as cryptographic capabilities. Do not invent CVEs. If the package has none of those capabilities, set isCryptographicPackage to false, category to unknown, and algorithms to [].',
        },
        {
          role: 'user',
          content: JSON.stringify({
            package: packageName,
            version,
            schema: {
              isCryptographicPackage: 'boolean',
              category: 'one supported crypto category',
              algorithms: [{ name: 'string', type: 'string', risk: 'none|low|medium|high|critical', quantumVulnerable: 'boolean' }],
              risk: 'none|low|medium|high|critical',
              deprecated: 'boolean',
              description: 'optional string',
            },
          }),
        },
      ],
    }),
  });

  if (!response.ok) {
    throw new Error(`Groq request failed with HTTP ${response.status}.`);
  }
  const payload = (await response.json()) as GroqResponse;
  const content = payload.choices?.[0]?.message?.content;
  if (!content) {
    throw new Error('Groq returned no assessment content.');
  }
  return parseAssessment(JSON.parse(content));
}

export async function buildLiveDatabase(
  packageNames: Array<{ name: string; version: string }>,
  fallback: CryptoDatabase,
  options: { apiKey?: string; model?: string; fetchImpl?: typeof fetch } = {},
): Promise<CryptoDatabase> {
  const candidates = packageNames
    .filter(({ name }) => isCryptoCandidate(name))
    .sort((a, b) => candidateScore(b.name) - candidateScore(a.name))
    .slice(0, 40);
  const assessments: PromiseSettledResult<{
    dependency: { name: string; version: string };
    assessment: GroqPackageAssessment;
  }>[] = [];
  const concurrency = 4;
  let cursor = 0;
  async function worker(): Promise<void> {
    while (cursor < packageNames.length) {
      const dependency = packageNames[cursor++];
      if (!dependency) continue;
      try {
        assessments.push({
          status: 'fulfilled',
          value: {
            dependency,
            assessment: await assessPackageWithGroq(dependency.name, dependency.version, options),
          },
        });
      } catch (reason) {
        assessments.push({ status: 'rejected', reason });
      }
    }
  }
  packageNames = candidates;
  await Promise.all(Array.from({ length: Math.min(concurrency, packageNames.length) }, () => worker()));
  const packages = [...fallback.packages];
  const algorithms = { ...fallback.algorithms };

  for (const result of assessments) {
    if (result.status !== 'fulfilled' || !result.value.assessment.isCryptographicPackage) {
      continue;
    }
    const { dependency, assessment } = result.value;
    const packageDefinition: CryptoPackageDefinition = {
      name: dependency.name,
      category: assessment.category,
      algorithms: assessment.algorithms.map((algorithm) => algorithm.name),
      risk: assessment.risk,
      deprecated: assessment.deprecated,
      ...(assessment.description ? { description: assessment.description } : {}),
    };
    const existing = packages.some((item) =>
      [item.name, ...(item.aliases ?? [])].some(
        (name) => name.toLowerCase() === dependency.name.toLowerCase(),
      ),
    );
    if (!existing) packages.push(packageDefinition);

    for (const algorithm of assessment.algorithms) {
      algorithms[algorithm.name] = {
        type: algorithm.type,
        risk: algorithm.risk,
        quantumVulnerable: algorithm.quantumVulnerable,
        ...(algorithm.nistQuantumSecurityLevel !== undefined
          ? { nistQuantumSecurityLevel: algorithm.nistQuantumSecurityLevel }
          : {}),
      };
    }
  }

  return { ...fallback, updated: new Date().toISOString(), packages, algorithms };
}
