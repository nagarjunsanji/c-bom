# cbom-builder

Generate a **Cryptography Bill of Materials (CBOM)** from a Node.js `package.json`,
in **CycloneDX 1.6** format plus human-readable reports.

Phase-1 answers one question: *which of my dependencies bring cryptography into my
application, and how risky is it?* It is fully offline — packages are matched against
a local curated database.

## Install

```bash
npm install
npm run build
```

## Usage

```bash
cbom scan <path>
```

| Option | Description |
| --- | --- |
| `-o, --out <dir>` | Output directory (defaults to the scanned project directory) |
| `-f, --format <formats>` | Comma separated formats: `cyclonedx` (alias `cdx`), `json`, `md` (default `json,md,cyclonedx`) |
| `--no-dev` | Ignore `devDependencies` |
| `--db <path>` | Use a custom crypto package database |
| `--fail-on <risk>` | Exit code `1` when the highest component risk reaches `low\|medium\|high\|critical` |
| `-q, --quiet` | Suppress the console summary |

Example:

```bash
node dist/cli/bin.js scan examples/sample-node-app --out ./reports --fail-on high
```

Produces:

| File | Format |
| --- | --- |
| `reports/cbom.cdx.json` | CycloneDX 1.6 CBOM |
| `reports/cbom.json` | Native CBOM (risk-oriented, easy to diff) |
| `reports/cbom.md` | Markdown report |

Emit CycloneDX only:

```bash
cbom scan . --format cyclonedx
```

## Programmatic API

```ts
import { generateCbom, generateCycloneDxBom } from 'cbom-builder';

const cbom = generateCbom('./my-app', { includeDev: false });
console.log(cbom.summary.quantumVulnerableAlgorithms);

const cdx = generateCycloneDxBom('./my-app');
console.log(cdx.serialNumber);
```

## Architecture

```
src/
  cli/        commander wiring + the scan use case
  scanners/   package.json discovery, parsing and dependency extraction
  analyzers/  matching against the database, risk scoring, summary computation
  reporters/  pluggable renderers (cbom.cdx.json, cbom.json, cbom.md)
  database/   crypto-packages.json + indexed lookup
```

The pipeline is a pure function chain: `scan -> analyze -> report`. Each stage takes
plain data and returns plain data, so every stage is independently testable and new
scanners (lockfiles, source code) or reporters (CycloneDX, SARIF) can be added without
touching the others.

## CycloneDX 1.6 output

`cbom.cdx.json` is a standard CycloneDX BOM:

- `metadata.component` — the scanned project (`type: application`, npm purl)
- `metadata.tools.components` — cbom-builder
- `metadata.properties` — the summary metrics under the `cbom:` namespace
- `components` — one `type: library` per crypto dependency (purl, `scope`,
  `cdx:npm:package:development` for dev deps) plus one deduplicated
  `type: cryptographic-asset` per algorithm
- `cryptoProperties.algorithmProperties` — `primitive`, `cryptoFunctions`,
  `nistQuantumSecurityLevel`, `executionEnvironment`, `implementationPlatform`, `oid`
- `dependencies` — project → libraries → algorithms graph
- `serialNumber` — a UUID derived from the BOM content, so identical inputs produce
  byte-identical output (diff-friendly in CI)

Risk has no native CycloneDX field, so it is exported as `cbom:risk`,
`cbom:quantumVulnerable` and `cbom:algorithm:risk` component properties.

```json
{
  "type": "cryptographic-asset",
  "bom-ref": "crypto/algorithm/rsa",
  "name": "RSA",
  "cryptoProperties": {
    "assetType": "algorithm",
    "algorithmProperties": {
      "primitive": "pke",
      "executionEnvironment": "software-plain-ram",
      "implementationPlatform": "generic",
      "cryptoFunctions": ["encrypt", "decrypt", "keygen"],
      "nistQuantumSecurityLevel": 0
    },
    "oid": "1.2.840.113549.1.1.1"
  }
}
```

## Native CBOM entry shape

```json
{
  "package": "crypto-js",
  "version": "4.2.0",
  "category": "general-purpose",
  "algorithms": ["AES-128", "3DES", "MD5", "SHA-256"],
  "risk": "critical"
}
```

Each component additionally carries `scope`, `declaredVersion`, `deprecated`,
`quantumVulnerable` and per-algorithm `algorithmDetails`.

## Summary section

- **Total dependencies** — every entry in `dependencies` + `devDependencies`
- **Crypto dependencies** — entries matched in the database
- **High-risk algorithms** — algorithms rated `high` or `critical` (MD5, SHA-1, RC4, DES…)
- **Quantum-vulnerable algorithms** — primitives broken by Shor's algorithm (RSA, ECDSA, ECDH, DH…)
- Risk breakdown per level and the highest component risk

## Database

`src/database/crypto-packages.json` holds two maps:

- `algorithms` — risk level, family, quantum vulnerability and optional CycloneDX
  metadata (`primitive`, `nistQuantumSecurityLevel`, `oid`) per primitive
- `packages` — name, aliases, category, algorithms, baseline risk, deprecation

A package's risk is the maximum of its baseline risk and the risk of every algorithm it
exposes. Extend the file (or pass `--db`) to cover internal libraries.

## Development

```bash
npm run typecheck
npm test
npm run test:coverage
```

CI runs on Node 18/20/22 and uploads the sample app's CBOM as a build artifact.

## Roadmap

- Phase 2: lockfile + transitive dependency analysis
- Phase 3: source code scanning (`node:crypto` calls, hard-coded algorithms)
- Phase 4: certificate/key material assets and post-quantum migration advice
