# CBOM Builder: Cryptography Bill of Materials (CBOM)

This document describes how the `cbom-builder` project generates a Cryptography Bill of Materials (CBOM) and assesses cryptographic risk for Node.js applications. The resulting inventory can also provide context for future CVE prioritization workflows.

The current implementation is Phase-1. It scans a Node.js `package.json`, identifies known cryptographic packages from a local database, assesses algorithm risk, and exports a CycloneDX 1.6 CBOM. AI-based CVE prioritization, lockfile analysis, transitive dependency analysis, and source-code scanning are integration opportunities for later phases.

## 🎯 Executive Summary

`cbom-builder` generates a cryptographic inventory for Node.js applications. It reads a target project's `package.json`, extracts `dependencies` and `devDependencies`, matches package names and aliases against a local crypto package database, and produces:

- `cbom.cdx.json`: CycloneDX 1.6 CBOM output
- `cbom.json`: native risk-oriented CBOM output
- `cbom.md`: human-readable report

The CBOM identifies cryptographic packages, algorithms, risk levels, deprecated primitives, and quantum-vulnerable algorithms. This inventory can be used as an input to a broader CVE prioritization system that combines software vulnerabilities with cryptographic exposure and application context.

## 🚨 The Problem We're Solving

Traditional dependency scanning identifies vulnerable packages, but it does not necessarily explain the cryptographic consequences of those dependencies. Security teams may need to answer additional questions:

- Which application dependencies provide cryptographic functionality?
- Which algorithms are exposed by those dependencies?
- Are legacy or weak algorithms such as MD5, SHA-1, DES, RC4, or 3DES present?
- Which components depend on quantum-vulnerable algorithms such as RSA, ECDSA, ECDH, or Diffie-Hellman?
- Which findings should be prioritized based on cryptographic risk and future migration requirements?

A CVE score alone does not answer these questions. A package with no current CVE may still introduce obsolete cryptographic algorithms, while a package with a CVE may have different urgency depending on whether its cryptographic functionality is used in a production path.

## 💡 Our Solution

The project provides a deterministic CBOM generation pipeline:

```text
package.json
    -> package.json scanner
    -> crypto package and alias matching
    -> algorithm enrichment
    -> risk and quantum-vulnerability analysis
    -> CycloneDX / JSON / Markdown reports
```

The analyzer calculates a component's risk as the highest value among the package baseline risk and the algorithms exposed by that package. It also records whether any algorithm is quantum-vulnerable.

This output can become one signal in a future prioritization model alongside CVSS, EPSS, exploit availability, asset criticality, reachability, deployment exposure, and remediation availability.

## 🏗️ System Architecture

The repository is organized into focused TypeScript modules:

```text
src/
  cli/        Commander CLI and scan command
  scanners/   package.json discovery and dependency extraction
  analyzers/  crypto matching, algorithm enrichment, and risk scoring
  reporters/  CycloneDX, native JSON, and Markdown reporters
  database/   local crypto package and algorithm catalog
  types.ts    shared domain types
```

The main pipeline is:

1. `src/scanners/package-json-scanner.ts` resolves a directory or direct `package.json` path.
2. Dependencies are represented as `{ name, declaredVersion, version, scope }`.
3. `src/database/index.ts` creates a case-insensitive index of package names and aliases.
4. `src/analyzers/crypto-analyzer.ts` creates CBOM components for matched packages.
5. Risk, high-risk algorithms, and quantum-vulnerable algorithms are summarized.
6. `src/reporters/cyclonedx-reporter.ts` creates a CycloneDX 1.6 document.
7. The CLI writes the selected reports to the output directory.

## 🌟 Key Features

- Node.js and TypeScript implementation
- CLI command: `cbom scan <path>`
- Reads both `dependencies` and `devDependencies`
- Optional `--no-dev` mode for production-only analysis
- Local, offline crypto package database
- Case-insensitive package and alias matching
- Package categories such as general-purpose, hashing, symmetric encryption, public-key, TLS, token, password hashing, key derivation, random, protocol, wallet, and post-quantum
- Algorithm-level risk assessment
- Quantum-vulnerability detection
- Deprecated package and algorithm indicators
- CycloneDX 1.6 cryptographic assets
- npm Package URLs (`purl`) for package identity
- Dependency graph from project to libraries to algorithms
- Deterministic BOM serial number for repeatable output
- `--fail-on` threshold for CI policy enforcement
- Custom database support through `--db <path>`
- Unit tests and GitHub Actions for Node.js 18, 20, and 22

## 🔗 Data Sources & APIs

### Current data sources

The current Phase-1 implementation is intentionally offline and uses:

- The target project's `package.json`
- `src/database/crypto-packages.json`
- Optional user-supplied database passed with `--db`

The local database contains package names, aliases, categories, algorithms, baseline risks, deprecation flags, descriptions, URLs, OIDs, CycloneDX primitive types, and NIST quantum security levels.

### Current APIs

```bash
cbom scan <path>
cbom scan <path> --format cyclonedx
cbom scan <path> --out reports --fail-on high
cbom scan <path> --no-dev
cbom scan <path> --db ./custom-crypto-packages.json
```

The programmatic API includes `generateCbom()` and `generateCycloneDxBom()` from the package entry point.

### Future integrations

A complete CVE prioritization platform could add adapters for the NVD, CISA Known Exploited Vulnerabilities, EPSS, OSV, GitHub Advisory Database, package registries, lockfiles, asset inventories, and Debricked data. Those integrations are not part of the current Phase-1 implementation.

## 📊 Risk Assessment Methodology

The current risk model uses five ordered levels:

```text
none < low < medium < high < critical
```

For each matched package:

```text
component risk = max(package baseline risk, all algorithm risks)
```

Examples:

- `bcrypt` is low risk because it provides adaptive password hashing.
- `node-rsa` is high risk because it provides RSA and legacy RSA padding options.
- `crypto-js` is critical at the component level because its catalog entry includes severely weak or deprecated algorithms such as MD5, DES, and RC4.

The summary includes:

- Total dependencies
- Crypto dependencies
- High-risk and critical algorithms
- Quantum-vulnerable algorithms
- Risk breakdown by component
- Highest component risk

This is a cryptographic exposure assessment, not a CVSS replacement. It does not claim that every listed algorithm is executed by the application.

## 🧠 How CBOM Supports Future CVE Prioritization

AI prioritization is not implemented in this repository. The current CBOM is a deterministic evidence source that a future model or rules engine could use alongside vulnerability intelligence.

### CBOM evidence available today

For each cataloged cryptographic dependency, the CBOM provides:

- Package name, declared version, best-effort resolved version, and dependency scope.
- Package category, baseline risk, calculated component risk, and deprecation status.
- Known algorithms and per-algorithm risk ratings.
- Quantum-vulnerability indicators and NIST quantum security levels where available.
- Package-to-algorithm relationships in the CycloneDX 1.6 dependency graph.
- Summary counts for crypto dependencies, high-risk algorithms, quantum-vulnerable algorithms, and risk levels.

### Future prioritization workflow

A CVE prioritization service could correlate each vulnerability with the CBOM package identity and calculate a recommendation using:

```text
CVE severity and affected version range
+ exploit probability and known exploitation status
+ application or asset criticality
+ cryptographic component and algorithm risk
+ quantum-vulnerability status
+ production or development dependency scope
+ fixed-version availability
= explainable remediation priority
```

The CBOM can raise the priority of a vulnerability affecting a cryptographic dependency or an algorithm with critical, high, deprecated, or quantum-migration concerns. It cannot currently establish runtime algorithm usage, transitive reachability, exploitability, asset criticality, or the presence of a CVE; those require additional scanners, service integrations, or application context.

Any AI-generated recommendation should identify the CVE, package and version evidence, relevant algorithm findings, data sources, decision factors, and confidence level. Human review should remain part of the remediation decision.

## 📥 Input Methods & Flexibility

### Current inputs

The CLI accepts either:

- A project directory containing `package.json`
- A direct path to `package.json`

By default, both production and development dependencies are scanned. Use `--no-dev` to exclude `devDependencies`.

### Version handling

The scanner preserves the declared version range and derives a best-effort version value:

- `^4.2.0` becomes `4.2.0`
- `~1.3.0` becomes `1.3.0`
- `workspace:*`, `file:`, and Git dependencies become `unknown`

The current scanner does not read `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, or `pnpm-lock.yaml`.

### Extensibility

The reporter interface allows additional output formats. The database can be extended without changing the analyzer by adding packages, aliases, algorithms, and metadata to a custom database file.

## 📊 Output Format & Visualization

The default command creates three reports:

| File | Purpose |
| --- | --- |
| `cbom.cdx.json` | Machine-readable CycloneDX 1.6 CBOM |
| `cbom.json` | Native risk-oriented CBOM model |
| `cbom.md` | Human-readable summary and component table |

The CycloneDX report represents:

- The scanned project as an application component
- Crypto dependencies as `library` components
- Algorithms as deduplicated `cryptographic-asset` components
- `cryptoProperties.algorithmProperties` for primitive, functions, execution environment, implementation platform, and NIST quantum security level
- `dependencies[]` links from project to packages and packages to algorithms
- CBOM risk and summary values under `cbom:` properties

The Markdown report is useful for reviews and Confluence publishing. The CycloneDX JSON report is intended for automation, artifact storage, and integration with SBOM/CBOM tooling.

## 🎨 Debricked Integration Vision

A future Debricked integration could combine dependency vulnerability findings with the CBOM's cryptographic context.

Potential flow:

1. Debricked or another SCA platform provides package and CVE findings.
2. `cbom-builder` provides cryptographic package, algorithm, risk, and quantum exposure data.
3. A correlation service joins records using package URLs, package names, versions, and dependency graph references.
4. A prioritization view ranks findings using both vulnerability evidence and cryptographic impact.
5. The result is exported to dashboards, tickets, CI checks, or a consolidated CycloneDX artifact.

The current repository does not call Debricked APIs or transmit project data externally.

## 📈 Results & Impact

For the included `examples/sample-node-app`, the generated report demonstrates:

- Dependency inventory from `package.json`
- Identification of known crypto packages while ignoring unrelated packages
- Detection of legacy and high-risk algorithms
- Detection of RSA and other quantum-vulnerable algorithms
- Production versus development dependency scope
- CycloneDX library-to-algorithm dependency relationships
- CI-friendly JSON and Markdown artifacts

The impact of the current phase is improved crypto visibility and a consistent machine-readable foundation for future security prioritization. It does not yet measure vulnerability reduction, remediation time, or AI recommendation accuracy.

## 💡 Use Cases & Scenarios

### CI/CD policy gate

```bash
cbom scan . --format cyclonedx --fail-on high
```

The command exits with code `1` when the highest detected component risk reaches the configured threshold.

### Post-quantum readiness inventory

Use `cbom.cdx.json` to identify packages and algorithms marked as quantum-vulnerable. This creates an initial migration inventory for RSA, ECDSA, ECDH, Diffie-Hellman, Ed25519, X25519, and related algorithms.

### Secure package review

Use `cbom.md` to review whether a proposed dependency introduces deprecated algorithms, weak hashes, unauthenticated encryption modes, or non-cryptographic randomness.

### Software supply-chain evidence

Store the CycloneDX report as a build artifact alongside the application release. Its package URLs, dependency graph, database version, timestamp, and deterministic serial number support repeatable reviews.

### Future CVE correlation

Join the package references in the CBOM with CVE findings from an SCA platform to add cryptographic exposure to vulnerability prioritization.

## 🔒 Security & Compliance

The implementation supports security and compliance workflows by providing:

- A documented local crypto package catalog
- Explicit algorithm-level metadata
- Traceable package-to-algorithm relationships
- CycloneDX 1.6 interoperability
- Repeatable output suitable for CI artifacts
- No network access during scanning
- Custom database support for organization-specific packages
- Risk and quantum-vulnerability properties that can be reviewed or governed

Important limitations:

- The current database is curated and finite.
- Package capability is reported; actual runtime use is not proven.
- Transitive dependencies are not resolved in Phase-1.
- Installed lockfile versions are not used.
- No source-code, certificate, key-material, or configuration scanning is performed.
- Risk labels are CBOM-specific and should not be treated as CVSS scores.

## ❓ Frequently Asked Questions

### Is the output CycloneDX?

Yes. `cbom.cdx.json` uses CycloneDX 1.6 and includes library components, cryptographic assets, crypto properties, package URLs, and a dependency graph.

### Is this an AI system today?

No. The current project is a deterministic scanner and analyzer. It produces structured crypto-risk evidence that can be consumed by a future AI or rules-based prioritization system.

### Does the scanner inspect application source code?

No. Phase-1 only reads `package.json`. Source-code scanning is planned for a later phase.

### Does it scan transitive dependencies?

No. Lockfile and transitive dependency analysis are planned for a later phase.

### Does a listed algorithm mean the application uses it?

No. A listed algorithm means the matched package is cataloged as providing that capability. Runtime or call-site usage is not established.

### Can the package database be customized?

Yes. Pass a compatible database file with `--db <path>`. The database must contain `version`, `updated`, `algorithms`, and `packages` fields.

### Can development dependencies be excluded?

Yes. Use `--no-dev`.

### Where does the CBOM summary appear in CycloneDX?

CycloneDX summary metrics are stored as `cbom:summary:*` properties under `metadata.properties`. Component-level risk is stored under `cbom:*` properties.

## 📚 References

### Project references

- Project README
- Crypto package database
- Package JSON scanner
- Crypto analyzer
- CycloneDX reporter
- Sample Node.js application
- CI workflow
- CBOM workflow

### Standards and security references

- CycloneDX
- CycloneDX 1.6 specification
- NIST Post-Quantum Cryptography project
- NIST Cybersecurity Framework
- National Vulnerability Database
- CISA Known Exploited Vulnerabilities Catalog
- EPSS
- OSV

## 🎉 Conclusion

`cbom-builder` establishes the cryptographic inventory layer for a broader AI-powered CVE prioritization system. Its Phase-1 implementation is local, deterministic, testable, and compatible with CycloneDX 1.6.

The project currently answers which known cryptographic dependencies and algorithms are present in a Node.js project's declared dependencies. The next steps are lockfile and transitive analysis, source-code usage detection, certificate and key-material discovery, external vulnerability correlation, and explainable prioritization that combines CBOM evidence with CVE intelligence.
