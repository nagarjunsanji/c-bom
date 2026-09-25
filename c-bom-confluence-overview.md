# CBOM Builder: Cryptography Bill of Materials (CBOM)

This document describes how the `cbom-builder` project generates a Cryptography Bill of Materials (CBOM) and assesses cryptographic risk for Node.js applications. The resulting inventory can also provide context for future CVE prioritization workflows.

The default implementation scans a Node.js `package.json` and exports a CycloneDX 1.6 CBOM plus a Markdown report. The opt-in `--live` mode resolves a bounded transitive npm dependency graph, uses Groq for cryptographic package classification, and queries NVD for current CVE enrichment. Lockfile analysis and source-code scanning remain future work.

## 🎯 Executive Summary

`cbom-builder` generates a cryptographic inventory for Node.js applications. It reads a target project's `package.json`, extracts `dependencies` and `devDependencies`, and in live mode enriches bounded transitive dependencies with npm, Groq, and NVD data. It produces:

- `cbom.cdx.json`: CycloneDX 1.6 CBOM output
- `cbom.md`: human-readable report

The CBOM identifies cryptographic packages, algorithms, risk levels, deprecated primitives, quantum-vulnerability indicators, parent packages, and available CVE findings. This inventory can be used as an input to a broader CVE prioritization system that combines software vulnerabilities with cryptographic exposure and application context.

## 🚨 The Problem We're Solving

Traditional dependency scanning identifies vulnerable packages, but it does not necessarily explain the cryptographic consequences of those dependencies. Security teams may need to answer additional questions:

- Which application dependencies provide cryptographic functionality?
- Which algorithms are exposed by those dependencies?
- Are legacy or weak algorithms such as MD5, SHA-1, DES, RC4, or 3DES present?
- Which components depend on quantum-vulnerable algorithms such as RSA, ECDSA, ECDH, or Diffie-Hellman?
- Which findings should be prioritized based on cryptographic risk and future migration requirements?

A CVE score alone does not answer these questions. A package with no current CVE may still introduce obsolete cryptographic algorithms, while a package with a CVE may have different urgency depending on whether its cryptographic functionality is used in a production path.

## 💡 Our Solution

The project provides a CBOM generation pipeline:

```text
package.json
    -> package.json scanner
    -> npm dependency resolution
    -> Groq crypto capability classification or custom database matching
    -> algorithm enrichment
    -> risk and quantum-vulnerability analysis
    -> CycloneDX / JSON / Markdown reports
```

The analyzer calculates a component's risk as the highest value among the package baseline risk and the algorithms exposed by that package. It also records whether any algorithm is quantum-vulnerable.

In live mode, this output can become one signal in a future prioritization model alongside CVSS, EPSS, exploit availability, asset criticality, deployment exposure, and remediation availability. Groq classifications and NVD keyword matches require review.

## 🏗️ System Architecture

The repository is organized into focused TypeScript modules:

```text
src/
  cli/        Commander CLI and scan command
  scanners/   package.json discovery and dependency extraction
  analyzers/  crypto matching, algorithm enrichment, and risk scoring
  reporters/  CycloneDX, native JSON, and Markdown reporters
  database/   optional custom database loading and indexed lookup
  types.ts    shared domain types
```

The main pipeline is:

1. `src/scanners/package-json-scanner.ts` resolves a directory or direct `package.json` path.
2. Dependencies are represented as `{ name, declaredVersion, version, scope }`.
4. `src/live/npm-client.ts` resolves bounded transitive dependencies in live mode.
5. `src/live/groq-client.ts` classifies likely crypto-related packages and builds a live database.
6. `src/analyzers/crypto-analyzer.ts` creates CBOM components and risk summaries.
7. `src/live/nvd-client.ts` attaches available CVE findings.
8. The reporters create CycloneDX 1.6 and Markdown output.
9. The CLI writes the selected reports to the output directory.

## 🌟 Key Features

- Node.js and TypeScript implementation
- CLI command: `cbom scan <path>`
- Reads both `dependencies` and `devDependencies`
- Optional `--no-dev` mode for production-only analysis
- Live Groq classification with optional custom database support
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
- Optional `--live` mode for npm transitive resolution, Groq classification, and NVD CVE enrichment
- Custom database support through `--db <path>`
- Unit tests and GitHub Actions for Node.js 18, 20, and 22

## 🔗 Data Sources & APIs

### Current data sources

Live mode uses:

- The target project's `package.json`
- npm registry metadata for bounded transitive dependency resolution
- Groq package classification
- NVD CVE data
- An optional organization-maintained database passed with `--db`

An optional custom database can provide package names, aliases, categories, algorithms, baseline risks, deprecation flags, descriptions, URLs, OIDs, CycloneDX primitive types, and NIST quantum security levels.

### Current APIs

```bash
cbom scan <path>
cbom scan <path> --format cyclonedx
cbom scan <path> --out reports --fail-on high
cbom scan <path> --no-dev
cbom scan <path> --live
cbom scan <path> --db ./custom-crypto-db.json
```

The programmatic API includes `generateCbom()` and `generateCycloneDxBom()` from the package entry point.

### Future integrations

A complete CVE prioritization platform could add adapters for CISA Known Exploited Vulnerabilities, EPSS, OSV, GitHub Advisory Database, lockfiles, asset inventories, and Debricked data. NVD and npm registry enrichment are already used by `--live`; the additional integrations are future work.

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

- A live classification can mark a package low risk when it provides modern password hashing or secure random generation.
- A package exposing RSA or legacy padding can be rated high risk and quantum-vulnerable.
- A package exposing MD5, DES, or RC4 can be rated critical at the component level.

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

For each live-classified or custom-database cryptographic dependency, the CBOM provides:

- Package name, declared version, best-effort resolved version, and dependency scope.
- Package category, baseline risk, calculated component risk, and deprecation status.
- Known algorithms and per-algorithm risk ratings.
- Quantum-vulnerability indicators and NIST quantum security levels where available.
- Package-to-algorithm relationships in the CycloneDX 1.6 dependency graph.
- Parent package references for transitive dependencies.
- NVD CVE identifiers and counts when enrichment succeeds.
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

The CBOM can raise the priority of a vulnerability affecting a cryptographic dependency or an algorithm with critical, high, deprecated, or quantum-migration concerns. It does not establish runtime algorithm usage, exploitability, or asset criticality. NVD results are keyword-based and may be incomplete; those limitations require additional scanners, service integrations, or application context.

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

In `--live` mode, the npm registry is queried to resolve up to three levels of transitive dependencies. Installed lockfile versions are still not used.

### Extensibility

The reporter interface allows additional output formats. The database can be extended without changing the analyzer by adding packages, aliases, algorithms, and metadata to a custom database file.

## 📊 Output Format & Visualization

The default command creates two reports:

| File | Purpose |
| --- | --- |
| `cbom.cdx.json` | Machine-readable CycloneDX 1.6 CBOM |
| `cbom.md` | Human-readable summary and component table |

The CycloneDX report represents:

- The scanned project as an application component
- Crypto dependencies as `library` components
- Algorithms as deduplicated `cryptographic-asset` components
- `cryptoProperties.algorithmProperties` for primitive, functions, execution environment, implementation platform, and NIST quantum security level
- `dependencies[]` links from project to packages and packages to algorithms
- CBOM risk and summary values under `cbom:` properties

The Markdown report includes separate tables for cryptographic library components and cryptographic assets, including parent packages. The CycloneDX JSON report is intended for automation, artifact storage, and integration with SBOM/CBOM tooling.

## 🎨 Debricked Integration Vision

A future Debricked integration could combine dependency vulnerability findings with the CBOM's cryptographic context.

Potential flow:

1. Debricked or another SCA platform provides package and CVE findings.
2. `cbom-builder` provides cryptographic package, algorithm, risk, and quantum exposure data.
3. A correlation service joins records using package URLs, package names, versions, and dependency graph references.
4. A prioritization view ranks findings using both vulnerability evidence and cryptographic impact.
5. The result is exported to dashboards, tickets, CI checks, or a consolidated CycloneDX artifact.

The current repository does not call Debricked APIs. Live mode does transmit package names and versions to Groq and NVD, so it should be used only where that external data flow is acceptable.

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

- Live classification evidence and optional custom database support
- Explicit algorithm-level metadata
- Traceable package-to-algorithm relationships
- CycloneDX 1.6 interoperability
- Repeatable output suitable for CI artifacts
- Offline operation is available only when a custom database is supplied; `--live` intentionally calls npm, Groq, and NVD
- Custom database support for organization-specific packages
- Risk and quantum-vulnerability properties that can be reviewed or governed

Important limitations:

- Live classifications depend on package names, model responses, API availability, and response validation.
- Package capability is reported; actual runtime use is not proven.
- Live mode resolves a bounded transitive graph; non-live mode analyzes declared dependencies only.
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

Lockfiles are not read. Live mode resolves up to three npm registry dependency levels, but installed lockfile versions and complete reachability are not established.

### Does a listed algorithm mean the application uses it?

No. A listed algorithm means a live classifier or custom database attributes that capability to the package. Runtime or call-site usage is not established.

### Can the package database be customized?

Yes. Pass a compatible database file with `--db <path>`. The database must contain `version`, `updated`, `algorithms`, and `packages` fields.

### Can development dependencies be excluded?

Yes. Use `--no-dev`.

### Where does the CBOM summary appear in CycloneDX?

CycloneDX summary metrics are stored as `cbom:summary:*` properties under `metadata.properties`. Component-level risk is stored under `cbom:*` properties.

## 📚 References

### Project references

- Project README
- Optional custom database format
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

`cbom-builder` establishes a live-enrichment cryptographic inventory layer for a broader CVE prioritization system. Its CBOM generation is testable and compatible with CycloneDX 1.6, while live results depend on external APIs and require review.

The project identifies cryptographic dependencies and algorithms from declared and, in live mode, bounded transitive npm dependencies. Next steps include lockfile-aware resolution, source-code usage detection, certificate and key-material discovery, stronger advisory correlation, and explainable prioritization that combines CBOM evidence with CVE intelligence.
