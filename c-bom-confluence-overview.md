# CBOM Builder Overview

`cbom-builder` creates a Cryptography Bill of Materials (CBOM) for Node.js projects. It identifies dependencies with cryptographic capabilities, records their algorithms and risk indicators, and produces both a CycloneDX 1.6 document and a human-readable Markdown report.

## Purpose

The project answers these questions:

- Which declared and, in live mode, bounded transitive dependencies provide cryptographic capabilities?
- Which algorithms and cryptographic primitives do those dependencies expose?
- Which dependencies are deprecated or expose high- and critical-risk algorithms?
- Which public-key, signature, and key-agreement algorithms require post-quantum migration planning?

The CBOM is a cryptographic capability inventory. It is not a runtime usage scanner: a listed algorithm is attributed to a package, not proven to be called by the application.

## Inputs and Analysis

The standard scan reads a `package.json` and evaluates `dependencies` and `devDependencies`. `--no-dev` limits the scan to production dependencies.

Two data sources are available:

- `--db <path>` loads an organization-maintained database of packages, algorithms, risks, deprecation status, descriptions, OIDs, and NIST post-quantum security levels.
- `--live` resolves a bounded transitive dependency graph from npm and uses Groq to classify cryptographic package capabilities. It requires `GROQ_API_KEY` and should be reviewed before policy decisions.

The analyzer calculates each component's risk from its package baseline and the maximum risk of its known algorithms. It also records quantum vulnerability indicators and maps algorithms to CycloneDX primitives.

## Outputs

The default command writes:

| File | Purpose |
| --- | --- |
| `cbom.cdx.json` | CycloneDX 1.6 CBOM with library components, cryptographic assets, package URLs, and a dependency graph. |
| `cbom.md` | A concise assessment for engineering and security review. |

The Markdown report contains:

- A summary of dependency counts, risk breakdown, high-risk algorithms, quantum-vulnerable algorithms, and crypto health.
- A cryptographic-component table with parent packages, resolved and declared versions, scope, description, and next action.
- A cryptographic-asset table with primitive, risk, NIST post-quantum security level, OID, description, and next action.
- Notes for packages that are deprecated or have source descriptions.

## Remediation Guidance

Actions in `cbom.md` are ordered by immediate cryptographic impact:

1. Replace deprecated dependencies.
2. Replace or disable high- and critical-risk algorithms.
3. Assess post-quantum migration only for quantum-vulnerable public-key, signature, and key-agreement primitives.
4. Validate unexpected quantum-vulnerability classifications before acting on them.

This prevents weak hashes, legacy ciphers, and non-cryptographic PRNGs from receiving a misleading post-quantum migration recommendation.

## Crypto Health

The CBOM summary provides a deterministic `0-100` crypto-health score. It starts at `100` and deducts `30` for each deprecated dependency, `25` for each high- or critical-risk production component, `10` for each equivalent development component, `5` for each medium-risk component, `10` for each post-quantum migration candidate, and `5` for each quantum finding that requires validation. The score is clamped to `0`.

Status is assigned in order of urgency:

1. `at-risk`: deprecated dependency or high-risk production component.
2. `migration-needed`: post-quantum migration candidate without an immediate at-risk finding.
3. `needs-attention`: medium risk, high-risk development dependency, or quantum classification to validate.
4. `healthy`: no deductions.

The score describes cryptographic posture only. It does not assess general application quality, runtime reachability, secrets handling, or operational resilience.

## CLI Examples

```bash
cbom scan .
cbom scan . --format cyclonedx --fail-on high
cbom scan . --no-dev
cbom scan . --db ./custom-crypto-db.json
cbom scan . --live
```

`--fail-on` exits with code `1` when the highest component risk meets the configured level: `low`, `medium`, `high`, or `critical`.

## Current Boundaries

- Non-live scans inspect declared dependencies only.
- Live scans resolve up to three levels of transitive dependencies and do not read installed lockfiles.
- Version values are best-effort values from declared ranges unless supplied by live resolution.
- Classification identifies package capabilities, not runtime code paths, key material, certificates, or configuration.
- The repository deliberately focuses on CBOM information and cryptographic risk, rather than vulnerability intelligence.

## Roadmap

1. Read lockfiles for installed, reproducible dependency versions.
2. Detect cryptographic APIs and algorithms in application source code.
3. Inventory certificates and key material.
4. Add organization-specific policy controls for deprecated packages, production scope, and unreviewed classifications.
