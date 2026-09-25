# sample-node-app

A deliberately mixed-quality Node.js app used to exercise cbom-builder.

It depends on modern primitives (`bcrypt`, `argon2`) alongside legacy ones
(`crypto-js`, `md5`, `node-rsa`, `seedrandom`) so the generated CBOM contains
high-risk and quantum-vulnerable findings.

Generate the CBOM:

```bash
npm run build
node dist/cli/bin.js scan examples/sample-node-app
```

This writes `cbom.cdx.json` and `cbom.md` next to the sample `package.json`.

The Markdown report distinguishes declared package ranges from resolved versions, includes remediation guidance, and summarizes crypto health on a `0-100` scale. High- and critical-risk algorithms should be reviewed first; a post-quantum action applies only to vulnerable asymmetric primitives.
