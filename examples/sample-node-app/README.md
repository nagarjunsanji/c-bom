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

This writes `cbom.json` and `cbom.md` next to the sample `package.json`.
