import type { CryptoDatabase } from '../../src/types';

export const TEST_DATABASE: CryptoDatabase = {
  version: 'test',
  updated: '2026-01-01',
  algorithms: {
    bcrypt: { type: 'password-hash', risk: 'low', quantumVulnerable: false },
    Argon2: { type: 'password-hash', risk: 'low', quantumVulnerable: false },
    MD5: { type: 'hash', risk: 'critical', quantumVulnerable: false },
    'SHA-256': { type: 'hash', risk: 'low', quantumVulnerable: false, nistQuantumSecurityLevel: 2 },
    'ML-KEM': { type: 'post-quantum-kem', risk: 'low', quantumVulnerable: false, primitive: 'kem', nistQuantumSecurityLevel: 3 },
    RC4: { type: 'symmetric', risk: 'critical', quantumVulnerable: false, primitive: 'stream-cipher' },
    RSA: { type: 'public-key', risk: 'medium', quantumVulnerable: true, oid: '1.2.840.113549.1.1.1' },
    'RSA-OAEP': { type: 'public-key', risk: 'medium', quantumVulnerable: true },
    'RSA-PKCS1v1_5': { type: 'public-key', risk: 'high', quantumVulnerable: true },
    'AES-GCM': { type: 'aead', risk: 'low', quantumVulnerable: false },
    ECDSA: { type: 'signature', risk: 'medium', quantumVulnerable: true },
    ECDH: { type: 'key-exchange', risk: 'medium', quantumVulnerable: true },
    Ed25519: { type: 'signature', risk: 'low', quantumVulnerable: true },
    secp256k1: { type: 'signature', risk: 'medium', quantumVulnerable: true },
    JWT: { type: 'token', risk: 'medium', quantumVulnerable: false },
    HMAC: { type: 'mac', risk: 'low', quantumVulnerable: false },
  },
  packages: [
    { name: 'bcrypt', aliases: ['bcryptjs'], category: 'password-hashing', algorithms: ['bcrypt'], risk: 'low' },
    { name: 'argon2', category: 'password-hashing', algorithms: ['Argon2'], risk: 'low' },
    { name: 'crypto-js', category: 'general-purpose', algorithms: ['MD5', 'SHA-256'], risk: 'high', deprecated: true },
    { name: 'md5', category: 'hashing', algorithms: ['MD5'], risk: 'critical', deprecated: true },
    { name: 'node-rsa', category: 'public-key', algorithms: ['RSA', 'RSA-OAEP', 'RSA-PKCS1v1_5', 'SHA-256'], risk: 'high' },
    { name: '@noble/curves', category: 'public-key', algorithms: ['ECDSA', 'ECDH', 'Ed25519', 'secp256k1'], risk: 'low' },
    { name: 'jsonwebtoken', category: 'token', algorithms: ['JWT', 'HMAC'], risk: 'medium' },
  ],
};
