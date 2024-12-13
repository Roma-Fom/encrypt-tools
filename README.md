# Encrypt Tools

A comprehensive TypeScript encryption toolkit providing secure cryptographic operations, signing capabilities, and webhook handling.

## Installation

```bash
npm install encrypt-tools
```

## Features

- 🔐 Symmetric & Asymmetric Encryption
- 📝 Data Signing & Verification
- 🔑 Key Generation Tools
- 🪝 Secure Webhook Handling
- 🔒 Hashing Functions

## Quick Start

### Symmetric Encryption

```typescript
import { encrypt, decrypt, generateSecretKey } from "encrypt-tools";
// Generate a secure key
const secretKey = generateSecretKey(); // 32 bytes by default
// Encrypt data
const { ciphertext, iv } = encrypt({
  plaintext: "sensitive data",
  secretKey,
});
// Decrypt data
const decrypted = decrypt({
  ciphertext,
  secretKey,
  iv,
});
```

### Data Signing

```typescript
import { sign, verify, generateSecretKey } from "encrypt-tools";
// Symmetric Signing
const secretKey = generateSecretKey();
const data = JSON.stringify({ userId: "123", action: "login" });
// Sign data
const signature = sign({
  data,
  secret: secretKey,
  algorithm: "sha256",
});
// Verify signature
const isValid = verify({
  data,
  secret: secretKey,
  signature,
  algorithm: "sha256",
});
```
