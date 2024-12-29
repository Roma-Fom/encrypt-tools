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
console.log(decrypted); // "sensitive data"
```

### Hashing

```typescript
import { hash } from "encrypt-tools";

// Default SHA-256
const hashValue = hash("data to hash");

// Specify algorithm
const sha512Hash = hash("data to hash", "sha512");
```

### Digital Signatures

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

#### Symmetric Signing (HMAC)

```typescript
import { sign, verify, generateSecretKey } from "encrypt-tools";

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

#### Asymmetric Signing (RSA)

```typescript
import { sign, verify, generateRSAKeyPair } from "encrypt-tools";

// Generate key pair
const { privateKey, publicKey } = generateRSAKeyPair();

// Sign data
const signature = sign({
  data: "message to sign",
  privateKey,
});

// Verify signature
const isValid = verify({
  data: "message to sign",
  publicKey,
  signature,
});
```

#### Webhook Handling

```typescript
import {
  generateWebhookSecret,
  signWebhook,
  verifyWebhook,
} from "encrypt-tools";

// Generate webhook secret
const secret = generateWebhookSecret(); // Format: whsec_*

// Create event
const event = {
  id: "evt_123",
  type: "user.created",
  timestamp: Date.now(),
  data: {
    userId: "123",
    email: "user@example.com",
  },
};

// Sign webhook
const { signature, timestamp } = signWebhook(secret, event);

// Verify webhook
const isValid = verifyWebhook(event, timestamp, signature, secret);
```

### Key Generation

```typescript
import { generateSecretKey, generateRSAKeyPair, id } from "encrypt-tools";

// Generate symmetric key
const key16 = generateSecretKey(16); // 16 bytes
const key32 = generateSecretKey(); // 32 bytes (default)

// Generate RSA key pair
const { privateKey, publicKey } = generateRSAKeyPair();

// Generate unique ID with prefix
const uniqueId = id("prefix"); // Format: prefix_*
```

### Error Handling

```typescript
try {
  const result = encrypt({
    plaintext: "data",
    secretKey: "invalid_key",
  });
} catch (error) {
  if (error instanceof EncryptError) {
    console.error(`Error: ${error.message}`);
  }
}
```
