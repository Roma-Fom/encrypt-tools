import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createSign,
  createVerify,
  generateKeyPairSync,
  randomBytes,
} from "crypto";
import { EncryptError } from "./encrypt-error";
import {
  Sign,
  SignAsymmetric,
  SignSymmetric,
  Verify,
  VerifyAsymmetric,
  VerifySymmetric,
} from "./types";
import { nanoid } from "nanoid";

export function id(prefix?: string, size?: number) {
  return prefix ? `${prefix}_${nanoid(size)}` : nanoid();
}

export function hash(
  input: string,
  algorithm: "sha256" | "sha512" = "sha256"
): string {
  try {
    const hash = createHash(algorithm);
    hash.update(input);
    return hash.digest("hex");
  } catch (e: any) {
    throw new EncryptError(e.message, "Hash failed", "HASH_ERROR");
  }
}

export function encrypt({
  plaintext,
  secretKey,
  iv = randomBytes(16),
}: {
  plaintext: string;
  secretKey: string;
  iv?: Buffer;
}): { ciphertext: string; iv: string } {
  try {
    const cipher = createCipheriv(
      "aes-256-cbc",
      Buffer.from(secretKey, "hex"),
      iv
    );
    const encrypted = Buffer.concat([
      cipher.update(plaintext, "utf8"),
      cipher.final(),
    ]);
    return {
      ciphertext: encrypted.toString("hex"),
      iv: iv.toString("hex"),
    };
  } catch (e: any) {
    throw new EncryptError(e.message, "Encryption failed", "ENCRYPT_ERROR");
  }
}

export function decrypt({
  ciphertext,
  secretKey,
  iv,
}: {
  ciphertext: string;
  secretKey: string;
  iv: string;
}): string {
  try {
    const decipher = createDecipheriv(
      "aes-256-cbc",
      Buffer.from(secretKey, "hex"),
      Buffer.from(iv, "hex")
    );
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(ciphertext, "hex")),
      decipher.final(),
    ]);
    return decrypted.toString("utf8");
  } catch (e: any) {
    throw new EncryptError(e.message, "Decryption failed", "DECRYPT_ERROR");
  }
}

export function generateSecretKey(length: 16 | 32 = 32): string {
  return randomBytes(length).toString("hex");
}

export function generateNanoKey(prefix?: string, size?: number): string {
  return id(prefix, size);
}

export function generateRSAKeyPair(): {
  privateKey: string;
  publicKey: string;
} {
  try {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048, // Key size in bits
      publicKeyEncoding: {
        type: "spki",
        format: "pem",
      },
      privateKeyEncoding: {
        type: "pkcs8",
        format: "pem",
      },
    });

    return { privateKey, publicKey };
  } catch (e: any) {
    throw new EncryptError(
      e.message,
      "Key pair generation failed",
      "KEYPAIR_ERROR"
    );
  }
}

function signAsymmetric({ data, privateKey }: SignAsymmetric): string {
  try {
    const sign = createSign("sha256");
    sign.update(data);
    sign.end();
    return sign.sign(privateKey, "base64");
  } catch (e: any) {
    throw new EncryptError(
      e.message,
      "Signing failed",
      "SIGN_ASYMMETRIC_ERROR"
    );
  }
}

function signSymmetric({
  data,
  secret,
  algorithm = "sha256",
}: SignSymmetric): string {
  try {
    const hmac = createHmac(algorithm, secret);
    hmac.update(data);
    return hmac.digest("hex");
  } catch (e: any) {
    throw new EncryptError(
      e.message,
      "Symmetric signing failed",
      "SIGN_SYMMETRIC_ERROR"
    );
  }
}

function verifyAsymmetricSignature({
  data,
  signature,
  publicKey,
}: VerifyAsymmetric): boolean {
  try {
    const verify = createVerify("sha256");
    verify.update(data);
    verify.end();
    return verify.verify(publicKey, signature, "base64");
  } catch (e) {
    return false;
  }
}

function verifySymmetric({
  data,
  secret,
  algorithm,
  signature,
}: VerifySymmetric): boolean {
  try {
    const computedSignature = signSymmetric({
      data,
      secret,
      algorithm,
    });
    return computedSignature === signature;
  } catch (e) {
    return false;
  }
}

export function sign({ data, privateKey, secret, algorithm }: Sign): string {
  if (privateKey) {
    return signAsymmetric({
      data,
      privateKey,
    });
  }
  return signSymmetric({ data, secret: secret!, algorithm: algorithm! });
}

export function verify({
  data,
  secret,
  signature,
  publicKey,
  algorithm,
}: Verify) {
  if (publicKey) {
    return verifyAsymmetricSignature({ data, signature, publicKey });
  } else if (secret) {
    return verifySymmetric({ data, secret, algorithm, signature });
  }
}
