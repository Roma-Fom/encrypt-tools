import { generateKeyPairSync, randomBytes } from "crypto";
import { nanoid } from "nanoid";
import { EncryptError } from "./encrypt-error";

export function generateSecretKey(length: 16 | 32 = 32): string {
  if (length !== 16 && length !== 32) {
    throw new EncryptError(
      "Invalid key length",
      "Key length must be 16 or 32",
      "INVALID_KEY_LENGTH",
    );
  }
  return randomBytes(length).toString("hex");
}

export function generateNanoKey(prefix?: string, size?: number): string {
  return id(prefix, size);
}

export function id(prefix?: string, size?: number) {
  return prefix ? `${prefix}_${nanoid(size)}` : nanoid();
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
      "KEYPAIR_ERROR",
    );
  }
}
