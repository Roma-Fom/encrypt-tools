import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "crypto";
import { EncryptError } from "./encrypt-error";

export function hash(
  input: string,
  algorithm: "sha256" | "sha512" = "sha256",
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
  iv = randomBytes(12),
}: {
  plaintext: string;
  secretKey: string;
  iv?: Buffer;
}): { ciphertext: string; iv: string } {
  try {
    const cipher = createCipheriv(
      "aes-256-gcm",
      Buffer.from(secretKey, "hex"),
      iv,
    );
    const encrypted = Buffer.concat([
      cipher.update(plaintext, "utf8"),
      cipher.final(),
      cipher.getAuthTag(),
    ]);
    return {
      ciphertext: encrypted.toString("hex"),
      iv: iv.toString("hex"),
    };
  } catch (e: any) {
    console.log(e);
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
    const buf = Buffer.from(ciphertext, "hex");
    const decipher = createDecipheriv(
      "aes-256-gcm",
      Buffer.from(secretKey, "hex"),
      Buffer.from(iv, "hex"),
    );

    const authTag = buf.subarray(buf.length - 16);
    const encryptedData = buf.subarray(0, buf.length - 16);

    decipher.setAuthTag(authTag);
    return Buffer.concat([
      decipher.update(encryptedData),
      decipher.final(),
    ]).toString("utf8");
  } catch (e: any) {
    throw new EncryptError(e.message, "Decryption failed", "DECRYPT_ERROR");
  }
}
