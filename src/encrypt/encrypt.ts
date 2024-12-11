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
      iv,
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
      Buffer.from(iv, "hex"),
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
