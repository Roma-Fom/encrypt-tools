export const EncryptErrorType = {
  ENCRYPT_ERROR: "ENCRYPT_ERROR",
  DECRYPT_ERROR: "DECRYPT_ERROR",
  HASH_ERROR: "HASH_ERROR",
  KEYPAIR_ERROR: "KEYPAIR_ERROR",
  SIGN_ASYMMETRIC_ERROR: "SIGN_ASYMMETRIC_ERROR",
  SIGN_SYMMETRIC_ERROR: "SIGN_SYMMETRIC_ERROR",
  INVALID_SECRET: "INVALID_SECRET",
} as const;
export type EncryptErrorType =
  (typeof EncryptErrorType)[keyof typeof EncryptErrorType];

export class EncryptError extends Error {
  private readonly code: EncryptErrorType;
  private readonly reason: string = "";

  constructor(message: string, reason: string, code: EncryptErrorType) {
    super(message);
    this.code = code;
    this.reason = reason;
  }
}
