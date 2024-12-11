import { createSign, createHmac, createVerify } from "crypto";
import { EncryptError } from "./encrypt-error";
import {
  SignAsymmetric,
  SignSymmetric,
  VerifyAsymmetric,
  VerifySymmetric,
  Sign,
  Verify,
} from "./types";

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
