import { randomUUID } from "crypto";
import { sign, verify } from "./sign";
import { EncryptError } from "./encrypt-error";

export function signWebhook<
  T extends string | object,
  U extends object | undefined,
>(
  data: T,
  options: { id?: string; secret: string; extraParams?: U }
): {
  payload: U extends object
    ? { id: string; timestamp: number; data: T } & U
    : { id: string; timestamp: number; data: T };
  signature: string;
  raw: string;
} {
  const { id, secret, extraParams } = options;
  if (!secret)
    throw new EncryptError(
      "Secret is required",
      "Invalid secret",
      "INVALID_SECRET"
    );

  const payload = {
    id: id || randomUUID(),
    timestamp: Date.now(),
    ...(extraParams || {}),
    data,
  } as any;

  const serializedData = JSON.stringify(payload);
  const signatureBase = `${payload.timestamp}.${serializedData}`;
  const signature = sign({
    data: signatureBase,
    secret,
    algorithm: "sha256",
  });

  return {
    payload,
    signature: `v1.${signature}`,
    raw: serializedData,
  };
}

export function verifyWebhook({
  payload,
  secret,
  signature,
}: {
  payload: object & { timestamp: number };
  secret: string;
  signature: string;
}) {
  if (!signature.startsWith("v1.")) {
    return false;
  }
  const actualSignature = signature.slice(3);
  const signatureBase = `${payload.timestamp}.${JSON.stringify(payload)}`;

  return verify({
    data: signatureBase,
    secret,
    algorithm: "sha256",
    signature: actualSignature,
  });
}
