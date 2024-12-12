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
  } as U extends object
    ? { id: string; timestamp: number; data: T } & U
    : { id: string; timestamp: number; data: T };

  const serializedData = JSON.stringify(payload);

  const signature = sign({
    data: serializedData,
    secret,
    algorithm: "sha256",
  });

  return { payload, signature, raw: serializedData };
}

export function verifyWebhook({
  payload,
  secret,
  signature,
}: {
  payload: object;
  secret: string;
  signature: string;
}) {
  return verify({
    data: JSON.stringify(payload),
    secret,
    algorithm: "sha256",
    signature,
  });
}
