import { sign, verify } from "./sign";
import { EncryptError } from "./encrypt-error";
import { generateSecretKey, id } from "./generators";

export function createV1SignatureBase(
  id: string,
  timestamp: number,
  payload: string,
): `${string}.${number}.${string}` {
  return `${id}.${timestamp}.${payload}`;
}

export function signWebhook(
  secret: string,
  params: {
    msgId?: string;
    payload: object;
  },
) {
  if (!secret)
    throw new EncryptError(
      "Secret is required",
      "Invalid secret",
      "INVALID_SECRET",
    );
  const secretString = secret.split("_")[1];
  if (!secretString) {
    throw new EncryptError(
      "Invalid secret",
      "Invalid secret",
      "INVALID_SECRET",
    );
  }
  const msgId = params.msgId ?? id("msg", 27);
  const timestamp = Date.now();
  const serializedData = JSON.stringify(params.payload);
  const signature = sign({
    data: createV1SignatureBase(msgId, timestamp, serializedData),
    secret: secretString,
    algorithm: "sha256",
  });
  return {
    msgId,
    timestamp,
    signature: `v1,${signature}`,
    raw: serializedData,
  };
}

export function verifyWebhook(
  payload: object,
  {
    msgId,
    timestamp,
    secret,
    signature,
  }: {
    msgId: string;
    timestamp: number;
    secret: string;
    signature: string;
  },
) {
  if (!signature.startsWith("v1,") || !secret) {
    return false;
  }
  const secretString = secret.split("_")[1];
  const actualSignature = signature.slice(3);

  return verify({
    data: createV1SignatureBase(msgId, timestamp, JSON.stringify(payload)),
    secret: secretString,
    algorithm: "sha256",
    signature: actualSignature,
  });
}

export function generateWebhookSecret() {
  return `whsec_${generateSecretKey(16)}`;
}
