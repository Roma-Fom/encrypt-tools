import { sign, verify } from "./sign";
import { EncryptError } from "./encrypt-error";
import { generateSecretKey } from "./generators";

export type EventData = {
  id: string;
  type: string;
  timestamp: number;
  data: object;
};

export function createV1SignatureBase(
  timestamp: number,
  payload: string,
): `${number}.${string}` {
  return `${timestamp}.${payload}`;
}

export function signWebhook(secret: string, event: EventData) {
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

  const signTimestamp = Date.now();
  const serializedData = JSON.stringify(event);

  const signature = sign({
    data: createV1SignatureBase(signTimestamp, serializedData),
    secret: secretString,
    algorithm: "sha256",
  });
  return {
    timestamp: signTimestamp,
    signature: `v1,${signature}`,
    event: event,
    raw: serializedData,
  };
}

export function verifyWebhook(
  event: EventData,
  timestamp: number,
  signature: string,
  secret: string,
) {
  if (!signature.startsWith("v1,") || !secret) {
    return false;
  }
  const secretString = secret.split("_")[1];
  const actualSignature = signature.slice(3);

  return verify({
    data: createV1SignatureBase(timestamp, JSON.stringify(event)),
    secret: secretString,
    algorithm: "sha256",
    signature: actualSignature,
  });
}

export function generateWebhookSecret() {
  return `whsec_${generateSecretKey(16)}`;
}
