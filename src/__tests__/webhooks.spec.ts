import {
  EventData,
  generateWebhookSecret,
  signWebhook,
  verifyWebhook,
} from "../encrypt";

describe("Webhooks Tests", () => {
  let secret = generateWebhookSecret();
  const testData = {
    userId: "123",
    name: "John Doe",
    email: "john@example.com",
  };
  const event: EventData = {
    id: "evt_29w8B1J7CwVlJXylYLxcslromF1",
    timestamp: 1654012591835,
    type: "user.created",
    data: testData,
  };

  it("should test", () => {
    const sig = signWebhook(secret, event);
    console.log(sig);
    const verified = verifyWebhook(event, sig.timestamp, sig.signature, secret);
    console.log("Verified: ", verified);
  });

  // describe("Generate webhook secret", () => {
  //   it("should generate a valid secret key", () => {
  //     secret = generateWebhookSecret();
  //     console.log(secret);
  //     expect(secret).toMatch(/^whsec_[a-zA-Z0-9]{32}$/);
  //   });
  // });
  //
  // describe("Sign Webhooks", () => {
  //   secret = generateWebhookSecret();
  //   const testData = {
  //     eventId: "evt_29w8B1J7CwVlJXylYLxcslromF1",
  //     eventType: "user.created",
  //     payload: {
  //       amount: 1000,
  //       currency: "usd",
  //       country: "us",
  //     },
  //   };
  //
  //   it("should generate a valid signature with provided payload", () => {
  //     const result = signWebhook(secret, {
  //       eventId: "evt_29w8B1J7CwVlJXylYLxcslromF1",
  //       eventType: "user.created",
  //       payload: testData.payload,
  //     });
  //     console.log(result);
  //     expect(result).toHaveProperty("msgId");
  //     expect(result).toHaveProperty("timestamp");
  //     expect(result).toHaveProperty("signature");
  //     expect(result).toHaveProperty("raw");
  //     expect(result.raw).toBe(JSON.stringify(payload));
  //   });
  //
  //   it("should throw an EncryptError if secret is missing", () => {
  //     expect(() => signWebhook("", { payload })).toThrow(EncryptError);
  //   });
  //
  //   it("should use provided msgId if available", () => {
  //     const msgId = "custom_msg_id";
  //     const result = signWebhook(secret, { msgId, payload });
  //     expect(result.msgId).toBe(msgId);
  //   });
  //
  //   it("should generate a new msgId if not provided", () => {
  //     const result = signWebhook(secret, { payload });
  //     const msgId = result.msgId.split("msg_")[1];
  //     expect(msgId.length).toEqual(27);
  //   });
  //
  //   it("should handle complex payloads correctly", () => {
  //     const complexPayload = { key: "value", nested: { key: "nestedValue" } };
  //     const result = signWebhook(secret, { payload: complexPayload });
  //     expect(result.raw).toBe(JSON.stringify(complexPayload));
  //   });
  // });
  //
  // describe("Webhook Verification", () => {
  //   secret = generateWebhookSecret();
  //   it("should verify valid webhook signature", () => {
  //     const { msgId, raw, signature, timestamp } = signWebhook(secret, {
  //       payload: testData,
  //     });
  //
  //     const isValid = verifyWebhook(JSON.parse(raw), {
  //       msgId,
  //       secret,
  //       signature,
  //       timestamp,
  //     });
  //
  //     expect(isValid).toBe(true);
  //   });
  //
  //   it("should reject tampered payload", () => {
  //     const { msgId, raw, signature, timestamp } = signWebhook(secret, {
  //       payload: testData,
  //     });
  //     const tamperedPayload = {
  //       ...JSON.parse(raw),
  //       data: { ...testData, userId: "456" },
  //     };
  //
  //     const isValid = verifyWebhook(tamperedPayload, {
  //       msgId,
  //       secret,
  //       signature,
  //       timestamp,
  //     });
  //
  //     expect(isValid).toBe(false);
  //   });
  //
  //   it("should reject invalid signature", () => {
  //     const { msgId, raw, timestamp } = signWebhook(secret, {
  //       payload: testData,
  //     });
  //
  //     const isValid = verifyWebhook(JSON.parse(raw), {
  //       msgId,
  //       secret,
  //       timestamp,
  //       signature: "invalid_signature",
  //     });
  //
  //     expect(isValid).toBe(false);
  //   });
  //
  //   it("should TEST", () => {
  //     const payloadToSign = {
  //       data: {
  //         birthday: "",
  //         created_at: 1654012591514,
  //         email_addresses: [
  //           {
  //             email_address: "example@example.org",
  //             id: "idn_29w83yL7CwVlJXylYLxcslromF1",
  //             linked_to: [],
  //             object: "email_address",
  //             verification: {
  //               status: "verified",
  //               strategy: "ticket",
  //             },
  //           },
  //         ],
  //       },
  //       object: "event",
  //       type: "user.created",
  //     };
  //
  //     const body = {
  //       eventId: "evt_29w8B1J7CwVlJXylYLxcslromF1",
  //       eventType: "user.created",
  //       timestamp: 1654012591835,
  //       data: {},
  //     };
  //
  //     const signature = signWebhook(secret, { payload: payloadToSign });
  //     console.log(signature);
  //   });
  // });
});
