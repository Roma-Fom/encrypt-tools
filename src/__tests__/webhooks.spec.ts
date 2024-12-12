import { generateSecretKey, signWebhook, verifyWebhook } from "../encrypt";

describe("Webhooks Tests", () => {
  describe("Webhook Signing", () => {
    const secret = generateSecretKey();
    const testData = {
      id: "123456789",
      name: "John",
      lastName: "Doe",
      city: "Tel Aviv",
    };

    it("should sign and verify a string payload", () => {
      const result = signWebhook("Test string payload", {
        secret: secret,
      });
      expect(result.payload).toHaveProperty("id");
      expect(result.payload).toHaveProperty("timestamp");
      expect(result.payload).toHaveProperty("data", "Test string payload");
      expect(typeof result.signature).toBe("string");

      const verified = verifyWebhook({
        payload: result.payload,
        secret,
        signature: result.signature,
      });
      expect(verified).toBe(true);
    });

    it("should sign and verify an object payload", () => {
      const result = signWebhook(testData, {
        secret: secret,
        extraParams: { type: "test.object.event" },
      });

      expect(result.payload).toHaveProperty("id");
      expect(result.payload).toHaveProperty("type", "test.object.event");
      expect(result.payload).toHaveProperty("timestamp");
      expect(result.payload).toHaveProperty("data", testData);
      expect(typeof result.signature).toBe("string");

      const verified = verifyWebhook({
        payload: result.payload,
        secret,
        signature: result.signature,
      });
      expect(verified).toBe(true);
    });
  });
});
