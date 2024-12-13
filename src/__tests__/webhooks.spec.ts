import { generateSecretKey, signWebhook, verifyWebhook } from "../encrypt";

describe("Webhooks Tests", () => {
  const secret = generateSecretKey();
  const testData = {
    event: "user.created",
    userId: "123",
    details: {
      name: "John Doe",
      email: "john@example.com",
    },
  };

  describe("Webhook Signing", () => {
    it("should generate valid webhook signature with basic payload", () => {
      const result = signWebhook(testData, { secret });

      expect(result).toHaveProperty("payload");
      expect(result).toHaveProperty("signature");
      expect(result).toHaveProperty("raw");
      expect(result.payload).toHaveProperty("id");
      expect(result.payload).toHaveProperty("timestamp");
      expect(result.payload).toHaveProperty("data", testData);
    });

    it("should include extra parameters in payload", () => {
      const extraParams = { type: "USER_EVENT", version: "1.0" };
      const result = signWebhook(testData, {
        secret,
        extraParams,
      });

      expect(result.payload).toHaveProperty("type", "USER_EVENT");
      expect(result.payload).toHaveProperty("version", "1.0");
    });

    it("should use custom ID if provided", () => {
      const customId = "custom_123";
      const result = signWebhook(testData, {
        secret,
        id: customId,
      });

      expect(result.payload.id).toBe(customId);
    });

    it("should throw error if secret is missing", () => {
      expect(() =>
        signWebhook(testData, {
          secret: "",
        })
      ).toThrow("Secret is required");
    });
  });

  describe("Webhook Verification", () => {
    it("should verify valid webhook signature", () => {
      const { payload, signature } = signWebhook(testData, { secret });

      const isValid = verifyWebhook({
        payload,
        secret,
        signature,
      });

      expect(isValid).toBe(true);
    });

    it("should reject tampered payload", () => {
      const { payload, signature } = signWebhook(testData, { secret });
      const tamperedPayload = {
        ...payload,
        data: { ...testData, userId: "456" },
      };

      const isValid = verifyWebhook({
        payload: tamperedPayload,
        secret,
        signature,
      });

      expect(isValid).toBe(false);
    });

    it("should reject invalid signature", () => {
      const { payload } = signWebhook(testData, { secret });

      const isValid = verifyWebhook({
        payload,
        secret,
        signature: "invalid_signature",
      });

      expect(isValid).toBe(false);
    });
  });

  describe("Input Validation", () => {
    const secret = generateSecretKey();

    it("should handle null values in payload data", () => {
      const testData = {
        event: "test.event",
        value: null,
      };

      const result = signWebhook(testData, { secret });
      expect(result.payload.data).toEqual(testData);
    });

    it("should handle undefined optional parameters", () => {
      const result = signWebhook("test", {
        secret,
        id: undefined,
        extraParams: undefined,
      });

      expect(result.payload).toHaveProperty("id");
      expect(typeof result.payload.id).toBe("string");
    });

    it("should validate timestamp is current", () => {
      const result = signWebhook("test", { secret });
      const now = Date.now();
      expect(result.payload.timestamp).toBeLessThanOrEqual(now);
      expect(result.payload.timestamp).toBeGreaterThan(now - 1000);
    });
  });
});
