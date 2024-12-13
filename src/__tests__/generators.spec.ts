import {
  generateSecretKey,
  generateNanoKey,
  generateRSAKeyPair,
  EncryptError,
} from "../encrypt";

describe("Generator Tests", () => {
  describe("Secret Key Generation", () => {
    it("should generate key of correct length", () => {
      const key16 = generateSecretKey(16);
      const key32 = generateSecretKey(32);

      expect(Buffer.from(key16, "hex").length).toBe(16);
      expect(Buffer.from(key32, "hex").length).toBe(32);
    });

    it("should generate different keys each time", () => {
      const key1 = generateSecretKey();
      const key2 = generateSecretKey();
      expect(key1).not.toBe(key2);
    });
  });

  describe("RSA Key Pair Generation", () => {
    it("should generate valid RSA key pair", () => {
      const { privateKey, publicKey } = generateRSAKeyPair();

      expect(privateKey).toContain("BEGIN PRIVATE KEY");
      expect(privateKey).toContain("END PRIVATE KEY");
      expect(publicKey).toContain("BEGIN PUBLIC KEY");
      expect(publicKey).toContain("END PUBLIC KEY");
    });

    it("should generate unique key pairs", () => {
      const pair1 = generateRSAKeyPair();
      const pair2 = generateRSAKeyPair();

      expect(pair1.privateKey).not.toBe(pair2.privateKey);
      expect(pair1.publicKey).not.toBe(pair2.publicKey);
    });
  });

  describe("Nano Key Generation", () => {
    it("should generate key with prefix", () => {
      const key = generateNanoKey("test", 10);
      expect(key).toMatch(/^test_/);
      expect(key.length).toBeGreaterThan(5);
    });

    it("should generate key without prefix", () => {
      const key = generateNanoKey();
      expect(key).toBeDefined();
      expect(typeof key).toBe("string");
    });

    it("should generate unique keys", () => {
      const key1 = generateNanoKey("test");
      const key2 = generateNanoKey("test");
      expect(key1).not.toBe(key2);
    });
  });

  describe("Input Validation", () => {
    it("should handle invalid key sizes for generateSecretKey", () => {
      expect(() => generateSecretKey(15 as any)).toThrow(EncryptError);
      expect(() => generateSecretKey(33 as any)).toThrow(EncryptError);
    });

    it("should handle empty prefix in generateNanoKey", () => {
      const key = generateNanoKey("");
      expect(key).toBeDefined();
      expect(key.length).toBeGreaterThan(0);
    });

    it("should validate nano key size constraints", () => {
      const key = generateNanoKey("test", 5);
      expect(key.length).toBeGreaterThan(5); // prefix + underscore + 5 chars
      expect(key).toMatch(/^test_[A-Za-z0-9]{5,}$/);
    });
  });

  describe("RSA Key Pair Generation Error Handling", () => {
    it("should handle RSA key generation errors", () => {
      // Mock crypto.generateKeyPairSync to throw an error
      const originalGenerateKeyPair = require("crypto").generateKeyPairSync;
      require("crypto").generateKeyPairSync = () => {
        throw new Error("Mocked RSA generation error");
      };

      expect(() => generateRSAKeyPair()).toThrow(EncryptError);

      // Restore original function
      require("crypto").generateKeyPairSync = originalGenerateKeyPair;
    });
  });
});
