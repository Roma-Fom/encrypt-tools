import {
  generateSecretKey,
  generateNanoKey,
  generateRSAKeyPair,
} from "../encrypt";

describe("Generators Tests", () => {
  describe("Key Generation", () => {
    it("should generate a valid secret key", () => {
      const secretKey = generateSecretKey();
      expect(secretKey).toBeDefined();
      expect(secretKey.length).toBe(64); // 32 bytes in hex
    });

    it("should generate a valid Nano ID", () => {
      const nanoKey = generateNanoKey("prefix", 10);
      expect(nanoKey).toMatch(/^prefix_/);
      expect(nanoKey.length).toBeGreaterThan(10); // Includes prefix
    });

    it("should generate a valid RSA key pair", () => {
      const { privateKey, publicKey } = generateRSAKeyPair();
      expect(privateKey).toContain("BEGIN PRIVATE KEY");
      expect(publicKey).toContain("BEGIN PUBLIC KEY");
    });
  });
});
