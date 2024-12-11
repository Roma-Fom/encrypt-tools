import {
  hash,
  encrypt,
  decrypt,
  generateSecretKey,
  generateNanoKey,
  generateRSAKeyPair,
  sign,
  verify,
  EncryptError,
} from "../encrypt";

describe("Crypto Library Tests", () => {
  describe("Hash Function", () => {
    it("should generate a valid hash for input", () => {
      const input = "test data";
      const result = hash(input);
      expect(result).toBeDefined();
      expect(typeof result).toBe("string");
    });

    it("should throw an EncryptError for invalid algorithm", () => {
      expect(() => hash("test data", "invalid" as any)).toThrow(EncryptError);
    });
  });

  describe("Encryption and Decryption", () => {
    const secretKey = generateSecretKey();
    const plaintext = "Sensitive information";

    it("should encrypt and decrypt data correctly", () => {
      const { ciphertext, iv } = encrypt({ plaintext, secretKey });
      const decryptedText = decrypt({ ciphertext, secretKey, iv });
      expect(decryptedText).toBe(plaintext);
    });

    it("should throw an EncryptError for invalid decryption", () => {
      const { ciphertext } = encrypt({ plaintext, secretKey });
      expect(() =>
        decrypt({ ciphertext, secretKey, iv: "invalid_iv" })
      ).toThrow(EncryptError);
    });
  });

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

  describe("Symmetric Signing and Verification", () => {
    const secretKey = generateSecretKey();
    const data = {
      name: "John",
      lastName: "Doe",
      city: "Tel Aviv",
      id: "123456789",
    };

    it("should sign and verify data symmetrically", () => {
      const signature = sign({
        data: JSON.stringify(data),
        secret: secretKey,
        algorithm: "sha256",
      });

      const isValid = verify({
        data: JSON.stringify(data),
        secret: secretKey,
        signature,
        algorithm: "sha256",
      });
      expect(isValid).toBe(true);
    });

    it("should fail verification for tampered data", () => {
      const signature = sign({
        data: JSON.stringify(data),
        secret: secretKey,
        algorithm: "sha256",
      });

      const isValid = verify({
        data: JSON.stringify({ ...data, id: "987654321" }),
        secret: secretKey,
        signature,
        algorithm: "sha256",
      });
      expect(isValid).toBe(false);
    });
  });

  describe("Asymmetric Signing and Verification", () => {
    const { privateKey, publicKey } = generateRSAKeyPair();
    const data = "Sensitive information";

    it("should sign and verify data asymmetrically", () => {
      const signature = sign({ data, privateKey });
      const isValid = verify({ data, publicKey, signature });
      expect(isValid).toBe(true);
    });

    it("should fail verification with an invalid signature", () => {
      const signature = "invalid_signature";
      const isValid = verify({ data, publicKey, signature });
      expect(isValid).toBe(false);
    });
  });

  describe("Error Handling", () => {
    it("should handle invalid public key for asymmetric verification", () => {
      const { privateKey } = generateRSAKeyPair();
      const signature = sign({ data: "data", privateKey });
      const isValid = verify({
        data: "data",
        publicKey: "invalid_key",
        signature,
      });
      expect(isValid).toBe(false);
    });
  });
});
