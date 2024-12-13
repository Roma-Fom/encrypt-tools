import {
  hash,
  encrypt,
  decrypt,
  generateSecretKey,
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

    it("should throw an error if secret is missing", () => {
      expect(() =>
        encrypt({
          plaintext: JSON.stringify({ name: "John" }),
          secretKey: "123",
        })
      ).toThrow(EncryptError);
    });
  });
});

describe("Encryption Tests", () => {
  describe("Hash Function", () => {
    it("should generate consistent hash for same input", () => {
      const input = "test data";
      const hash1 = hash(input);
      const hash2 = hash(input);
      expect(hash1).toBe(hash2);
    });

    it("should generate different hashes for different inputs", () => {
      const hash1 = hash("data1");
      const hash2 = hash("data2");
      expect(hash1).not.toBe(hash2);
    });

    it("should support different algorithms", () => {
      const input = "test data";
      const sha256Hash = hash(input, "sha256");
      const sha512Hash = hash(input, "sha512");
      expect(sha256Hash).not.toBe(sha512Hash);
      expect(sha512Hash.length).toBeGreaterThan(sha256Hash.length);
    });
  });

  describe("Encryption and Decryption", () => {
    const secretKey = generateSecretKey();
    const testData = {
      sensitive: "information",
      numbers: [1, 2, 3],
      nested: { key: "value" },
    };

    it("should encrypt and decrypt object data", () => {
      const plaintext = JSON.stringify(testData);
      const { ciphertext, iv } = encrypt({ plaintext, secretKey });
      const decrypted = decrypt({ ciphertext, secretKey, iv });
      expect(JSON.parse(decrypted)).toEqual(testData);
    });

    it("should encrypt and decrypt string data", () => {
      const plaintext = "Hello, World!";
      const { ciphertext, iv } = encrypt({ plaintext, secretKey });
      const decrypted = decrypt({ ciphertext, secretKey, iv });
      expect(decrypted).toBe(plaintext);
    });

    it("should generate different ciphertext for same plaintext", () => {
      const plaintext = "same text";
      const result1 = encrypt({ plaintext, secretKey });
      const result2 = encrypt({ plaintext, secretKey });
      expect(result1.ciphertext).not.toBe(result2.ciphertext);
    });

    it("should throw error for invalid decryption", () => {
      const { ciphertext } = encrypt({
        plaintext: "test",
        secretKey,
      });

      expect(() =>
        decrypt({
          ciphertext,
          secretKey: "invalid_key",
          iv: "invalid_iv",
        })
      ).toThrow(EncryptError);
    });
  });

  describe("Buffer Handling", () => {
    const secretKey = generateSecretKey();

    it("should handle empty string encryption", () => {
      const plaintext = "";
      const { ciphertext, iv } = encrypt({ plaintext, secretKey });
      const decrypted = decrypt({ ciphertext, secretKey, iv });
      expect(decrypted).toBe("");
    });

    it("should handle unicode characters", () => {
      const plaintext = "Hello 世界 🌍";
      const { ciphertext, iv } = encrypt({ plaintext, secretKey });
      const decrypted = decrypt({ ciphertext, secretKey, iv });
      expect(decrypted).toBe(plaintext);
    });

    it("should handle very large payloads", () => {
      const plaintext = "x".repeat(1000000); // 1MB of data
      const { ciphertext, iv } = encrypt({ plaintext, secretKey });
      const decrypted = decrypt({ ciphertext, secretKey, iv });
      expect(decrypted).toBe(plaintext);
    });
  });
});
