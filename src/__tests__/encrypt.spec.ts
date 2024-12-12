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
