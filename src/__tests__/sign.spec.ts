import {
  generateSecretKey,
  generateRSAKeyPair,
  sign,
  verify,
  EncryptError,
} from "../encrypt";

describe("Sign and Verify", () => {
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
    it("should fail sign", () => {
      expect(() => sign({ data: "data", privateKey: "123" })).toThrow(
        EncryptError
      );
    });
  });

  describe("Edge Cases", () => {
    it("should handle empty data", () => {
      const secretKey = generateSecretKey();
      const signature = sign({
        data: "",
        secret: secretKey,
        algorithm: "sha256",
      });

      const isValid = verify({
        data: "",
        secret: secretKey,
        signature,
        algorithm: "sha256",
      });

      expect(isValid).toBe(true);
    });

    it("should fail verification with mismatched algorithms", () => {
      const secretKey = generateSecretKey();
      const data = "test data";
      const signature = sign({
        data,
        secret: secretKey,
        algorithm: "sha256",
      });

      const isValid = verify({
        data,
        secret: secretKey,
        signature,
        algorithm: "sha512",
      });

      expect(isValid).toBe(false);
    });

    it("should handle large data payloads", () => {
      const secretKey = generateSecretKey();
      const largeData = "x".repeat(10000);

      const signature = sign({
        data: largeData,
        secret: secretKey,
        algorithm: "sha256",
      });

      expect(() =>
        verify({
          data: largeData,
          secret: secretKey,
          signature,
          algorithm: "sha256",
        })
      ).not.toThrow();
    });
  });
});
