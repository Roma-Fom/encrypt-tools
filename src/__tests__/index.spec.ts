import * as encryptTools from "../index";

describe("Index Exports", () => {
  it("should export all required functions", () => {
    expect(encryptTools.encrypt).toBeDefined();
    expect(encryptTools.decrypt).toBeDefined();
    expect(encryptTools.hash).toBeDefined();
    expect(encryptTools.sign).toBeDefined();
    expect(encryptTools.verify).toBeDefined();
    expect(encryptTools.generateSecretKey).toBeDefined();
    expect(encryptTools.generateRSAKeyPair).toBeDefined();
    expect(encryptTools.signWebhook).toBeDefined();
    expect(encryptTools.verifyWebhook).toBeDefined();
    expect(encryptTools.EncryptError).toBeDefined();
  });

  it("should be able to use exported functions", () => {
    const secretKey = encryptTools.generateSecretKey();
    const { ciphertext, iv } = encryptTools.encrypt({
      plaintext: "test",
      secretKey,
    });
    const decrypted = encryptTools.decrypt({ ciphertext, secretKey, iv });
    expect(decrypted).toBe("test");
  });
});
