export type SignSymmetric = {
  data: string;
  privateKey?: undefined;
  secret: string;
  algorithm: 'sha256' | 'sha512';
};

export type SignAsymmetric = {
  data: string;
  privateKey: string;
  secret?: undefined;
  algorithm?: undefined;
};

export type VerifyAsymmetric = {
  data: string;
  signature: string;
  publicKey: string;
  secret?: undefined;
  algorithm?: undefined;
};

export type VerifySymmetric = {
  data: string;
  signature: string;
  publicKey?: undefined;
  secret: string;
  algorithm: 'sha256' | 'sha512';
};

export type Sign = SignSymmetric | SignAsymmetric;
export type Verify = VerifySymmetric | VerifyAsymmetric;
