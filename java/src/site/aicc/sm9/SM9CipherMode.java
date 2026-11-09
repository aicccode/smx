package site.aicc.sm9;

/** The data encapsulation of SM9 encryption (GB/T 38635.4). A ciphertext does not record it. */
public enum SM9CipherMode {
  /** C2 = M xor K1 with K1 as long as M: the default. */
  STREAM,
  /** C2 = SM4-ECB(K1, PKCS#7(M)) with a 16-byte K1, as in the standard's worked example. */
  SM4
}
