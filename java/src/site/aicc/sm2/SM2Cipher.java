package site.aicc.sm2;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import site.aicc.sm2.ec.AbstractECPoint;
import site.aicc.sm2.ec.Sm2Engine;
import site.aicc.sm2.keygen.ECKeyPair;
import site.aicc.sm2.keygen.ECPrivateKey;
import site.aicc.sm2.keygen.ECPublicKey;
import site.aicc.sm2.util.ConvertUtil;
import site.aicc.sm3.SM3;

/**
 * SM2 encryption/decryption and signature core.
 *
 * <p>On the standard SM2 domain, private keys and nonces stay in constant-flow limb arithmetic. On
 * a custom domain, which only a caller of the public {@link SM2Initializer} constructor can reach,
 * this falls back to {@link BigInteger}, which is not side-channel protected.
 */
public class SM2Cipher {

  private static final int C1_BYTES = 65;
  private static final int C3_BYTES = 32;
  private static final int SCALAR_BYTES = 32;
  private static final int SIGNATURE_HEX_LENGTH = 129;
  private static final int SIGNATURE_SEPARATOR_INDEX = 64;

  /** Largest plaintext whose ciphertext still fits a hex String. */
  private static final int MAX_PLAINTEXT_BYTES = (Integer.MAX_VALUE - 64) / 2 - C1_BYTES - C3_BYTES;

  /** Retries on a rejected value; each is astronomically unlikely, so exhaustion is a failure. */
  private static final int MAX_ATTEMPTS = 16;

  private AbstractECPoint p2;
  private SM3 sm3c3;

  /**
   * Encrypts data for an encoded public key.
   *
   * @return the hex of C1 || C3 || C2, or null for empty data
   * @throws IllegalArgumentException for an invalid public key or oversized data
   * @throws IllegalStateException when the random source fails
   */
  protected static String encrypt(byte[] publicKey, byte[] data, SM2Initializer init)
      throws IOException {
    requireInit(init);
    AbstractECPoint userPublicKey = init.decodePoint(publicKey);
    if (data == null || data.length == 0) {
      return null;
    }
    if (data.length > MAX_PLAINTEXT_BYTES) {
      throw new IllegalArgumentException("Input too long for SM2");
    }
    for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
      SM2Cipher cipher = new SM2Cipher();
      AbstractECPoint c1 = cipher.initEnc(init, userPublicKey);
      int c2Offset = C1_BYTES + C3_BYTES;
      byte[] out = new byte[c2Offset + data.length];
      System.arraycopy(c1.getEncoded(), 0, out, 0, C1_BYTES);
      System.arraycopy(data, 0, out, c2Offset, data.length);
      // A KDF that outputs all zeros would leave the plaintext in the clear: pick a new k.
      if (cipher.xorKeyStream(out, c2Offset, data.length)) {
        cipher.sm3c3.update(data, 0, data.length);
        byte[] c3 = cipher.finishC3();
        System.arraycopy(c3, 0, out, C1_BYTES, C3_BYTES);
        cipher.clearSecret();
        return ConvertUtil.byteToHex(out);
      }
      cipher.clearSecret();
    }
    throw new IllegalStateException("Encryption failed");
  }

  /**
   * Decrypts C1 || C3 || C2.
   *
   * @throws IllegalArgumentException for an invalid private key or any rejected ciphertext, which
   *     all give the same message
   */
  protected static byte[] decrypt(byte[] privateKey, byte[] encryptedData, SM2Initializer init)
      throws IOException {
    requireInit(init);
    if (privateKey == null || privateKey.length != SCALAR_BYTES) {
      throw new IllegalArgumentException("Invalid private key");
    }
    BigInteger genericKey = null;
    if (init.isStandardDomain()) {
      if (!Sm2Engine.isValidPrivateKey(privateKey)) {
        throw new IllegalArgumentException("Invalid private key");
      }
    } else {
      genericKey = new BigInteger(1, privateKey);
      if (!init.isPrivateKeyInRange(genericKey)) {
        throw new IllegalArgumentException("Invalid private key");
      }
    }
    // C1(65) || C3(32) || C2(at least 1)
    if (encryptedData == null || encryptedData.length <= C1_BYTES + C3_BYTES) {
      throw decryptionFailure();
    }
    AbstractECPoint c1;
    try {
      c1 = init.decodePoint(Arrays.copyOf(encryptedData, C1_BYTES));
    } catch (IllegalArgumentException e) {
      throw decryptionFailure();
    }
    byte[] c3 = Arrays.copyOfRange(encryptedData, C1_BYTES, C1_BYTES + C3_BYTES);
    byte[] c2 = Arrays.copyOfRange(encryptedData, C1_BYTES + C3_BYTES, encryptedData.length);
    SM2Cipher cipher = new SM2Cipher();
    if (genericKey != null) {
      cipher.startC3(init, c1.multiply(genericKey));
    } else {
      cipher.startC3(init, Sm2Engine.sharedPoint(privateKey, c1));
    }
    boolean keyStreamUsable = cipher.xorKeyStream(c2, 0, c2.length);
    cipher.sm3c3.update(c2, 0, c2.length);
    boolean tagMatches = ConvertUtil.byteArrayEqual(cipher.finishC3(), c3);
    cipher.clearSecret();
    if (!keyStreamUsable | !tagMatches) {
      Arrays.fill(c2, (byte) 0);
      throw decryptionFailure();
    }
    return c2;
  }

  private static IllegalArgumentException decryptionFailure() {
    return new IllegalArgumentException("Decryption failed");
  }

  private static void requireInit(SM2Initializer init) {
    if (init == null) {
      throw new IllegalArgumentException("SM2 domain is required");
    }
  }

  /**
   * Signs with a private key of exactly 32 unsigned big-endian bytes.
   *
   * @throws IllegalArgumentException for an invalid key, user ID or message
   * @throws IllegalStateException when the random source fails
   */
  protected static String sm2Sign(
      String userId, byte[] privatekey, byte[] sourceData, SM2Initializer init) throws Exception {
    requireInit(init);
    if (privatekey == null || privatekey.length != SCALAR_BYTES || sourceData == null) {
      throw new IllegalArgumentException("Invalid private key or message");
    }
    byte[] id = ConvertUtil.hexToByte(userId);
    if (init.isStandardDomain()) {
      AbstractECPoint pA = Sm2Engine.publicPoint(init.getCurve(), privatekey);
      byte[] signature = Sm2Engine.sign(privatekey, digest(init, id, pA, sourceData));
      return ConvertUtil.byteToHex(Arrays.copyOf(signature, SCALAR_BYTES))
          + "h"
          + ConvertUtil.byteToHex(Arrays.copyOfRange(signature, SCALAR_BYTES, 2 * SCALAR_BYTES));
    }
    BigInteger d = new BigInteger(1, privatekey);
    if (!init.isPrivateKeyInRange(d)) {
      throw new IllegalArgumentException("Invalid private key");
    }
    return genericSign(init, d, digest(init, id, init.getPublicKey(d), sourceData));
  }

  private static byte[] digest(
      SM2Initializer init, byte[] id, AbstractECPoint key, byte[] sourceData) {
    byte[] z = init.userSM3Z(id, key);
    SM3 sm3 = new SM3();
    sm3.update(z, 0, z.length);
    sm3.update(sourceData, 0, sourceData.length);
    return sm3.finish().getHashBytes();
  }

  private static String genericSign(SM2Initializer init, BigInteger d, byte[] digest) {
    BigInteger n = init.getN();
    BigInteger e = new BigInteger(1, digest);
    BigInteger inverse = d.add(BigInteger.ONE).modInverse(n);
    for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
      ECKeyPair keypair = init.genKeyPair();
      BigInteger k = ((ECPrivateKey) keypair.getPrivate()).getD();
      AbstractECPoint kp = ((ECPublicKey) keypair.getPublic()).getQ();
      BigInteger r = e.add(kp.getXCoord().toBigInteger()).mod(n);
      if (r.signum() == 0 || r.add(k).equals(n)) {
        continue;
      }
      BigInteger s = inverse.multiply(k.subtract(r.multiply(d)).mod(n)).mod(n);
      if (s.signum() != 0) {
        return ConvertUtil.byteToHex(ConvertUtil.bigIntegerTo32Bytes(r))
            + "h"
            + ConvertUtil.byteToHex(ConvertUtil.bigIntegerTo32Bytes(s));
      }
    }
    throw new IllegalStateException("Signing failed");
  }

  /**
   * Verifies a signature of exactly 64 hex digits, 'h', 64 hex digits, with r and s in [1, n - 1]
   * and r + s not congruent to 0, against an encoded public key of exactly 65 bytes.
   *
   * @return false for every invalid input
   */
  protected static boolean sm2SignVerify(
      String userId, byte[] publicKey, byte[] sourceData, String signData, SM2Initializer init) {
    if (init == null || sourceData == null) {
      return false;
    }
    try {
      AbstractECPoint userKey = init.decodePoint(publicKey);
      if (signData == null
          || signData.length() != SIGNATURE_HEX_LENGTH
          || signData.charAt(SIGNATURE_SEPARATOR_INDEX) != 'h') {
        return false;
      }
      BigInteger r =
          new BigInteger(
              1, ConvertUtil.hexToByte(signData.substring(0, SIGNATURE_SEPARATOR_INDEX)));
      BigInteger s =
          new BigInteger(
              1, ConvertUtil.hexToByte(signData.substring(SIGNATURE_SEPARATOR_INDEX + 1)));
      byte[] digest = digest(init, ConvertUtil.hexToByte(userId), userKey, sourceData);
      if (init.isStandardDomain()) {
        return Sm2Engine.verify(userKey, r, s, digest);
      }
      BigInteger n = init.getN();
      if (r.signum() == 0 || s.signum() == 0 || r.compareTo(n) >= 0 || s.compareTo(n) >= 0) {
        return false;
      }
      BigInteger t = r.add(s).mod(n);
      if (t.signum() == 0) {
        return false;
      }
      AbstractECPoint sum = init.getG().multiply(s).add(userKey.multiply(t));
      if (sum.isInfinity()) {
        return false;
      }
      return r.equals(new BigInteger(1, digest).add(sum.getXCoord().toBigInteger()).mod(n));
    } catch (IllegalArgumentException e) {
      return false;
    }
  }

  /**
   * Starts an encryption for a validated public key; returns C1.
   *
   * @throws IllegalArgumentException for an invalid key
   * @throws IllegalStateException when the random source fails
   */
  protected AbstractECPoint initEnc(SM2Initializer init, AbstractECPoint userPublicKey) {
    requireInit(init);
    if (!init.isUsablePoint(userPublicKey)) {
      throw new IllegalArgumentException("Invalid EC point");
    }
    if (init.isStandardDomain()) {
      AbstractECPoint[] points = Sm2Engine.encapsulate(userPublicKey);
      startC3(init, points[1]);
      return points[0];
    }
    ECKeyPair key = init.genKeyPair();
    BigInteger k = ((ECPrivateKey) key.getPrivate()).getD();
    startC3(init, userPublicKey.multiply(k));
    return ((ECPublicKey) key.getPublic()).getQ();
  }

  /**
   * Starts a decryption.
   *
   * @throws IllegalArgumentException for an invalid private key or C1
   */
  protected void initDec(SM2Initializer init, BigInteger privateKey, AbstractECPoint c1) {
    requireInit(init);
    if (!init.isPrivateKeyInRange(privateKey) || !init.isUsablePoint(c1)) {
      throw new IllegalArgumentException("Invalid private key or point");
    }
    startC3(init, c1.multiply(privateKey));
  }

  private void startC3(SM2Initializer init, AbstractECPoint shared) {
    if (shared.isInfinity() || !init.isUsablePoint(shared)) {
      throw decryptionFailure();
    }
    this.p2 = shared;
    byte[] p2x = shared.getXCoord().getEncoded();
    this.sm3c3 = new SM3();
    this.sm3c3.update(p2x, 0, p2x.length);
    Arrays.fill(p2x, (byte) 0);
  }

  /** XORs the KDF output into data; returns false when the output was all zeros. */
  private boolean xorKeyStream(byte[] data, int offset, int length) {
    byte[] key = SM2KdfUtil.kdf(length, this.p2, null, null);
    boolean usable = !SM2KdfUtil.isAllZero(key, 0, length);
    for (int i = 0; i < length; i++) {
      data[offset + i] ^= key[i];
    }
    Arrays.fill(key, (byte) 0);
    return usable;
  }

  private byte[] finishC3() {
    byte[] y = p2.getYCoord().getEncoded();
    this.sm3c3.update(y, 0, y.length);
    Arrays.fill(y, (byte) 0);
    return this.sm3c3.finish().getHashBytes();
  }

  private void clearSecret() {
    Sm2Engine.wipe(this.p2);
    this.p2 = null;
  }
}
