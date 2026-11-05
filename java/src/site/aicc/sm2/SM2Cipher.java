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

/** SM2 encryption/decryption and signature core. */
public class SM2Cipher {

  private static final int C1_BYTES = 65;
  private static final int C3_BYTES = 32;

  /** A hex value is 64 digits long exactly when its bit length exceeds this. */
  private static final int SHORT_VALUE_BITS = 252;

  private AbstractECPoint p2;
  private SM3 sm3c3;

  protected static String encrypt(byte[] publicKey, byte[] data, SM2Initializer init)
      throws IOException {
    if (publicKey == null || publicKey.length == 0) {
      return null;
    }
    if (data == null || data.length == 0) {
      return null;
    }
    SM2Cipher cipher = new SM2Cipher();
    AbstractECPoint userPublicKey = init.decodePoint(publicKey);
    AbstractECPoint c1 = cipher.initEnc(init, userPublicKey);
    byte[] c1Bytes = c1.getEncoded();
    byte[] out = new byte[c1Bytes.length + C3_BYTES + data.length];
    System.arraycopy(c1Bytes, 0, out, 0, c1Bytes.length);
    int c2Offset = c1Bytes.length + C3_BYTES;
    System.arraycopy(data, 0, out, c2Offset, data.length);
    cipher.sm3c3.update(data, 0, data.length);
    cipher.xorKeyStream(out, c2Offset, data.length);
    byte[] c3 = cipher.finishC3();
    System.arraycopy(c3, 0, out, c1Bytes.length, C3_BYTES);
    return ConvertUtil.byteToHex(out);
  }

  protected static byte[] decrypt(byte[] privateKey, byte[] encryptedData, SM2Initializer init)
      throws IOException {
    if (privateKey == null || privateKey.length == 0) {
      return null;
    }
    if (encryptedData == null || encryptedData.length == 0) {
      return null;
    }
    // C1(65) || C3(32) || C2
    if (encryptedData.length < C1_BYTES + C3_BYTES) {
      throw new StringIndexOutOfBoundsException(
          "ciphertext too short: " + encryptedData.length + " bytes");
    }
    byte[] c1Bytes = Arrays.copyOf(encryptedData, C1_BYTES);
    byte[] c3 = Arrays.copyOfRange(encryptedData, C1_BYTES, C1_BYTES + C3_BYTES);
    byte[] c2 = Arrays.copyOfRange(encryptedData, C1_BYTES + C3_BYTES, encryptedData.length);
    BigInteger userPrivateKey = new BigInteger(1, privateKey);
    AbstractECPoint c1 = init.decodePoint(c1Bytes);
    SM2Cipher cipher = new SM2Cipher();
    cipher.initDec(init, userPrivateKey, c1);
    cipher.xorKeyStream(c2, 0, c2.length);
    cipher.sm3c3.update(c2, 0, c2.length);
    if (!ConvertUtil.byteArrayEqual(cipher.finishC3(), c3)) {
      throw new IllegalArgumentException("Decryption failed");
    }
    return c2;
  }

  protected static String sm2Sign(
      String userId, byte[] privatekey, byte[] sourceData, SM2Initializer init) throws Exception {
    // Read as a signed number, so a key with the top bit set signs as d - 2^256. Changing this
    // would change signatures, so the behavior is kept.
    BigInteger d = new BigInteger(privatekey);
    AbstractECPoint pA = init.getPublicKey(d);
    byte[] zA = init.userSM3Z(ConvertUtil.hexToByte(userId), pA);
    SM3 sm3 = new SM3();
    sm3.update(zA, 0, zA.length);
    sm3.update(sourceData, 0, sourceData.length);
    BigInteger e = new BigInteger(1, sm3.finish().getHashBytes());
    boolean limbPath = init.isStandardDomain() && Sm2Engine.isSigningKeyInRange(d);
    BigInteger n = init.getN();
    BigInteger r;
    BigInteger s;
    do {
      BigInteger k;
      BigInteger candidate;
      do {
        ECKeyPair keypair = init.genKeyPair();
        k = ((ECPrivateKey) keypair.getPrivate()).getD();
        AbstractECPoint kp = ((ECPublicKey) keypair.getPublic()).getQ();
        r = e.add(kp.getXCoord().toBigInteger()).mod(n);
        candidate = limbPath ? signatureValue(d, k, r) : null;
      } while (r.signum() == 0
          || r.bitLength() <= SHORT_VALUE_BITS
          || (limbPath ? candidate == null : r.add(k).equals(n)));
      s = limbPath ? candidate : genericSignatureValue(d, k, r, n);
    } while (s.signum() == 0 || s.bitLength() <= SHORT_VALUE_BITS);
    return ConvertUtil.byteToHex(ConvertUtil.bigIntegerTo32Bytes(r))
        + "h"
        + ConvertUtil.byteToHex(ConvertUtil.bigIntegerTo32Bytes(s));
  }

  /** Limb computation of s, skipped for r values the signer rejects anyway. */
  private static BigInteger signatureValue(BigInteger d, BigInteger k, BigInteger r) {
    return r.signum() == 0 || r.bitLength() <= SHORT_VALUE_BITS
        ? null
        : Sm2Engine.signatureS(d, k, r);
  }

  private static BigInteger genericSignatureValue(
      BigInteger d, BigInteger k, BigInteger r, BigInteger n) {
    BigInteger inverse = d.add(BigInteger.ONE).modInverse(n);
    return inverse.multiply(k.subtract(r.multiply(d)).mod(n)).mod(n);
  }

  protected static boolean sm2SignVerify(
      String userId, byte[] publicKey, byte[] sourceData, String signData, SM2Initializer init) {
    try {
      byte[] encodedKey = publicKey;
      if (publicKey.length == 64) {
        encodedKey = new byte[65];
        encodedKey[0] = 0x04;
        System.arraycopy(publicKey, 0, encodedKey, 1, publicKey.length);
      }
      AbstractECPoint userKey = init.decodePoint(encodedKey);
      SM3 sm3 = new SM3();
      byte[] z = init.userSM3Z(ConvertUtil.hexToByte(userId), userKey);
      sm3.update(z, 0, z.length);
      sm3.update(sourceData, 0, sourceData.length);
      String[] parts = signData.split("h");
      BigInteger r = new BigInteger(parts[0], 16);
      BigInteger s = new BigInteger(parts[1], 16);
      BigInteger e = new BigInteger(1, sm3.finish().getHashBytes());
      BigInteger n = init.getN();
      BigInteger t = r.add(s).mod(n);
      if (t.signum() == 0) {
        return false;
      }
      if (init.isStandardDomain()) {
        Boolean verdict = Sm2Engine.verify(userKey, s, t, e, r);
        if (verdict != null) {
          return verdict;
        }
      }
      AbstractECPoint sum = init.getG().multiply(s).add(userKey.multiply(t));
      return r.equals(e.add(sum.getXCoord().toBigInteger()).mod(n));
    } catch (Exception e) {
      return false;
    }
  }

  protected AbstractECPoint initEnc(SM2Initializer init, AbstractECPoint userPublicKey) {
    ECKeyPair key = init.genKeyPair();
    BigInteger k = ((ECPrivateKey) key.getPrivate()).getD();
    AbstractECPoint c1 = ((ECPublicKey) key.getPublic()).getQ();
    startC3(userPublicKey.multiply(k));
    return c1;
  }

  protected void initDec(SM2Initializer init, BigInteger privateKey, AbstractECPoint c1) {
    init.validatePoint(c1.getXCoord().toBigInteger(), c1.getYCoord().toBigInteger());
    startC3(c1.multiply(privateKey));
  }

  private void startC3(AbstractECPoint shared) {
    this.p2 = shared;
    byte[] p2x = shared.getXCoord().getEncoded();
    this.sm3c3 = new SM3();
    this.sm3c3.update(p2x, 0, p2x.length);
  }

  private void xorKeyStream(byte[] data, int offset, int length) {
    byte[] key = SM2KdfUtil.kdf(length, this.p2, null, null);
    for (int i = 0; i < length; i++) {
      data[offset + i] ^= key[i];
    }
  }

  private byte[] finishC3() {
    byte[] y = ConvertUtil.bigIntegerTo32Bytes(p2.getYCoord().toBigInteger());
    this.sm3c3.update(y, 0, y.length);
    return this.sm3c3.finish().getHashBytes();
  }
}
