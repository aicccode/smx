package site.aicc.sm2;

import java.math.BigInteger;
import java.util.Arrays;
import site.aicc.sm2.ec.AbstractECElement;
import site.aicc.sm2.ec.AbstractECPoint;
import site.aicc.sm2.ec.Sm2Engine;
import site.aicc.sm2.util.ConvertUtil;
import site.aicc.sm3.SM3;

/** SM2 key exchange protocol implementation. */
public class SM2KeySwap {
  private static final int MAX_KEY_BYTES = 1 << 20;
  private static final int HASH_BYTES = 32;

  protected static SM2KeySwapParams getSb(
      SM2Initializer init,
      int byteLen,
      AbstractECPoint pA,
      AbstractECPoint rA,
      AbstractECPoint pB,
      BigInteger dB,
      AbstractECPoint rB,
      BigInteger rb,
      String idA,
      String idB) {
    SM2KeySwapParams result = new SM2KeySwapParams();
    try {
      validateInputs(init, byteLen, pA, pB, dB, rb, idA, idB);
      requirePoint(init, rB, "Key exchange failed: B's random public key is not on the curve.");
      requirePoint(init, rA, "Key exchange failed: A's random public key is not on the curve.");
      requireOwnKeys(init, dB, pB, rb, rB);
      BigInteger x2 = calcX(init.getW(), rB.getXCoord().toBigInteger());
      BigInteger x1 = calcX(init.getW(), rA.getXCoord().toBigInteger());
      AbstractECPoint v = calcPoint(init, dB, rb, x2, x1, pA, rA);
      if (v.isInfinity()) {
        throw new IllegalArgumentException("Key exchange failed: V is at infinity.");
      }
      byte[] zA = init.userSM3Z(ConvertUtil.utf8Bytes(idA), pA);
      byte[] zB = init.userSM3Z(ConvertUtil.utf8Bytes(idB), pB);
      byte[] kB = deriveKey(byteLen, v, zA, zB);
      byte[] sB = createS((byte) 0x02, v, zA, zB, rA, rB);
      result.setSb(ConvertUtil.byteToHex(sB));
      result.setKb(ConvertUtil.byteToHex(kB));
      Arrays.fill(kB, (byte) 0);
      result.setV(v);
      result.setZa(zA);
      result.setZb(zB);
      result.setSuccess(true);
    } catch (RuntimeException e) {
      result.setMessage(failureMessage(e));
      result.setSuccess(false);
    }
    return result;
  }

  protected static SM2KeySwapParams getSa(
      SM2Initializer init,
      int byteLen,
      AbstractECPoint pB,
      AbstractECPoint rB,
      AbstractECPoint pA,
      BigInteger dA,
      AbstractECPoint rA,
      BigInteger ra,
      String idA,
      String idB,
      byte[] sB) {
    SM2KeySwapParams result = new SM2KeySwapParams();
    AbstractECPoint u = null;
    try {
      validateInputs(init, byteLen, pA, pB, dA, ra, idA, idB);
      requirePoint(init, rA, "Key exchange failed: A's random public key is not on the curve.");
      requirePoint(init, rB, "Key exchange failed: B's random public key is not on the curve.");
      requireOwnKeys(init, dA, pA, ra, rA);
      if (sB == null || sB.length != HASH_BYTES) {
        throw new IllegalArgumentException(
            "Key exchange failed: B's verification value does not match.");
      }
      BigInteger x1 = calcX(init.getW(), rA.getXCoord().toBigInteger());
      BigInteger x2 = calcX(init.getW(), rB.getXCoord().toBigInteger());
      u = calcPoint(init, dA, ra, x1, x2, pB, rB);
      if (u.isInfinity()) {
        throw new IllegalArgumentException("Key exchange failed: U is at infinity.");
      }
      byte[] zA = init.userSM3Z(ConvertUtil.utf8Bytes(idA), pA);
      byte[] zB = init.userSM3Z(ConvertUtil.utf8Bytes(idB), pB);
      byte[] s1 = createS((byte) 0x02, u, zA, zB, rA, rB);
      if (!ConvertUtil.byteArrayEqual(sB, s1)) {
        throw new IllegalArgumentException(
            "Key exchange failed: B's verification value does not match.");
      }
      byte[] kA = deriveKey(byteLen, u, zA, zB);
      byte[] sA = createS((byte) 0x03, u, zA, zB, rA, rB);
      result.setSa(ConvertUtil.byteToHex(sA));
      result.setKa(ConvertUtil.byteToHex(kA));
      Arrays.fill(kA, (byte) 0);
      result.setSuccess(true);
    } catch (RuntimeException e) {
      result.setSuccess(false);
      result.setMessage(failureMessage(e));
    } finally {
      Sm2Engine.wipe(u);
    }
    return result;
  }

  /** Checks the confirmation value; every invalid input gives false. */
  protected static boolean checkSa(
      AbstractECPoint v, byte[] zA, byte[] zB, AbstractECPoint rA, AbstractECPoint rB, byte[] sA) {
    if (v == null
        || v.isInfinity()
        || rA == null
        || rA.isInfinity()
        || rB == null
        || rB.isInfinity()
        || zA == null
        || zA.length != HASH_BYTES
        || zB == null
        || zB.length != HASH_BYTES
        || sA == null
        || sA.length != HASH_BYTES) {
      return false;
    }
    try {
      byte[] s2 = createS((byte) 0x03, v, zA, zB, rA, rB);
      return ConvertUtil.byteArrayEqual(sA, s2);
    } catch (RuntimeException e) {
      return false;
    }
  }

  /** Only this library's own validation messages reach the caller. */
  private static String failureMessage(RuntimeException e) {
    return e instanceof IllegalArgumentException ? e.getMessage() : "Key exchange failed.";
  }

  private static void validateInputs(
      SM2Initializer init,
      int byteLen,
      AbstractECPoint pA,
      AbstractECPoint pB,
      BigInteger d,
      BigInteger r,
      String idA,
      String idB) {
    if (init == null) {
      throw new IllegalArgumentException("Key exchange failed: SM2 domain is required.");
    }
    if (byteLen < 1 || byteLen > MAX_KEY_BYTES) {
      throw new IllegalArgumentException("Key exchange failed: invalid key length.");
    }
    if (idA == null || idB == null) {
      throw new IllegalArgumentException("Key exchange failed: user ID is required.");
    }
    if (!init.isPrivateKeyInRange(d) || !init.isPrivateKeyInRange(r)) {
      throw new IllegalArgumentException("Key exchange failed: invalid private key.");
    }
    requirePoint(init, pA, "Key exchange failed: A's public key is not on the curve.");
    requirePoint(init, pB, "Key exchange failed: B's public key is not on the curve.");
  }

  /** The caller's own public values must belong to its private values. */
  private static void requireOwnKeys(
      SM2Initializer init, BigInteger d, AbstractECPoint pub, BigInteger r, AbstractECPoint rnd) {
    boolean match =
        ConvertUtil.byteArrayEqual(init.getPublicKey(d).getEncoded(), pub.getEncoded())
            & ConvertUtil.byteArrayEqual(init.getPublicKey(r).getEncoded(), rnd.getEncoded());
    if (!match) {
      throw new IllegalArgumentException(
          "Key exchange failed: own public keys do not match the private keys.");
    }
  }

  private static void requirePoint(SM2Initializer init, AbstractECPoint point, String message) {
    if (!init.isUsablePoint(point)) {
      throw new IllegalArgumentException(message);
    }
  }

  /**
   * The KDF output, used as it is: GB/T 32918.3 has no all-zero rule for key exchange (that rule is
   * for encryption only), and other implementations return such keys.
   */
  private static byte[] deriveKey(int byteLen, AbstractECPoint shared, byte[] zA, byte[] zB) {
    return SM2KdfUtil.kdf(byteLen, shared, zA, zB);
  }

  private static void updateCoordinate(SM3 sm3, AbstractECElement coordinate) {
    byte[] bytes = coordinate.getEncoded();
    sm3.update(bytes, 0, bytes.length);
    Arrays.fill(bytes, (byte) 0);
  }

  /** Coordinates go through limbs here, so that the secret V never gets a BigInteger form. */
  private static byte[] createS(
      byte tag, AbstractECPoint vu, byte[] zA, byte[] zB, AbstractECPoint rA, AbstractECPoint rB) {
    SM3 inner = new SM3();
    updateCoordinate(inner, vu.getXCoord());
    inner.update(zA, 0, zA.length);
    inner.update(zB, 0, zB.length);
    updateCoordinate(inner, rA.getXCoord());
    updateCoordinate(inner, rA.getYCoord());
    updateCoordinate(inner, rB.getXCoord());
    updateCoordinate(inner, rB.getYCoord());
    byte[] h1 = inner.finish().getHashBytes();
    SM3 hash = new SM3();
    hash.update(tag);
    updateCoordinate(hash, vu.getYCoord());
    hash.update(h1, 0, h1.length);
    return hash.finish().getHashBytes();
  }

  private static BigInteger calcX(int w, BigInteger x) {
    BigInteger pow = BigInteger.ONE.shiftLeft(w);
    BigInteger value = pow.add(x.and(pow.subtract(BigInteger.ONE)));
    return ConvertUtil.fromUnsignedByteArray(ConvertUtil.bigIntegerTo32Bytes(value), 0, 32);
  }

  /** Computes (d + x * r) * (pub + y * rnd), own secrets first, peer's public values last. */
  private static AbstractECPoint calcPoint(
      SM2Initializer init,
      BigInteger d,
      BigInteger r,
      BigInteger x,
      BigInteger y,
      AbstractECPoint pub,
      AbstractECPoint rnd) {
    if (init.isStandardDomain()) {
      return Sm2Engine.keyExchangePoint(d, r, x, y, pub, rnd);
    }
    BigInteger t = d.add(x.multiply(r)).mod(init.getN());
    return pub.add(rnd.multiply(y)).multiply(t);
  }
}
