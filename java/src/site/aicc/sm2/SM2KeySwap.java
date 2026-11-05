package site.aicc.sm2;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import site.aicc.sm2.ec.AbstractECPoint;
import site.aicc.sm2.ec.Sm2Engine;
import site.aicc.sm2.util.ConvertUtil;
import site.aicc.sm3.SM3;

/** SM2 key exchange protocol implementation. */
public class SM2KeySwap {

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
      BigInteger x2 = calcX(init.getW(), rB.getXCoord().toBigInteger());
      BigInteger tb = calcT(init, rb, dB, x2);
      try {
        init.validatePoint(rA.getXCoord().toBigInteger(), rA.getYCoord().toBigInteger());
      } catch (Exception e) {
        throw new IllegalArgumentException(
            "Key exchange failed: A's random public key is not on the curve.");
      }
      BigInteger x1 = calcX(init.getW(), rA.getXCoord().toBigInteger());
      AbstractECPoint v = calcPoint(init, tb, x1, pA, rA);
      if (v.isInfinity()) {
        throw new IllegalArgumentException("Key exchange failed: V is at infinity.");
      }
      byte[] zA = init.userSM3Z(idA.getBytes(StandardCharsets.UTF_8), pA);
      byte[] zB = init.userSM3Z(idB.getBytes(StandardCharsets.UTF_8), pB);
      byte[] kB = SM2KdfUtil.kdf(byteLen, v, zA, zB);
      byte[] sB = createS((byte) 0x02, v, zA, zB, rA, rB);
      result.setSb(ConvertUtil.byteToHex(sB));
      result.setKb(ConvertUtil.byteToHex(kB));
      result.setV(v);
      result.setZa(zA);
      result.setZb(zB);
      result.setSuccess(true);
    } catch (Exception e) {
      result.setMessage(e.getMessage());
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
    try {
      BigInteger x1 = calcX(init.getW(), rA.getXCoord().toBigInteger());
      BigInteger ta = calcT(init, ra, dA, x1);
      try {
        init.validatePoint(rB.getXCoord().toBigInteger(), rB.getYCoord().toBigInteger());
      } catch (Exception e) {
        throw new IllegalArgumentException(
            "Key exchange failed: B's random public key is not on the curve.");
      }
      BigInteger x2 = calcX(init.getW(), rB.getXCoord().toBigInteger());
      AbstractECPoint u = calcPoint(init, ta, x2, pB, rB);
      if (u.isInfinity()) {
        throw new IllegalArgumentException("Key exchange failed: U is at infinity.");
      }
      byte[] zA = init.userSM3Z(idA.getBytes(StandardCharsets.UTF_8), pA);
      byte[] zB = init.userSM3Z(idB.getBytes(StandardCharsets.UTF_8), pB);
      byte[] kA = SM2KdfUtil.kdf(byteLen, u, zA, zB);
      byte[] s1 = createS((byte) 0x02, u, zA, zB, rA, rB);
      if (!ConvertUtil.byteArrayEqual(sB, s1)) {
        throw new IllegalArgumentException(
            "Key exchange failed: B's verification value does not match.");
      }
      byte[] sA = createS((byte) 0x03, u, zA, zB, rA, rB);
      result.setSa(ConvertUtil.byteToHex(sA));
      result.setKa(ConvertUtil.byteToHex(kA));
      result.setSuccess(true);
    } catch (Exception e) {
      result.setSuccess(false);
      result.setMessage(e.getMessage());
    }
    return result;
  }

  protected static boolean checkSa(
      AbstractECPoint v, byte[] zA, byte[] zB, AbstractECPoint rA, AbstractECPoint rB, byte[] sA) {
    byte[] s2 = createS((byte) 0x03, v, zA, zB, rA, rB);
    return ConvertUtil.byteArrayEqual(sA, s2);
  }

  private static void updateCoordinate(SM3 sm3, BigInteger coordinate) {
    byte[] bytes = ConvertUtil.bigIntegerTo32Bytes(coordinate);
    sm3.update(bytes, 0, bytes.length);
  }

  private static byte[] createS(
      byte tag, AbstractECPoint vu, byte[] zA, byte[] zB, AbstractECPoint rA, AbstractECPoint rB) {
    SM3 inner = new SM3();
    updateCoordinate(inner, vu.getXCoord().toBigInteger());
    inner.update(zA, 0, zA.length);
    inner.update(zB, 0, zB.length);
    updateCoordinate(inner, rA.getXCoord().toBigInteger());
    updateCoordinate(inner, rA.getYCoord().toBigInteger());
    updateCoordinate(inner, rB.getXCoord().toBigInteger());
    updateCoordinate(inner, rB.getYCoord().toBigInteger());
    byte[] h1 = inner.finish().getHashBytes();
    SM3 hash = new SM3();
    hash.update(tag);
    updateCoordinate(hash, vu.getYCoord().toBigInteger());
    hash.update(h1, 0, h1.length);
    return hash.finish().getHashBytes();
  }

  private static BigInteger calcX(int w, BigInteger x) {
    BigInteger pow = BigInteger.ONE.shiftLeft(w);
    BigInteger value = pow.add(x.and(pow.subtract(BigInteger.ONE)));
    return ConvertUtil.fromUnsignedByteArray(ConvertUtil.bigIntegerTo32Bytes(value), 0, 32);
  }

  private static BigInteger calcT(SM2Initializer init, BigInteger r, BigInteger d, BigInteger x) {
    if (init.isStandardDomain()
        && Sm2Engine.isScalarInRange(r)
        && Sm2Engine.isScalarInRange(d)
        && Sm2Engine.isScalarInRange(x)) {
      return Sm2Engine.keyExchangeT(d, x, r);
    }
    return d.add(x.multiply(r)).mod(init.getN());
  }

  private static AbstractECPoint calcPoint(
      SM2Initializer init, BigInteger t, BigInteger x, AbstractECPoint pub, AbstractECPoint rnd) {
    if (init.isStandardDomain()) {
      AbstractECPoint fast = Sm2Engine.keyExchangePoint(pub, rnd, x, t);
      if (fast != null) {
        return fast;
      }
    }
    return pub.add(rnd.multiply(x)).multiply(t);
  }
}
