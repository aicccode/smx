package site.aicc.sm2.ec;

import java.math.BigInteger;

/**
 * Bridge from the protocol classes in {@code site.aicc.sm2} to the limb arithmetic in this package.
 * Public only because Java 8 has no module system; it is an implementation detail, not API.
 */
public final class Sm2Engine {
  private static final BigInteger THREE = BigInteger.valueOf(3);
  private static final BigInteger A_BIG = Sm2Field.P_BIG.subtract(THREE);

  private Sm2Engine() {}

  /** True when the curve parameters are exactly those of SM2. */
  static boolean isSm2Curve(BigInteger q, BigInteger a, BigInteger b) {
    return q.equals(Sm2Field.P_BIG) && a.equals(A_BIG) && b.equals(Sm2Group.B_BIG);
  }

  /** True when the domain parameters are the standard SM2 ones, so the fast paths apply. */
  public static boolean isStandardDomain(AbstractECCurve curve, AbstractECPoint g, BigInteger n) {
    if (!(curve instanceof FpCurve) || !((FpCurve) curve).isSm2() || !n.equals(Sm2Scalar.N_BIG)) {
      return false;
    }
    int[] x = limbs(g.getXCoord());
    int[] y = limbs(g.getYCoord());
    return x != null && y != null && Sm2Group.isGenerator(x, y);
  }

  private static int[] limbs(AbstractECElement e) {
    return e instanceof FpElement ? ((FpElement) e).limbs() : null;
  }

  /** True for a finite, affine, on-curve point of the plain {@link FpPoint} class. */
  private static boolean isSupported(AbstractECPoint p) {
    if (p.getClass() != FpPoint.class || p.zs.length != 0 || p.isInfinity()) {
      return false;
    }
    AbstractECCurve curve = p.getCurve();
    if (!(curve instanceof FpCurve) || !((FpCurve) curve).isSm2()) {
      return false;
    }
    int[] x = limbs(p.getXCoord());
    int[] y = limbs(p.getYCoord());
    return x != null && y != null && Sm2Group.isOnCurve(x, y);
  }

  /** Returns k * p using constant-flow methods, or null when p is not eligible. */
  static AbstractECPoint tryMultiply(AbstractECPoint p, BigInteger k) {
    if (!isSupported(p)) {
      return null;
    }
    BigInteger bounded = k.bitLength() > 256 ? k.mod(Sm2Scalar.N_BIG) : k;
    int[] scalar = Sm2Field.fromBigInteger(bounded);
    Sm2Scalar.reduceOnce(scalar, scalar);
    int[] x = limbs(p.getXCoord());
    int[] y = limbs(p.getYCoord());
    Sm2Group.Point q;
    if (Sm2Group.isGenerator(x, y)) {
      q = Sm2Group.mulGenerator(scalar);
    } else {
      Sm2Group.Point base = new Sm2Group.Point();
      base.setAffine(x, y);
      q = Sm2Group.mulVariable(base, scalar);
    }
    return toPoint(q, p.getCurve());
  }

  private static AbstractECPoint toPoint(Sm2Group.Point q, AbstractECCurve curve) {
    if (q.isInfinity()) {
      return curve.getInfinity();
    }
    int[] ax = new int[8];
    int[] ay = new int[8];
    Sm2Group.toAffine(q, ax, ay);
    return new FpPoint(curve, new FpElement(ax), new FpElement(ay));
  }

  /**
   * SM2 verification equation without an inversion: checks that (s*G + t*p).x is congruent to
   * {@code r - e} modulo n, by comparing X with c * Z^2 for both field representatives c of that
   * residue.
   *
   * @return null when p is not eligible and the caller must use the generic path
   */
  public static Boolean verify(
      AbstractECPoint p, BigInteger s, BigInteger t, BigInteger e, BigInteger r) {
    if (!isSupported(p)) {
      return null;
    }
    if (!Sm2Scalar.inRange(r) || s.abs().bitLength() > 256) {
      return Boolean.FALSE;
    }
    int[] x = limbs(p.getXCoord());
    int[] y = limbs(p.getYCoord());
    int[] sl = Sm2Field.fromBigInteger(s.mod(Sm2Scalar.N_BIG));
    int[] tl = Sm2Field.fromBigInteger(t);
    Sm2Group.Point q = Sm2Group.wnafGeneratorPlusPoint(sl, tl, x, y);
    if (q.isInfinity()) {
      return Boolean.FALSE;
    }
    int[] zz = new int[8];
    int[] rhs = new int[8];
    Sm2Field.sqr(zz, q.z);
    BigInteger c = r.subtract(e).mod(Sm2Scalar.N_BIG);
    Sm2Field.mul(rhs, Sm2Field.fromBigInteger(c), zz);
    if (Sm2Field.isEqual(rhs, q.x) != 0) {
      return Boolean.TRUE;
    }
    BigInteger c2 = c.add(Sm2Scalar.N_BIG);
    if (c2.compareTo(Sm2Field.P_BIG) < 0) {
      Sm2Field.mul(rhs, Sm2Field.fromBigInteger(c2), zz);
      return Sm2Field.isEqual(rhs, q.x) != 0;
    }
    return Boolean.FALSE;
  }

  /**
   * Computes the signature value s = (1 + d)^-1 * (k - r * d) mod n with constant-flow arithmetic.
   * Requires 1 <= d <= n - 2, 1 <= k < n and 0 <= r < n.
   *
   * @return null when r + k = n, a value the signer must reject
   */
  public static BigInteger signatureS(BigInteger d, BigInteger k, BigInteger r) {
    int[] dl = Sm2Field.fromBigInteger(d);
    int[] kl = Sm2Field.fromBigInteger(k);
    int[] rl = Sm2Field.fromBigInteger(r);
    int[] t = new int[8];
    Sm2Scalar.add(t, rl, kl);
    if (Sm2Field.isZero(t) != 0) {
      return null;
    }
    int[] one = {1, 0, 0, 0, 0, 0, 0, 0};
    int[] inv = new int[8];
    Sm2Scalar.add(t, dl, one);
    Sm2Scalar.invert(inv, t);
    Sm2Scalar.mul(t, rl, dl);
    Sm2Scalar.sub(t, kl, t);
    Sm2Scalar.mul(t, inv, t);
    return Sm2Field.toBigInteger(t);
  }

  /** True when 1 <= d <= n - 2, the range {@link #signatureS} needs. */
  public static boolean isSigningKeyInRange(BigInteger d) {
    return d.signum() > 0 && d.compareTo(Sm2Scalar.N_BIG.subtract(BigInteger.ONE)) < 0;
  }

  /** True when 0 <= v < n. */
  public static boolean isScalarInRange(BigInteger v) {
    return Sm2Scalar.inRange(v);
  }

  /** Computes t = d + x * r mod n of the key exchange; d and r must be in [0, n), x below n. */
  public static BigInteger keyExchangeT(BigInteger d, BigInteger x, BigInteger r) {
    int[] t = new int[8];
    Sm2Scalar.mul(t, Sm2Field.fromBigInteger(x), Sm2Field.fromBigInteger(r));
    Sm2Scalar.add(t, t, Sm2Field.fromBigInteger(d));
    return Sm2Field.toBigInteger(t);
  }

  /**
   * Computes t * (pub + x * rnd) of the key exchange: x and both points are public, t is secret.
   *
   * @return null when a point is not eligible and the caller must use the generic path
   */
  public static AbstractECPoint keyExchangePoint(
      AbstractECPoint pub, AbstractECPoint rnd, BigInteger x, BigInteger t) {
    if (!isSupported(pub) || !isSupported(rnd) || !Sm2Scalar.inRange(t) || x.bitLength() > 255) {
      return null;
    }
    Sm2Group.Point sum = new Sm2Group.Point();
    sum.setAffine(limbs(pub.getXCoord()), limbs(pub.getYCoord()));
    Sm2Group.wnafAdd(
        sum, Sm2Field.fromBigInteger(x), limbs(rnd.getXCoord()), limbs(rnd.getYCoord()));
    if (sum.isInfinity() || t.signum() == 0) {
      return pub.getCurve().getInfinity();
    }
    AbstractECPoint v =
        toPoint(Sm2Group.mulVariable(sum, Sm2Field.fromBigInteger(t)), pub.getCurve());
    if (!v.isValid()) {
      throw new IllegalArgumentException("Invalid EC point");
    }
    return v;
  }
}
