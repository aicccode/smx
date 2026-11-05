package site.aicc.sm2.ec;

import java.math.BigInteger;
import java.util.Arrays;
import site.aicc.sm2.util.SystemRandom;

/**
 * Bridge from the protocol classes in {@code site.aicc.sm2} to the limb arithmetic in this package.
 * Public only because Java 8 has no module system; it is an implementation detail, not API.
 *
 * <p>Every method validates its arguments and raises {@link IllegalArgumentException} rather than
 * truncating or reducing them. Secret scalars arrive as 32 big-endian bytes wherever the caller has
 * them in that form, so that no {@link BigInteger} arithmetic touches them.
 */
public final class Sm2Engine {
  private static final BigInteger THREE = BigInteger.valueOf(3);
  private static final BigInteger A_BIG = Sm2Field.P_BIG.subtract(THREE);

  /** Bound on draws for one nonce; failing to find a valid one means the generator is broken. */
  private static final int MAX_NONCE_DRAWS = 128;

  private static final int SCALAR_BYTES = 32;
  private static final int[] ONE = {1, 0, 0, 0, 0, 0, 0, 0};

  private Sm2Engine() {}

  /** True when the curve parameters are exactly those of SM2. */
  static boolean isSm2Curve(BigInteger q, BigInteger a, BigInteger b) {
    return q.equals(Sm2Field.P_BIG) && a.equals(A_BIG) && b.equals(Sm2Group.B_BIG);
  }

  /** True when the domain parameters are the standard SM2 ones, so the fast paths apply. */
  public static boolean isStandardDomain(AbstractECCurve curve, AbstractECPoint g, BigInteger n) {
    if (!(curve instanceof FpCurve) || !((FpCurve) curve).isSm2() || !Sm2Scalar.N_BIG.equals(n)) {
      return false;
    }
    if (g == null || g.isInfinity()) {
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
    if (p == null || p.getClass() != FpPoint.class || p.zs.length != 0 || p.isInfinity()) {
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

  private static void requireSupported(AbstractECPoint p) {
    if (!isSupported(p)) {
      throw new IllegalArgumentException("Invalid EC point");
    }
  }

  private static int[] scalarLimbs(byte[] scalar) {
    if (scalar == null || scalar.length != SCALAR_BYTES) {
      throw new IllegalArgumentException("Scalar must be 32 bytes");
    }
    return Sm2Field.fromBytes(scalar, 0);
  }

  /** Returns all ones when 1 <= d <= n - 2, comparing without an early exit. */
  private static int privateKeyMask(int[] d) {
    int[] sum = new int[8];
    int inGroup = Sm2Scalar.isBelowN(d);
    Sm2Scalar.addUnreduced(sum, d, ONE);
    // d + 1 must stay below n as well, which excludes n - 1.
    int mask = inGroup & Sm2Scalar.isBelowN(sum) & ~Sm2Field.isZero(d);
    Arrays.fill(sum, 0);
    return mask;
  }

  /** Checks 1 <= d <= n - 2 for a private key of exactly 32 big-endian bytes. */
  public static boolean isValidPrivateKey(byte[] d) {
    if (d == null || d.length != SCALAR_BYTES) {
      return false;
    }
    int[] limbs = Sm2Field.fromBytes(d, 0);
    int mask = privateKeyMask(limbs);
    Arrays.fill(limbs, 0);
    return mask != 0;
  }

  /** Checks 1 <= d <= n - 2 for a private key given as a BigInteger; null is simply invalid. */
  public static boolean isValidPrivateKey(BigInteger d) {
    if (d == null || d.signum() <= 0 || d.bitLength() > 256) {
      return false;
    }
    int[] limbs = Sm2Field.fromBigInteger(d);
    int mask = privateKeyMask(limbs);
    Arrays.fill(limbs, 0);
    return mask != 0;
  }

  /** Limbs of a private key given as a BigInteger, after checking 1 <= d <= n - 2. */
  private static int[] privateKeyLimbs(BigInteger d) {
    if (d == null || d.signum() <= 0 || d.bitLength() > 256) {
      throw new IllegalArgumentException("Invalid private key");
    }
    int[] limbs = Sm2Field.fromBigInteger(d);
    if (privateKeyMask(limbs) == 0) {
      Arrays.fill(limbs, 0);
      throw new IllegalArgumentException("Invalid private key");
    }
    return limbs;
  }

  /** Returns k * p using constant-flow methods, or null when p is not eligible. */
  static AbstractECPoint tryMultiply(AbstractECPoint p, BigInteger k) {
    if (!isSupported(p) || k == null || k.signum() < 0) {
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
    Arrays.fill(scalar, 0);
    return toPoint(q, p.getCurve());
  }

  private static AbstractECPoint toPoint(Sm2Group.Point q, AbstractECCurve curve) {
    return toPoint(q, curve, false);
  }

  private static AbstractECPoint toSecretPoint(Sm2Group.Point q, AbstractECCurve curve) {
    return toPoint(q, curve, true);
  }

  private static AbstractECPoint toPoint(Sm2Group.Point q, AbstractECCurve curve, boolean secret) {
    if (q.isInfinity()) {
      return curve.getInfinity();
    }
    int[] ax = new int[8];
    int[] ay = new int[8];
    Sm2Group.toAffine(q, ax, ay);
    q.wipe();
    return new FpPoint(curve, new FpElement(ax, secret), new FpElement(ay, secret));
  }

  /** Computes d * G for a private key of 32 big-endian bytes. */
  public static AbstractECPoint publicPoint(AbstractECCurve curve, byte[] d) {
    requireSm2(curve);
    int[] limbs = scalarLimbs(d);
    return publicPoint(curve, limbs);
  }

  /** Computes d * G for a private key given as a BigInteger. */
  public static AbstractECPoint publicPoint(AbstractECCurve curve, BigInteger d) {
    requireSm2(curve);
    return publicPoint(curve, privateKeyLimbs(d));
  }

  private static AbstractECPoint publicPoint(AbstractECCurve curve, int[] d) {
    try {
      if (privateKeyMask(d) == 0) {
        throw new IllegalArgumentException("Invalid private key");
      }
      return toPoint(Sm2Group.mulGenerator(d), curve);
    } finally {
      Arrays.fill(d, 0);
    }
  }

  private static void requireSm2(AbstractECCurve curve) {
    if (!(curve instanceof FpCurve) || !((FpCurve) curve).isSm2()) {
      throw new IllegalArgumentException("Not the SM2 curve");
    }
  }

  /** Draws a uniform nonce in [1, n - 1] by rejection, without modulo bias. */
  private static int[] newNonce() {
    byte[] raw = new byte[SCALAR_BYTES];
    try {
      for (int i = 0; i < MAX_NONCE_DRAWS; i++) {
        SystemRandom.fill(SystemRandom.get(), raw);
        int[] k = Sm2Field.fromBytes(raw, 0);
        if ((Sm2Scalar.isBelowN(k) & ~Sm2Field.isZero(k)) != 0) {
          return k;
        }
      }
    } finally {
      Arrays.fill(raw, (byte) 0);
    }
    throw new IllegalStateException("Secure random source failed");
  }

  /**
   * Signs a 32-byte digest value: returns r || s, 64 bytes.
   *
   * @throws IllegalArgumentException for an invalid private key or digest
   * @throws IllegalStateException when the random source fails
   */
  public static byte[] sign(byte[] d, byte[] e) {
    int[] dl = scalarLimbs(d);
    try {
      if (privateKeyMask(dl) == 0) {
        throw new IllegalArgumentException("Invalid private key");
      }
      for (int i = 0; i < MAX_NONCE_DRAWS; i++) {
        int[] k = newNonce();
        byte[] signature = signWithNonce(dl, k, e);
        Arrays.fill(k, 0);
        if (signature != null) {
          return signature;
        }
      }
    } finally {
      Arrays.fill(dl, 0);
    }
    throw new IllegalStateException("Secure random source failed");
  }

  /** One signing attempt; returns null when the standard requires a new nonce. */
  static byte[] signWithNonce(int[] d, int[] k, byte[] e) {
    int[] el = scalarLimbs(e);
    Sm2Scalar.reduceOnce(el, el);
    Sm2Group.Point kg = Sm2Group.mulGenerator(k);
    if (kg.isInfinity()) {
      return null;
    }
    int[] x1 = new int[8];
    int[] y1 = new int[8];
    Sm2Group.toAffine(kg, x1, y1);
    kg.wipe();
    Sm2Scalar.reduceOnce(x1, x1);
    int[] r = new int[8];
    Sm2Scalar.add(r, el, x1);
    int[] t = new int[8];
    Sm2Scalar.add(t, r, k);
    if ((Sm2Field.isZero(r) | Sm2Field.isZero(t)) != 0) {
      return null;
    }
    int[] s = new int[8];
    signatureValue(s, d, k, r, t);
    if (Sm2Field.isZero(s) != 0) {
      return null;
    }
    byte[] out = new byte[2 * SCALAR_BYTES];
    Sm2Field.toBytes(r, out, 0);
    Sm2Field.toBytes(s, out, SCALAR_BYTES);
    Arrays.fill(y1, 0);
    Arrays.fill(t, 0);
    return out;
  }

  /** Sets s = (1 + d)^-1 * (k - r * d) mod n with constant-flow arithmetic. t is scratch. */
  private static void signatureValue(int[] s, int[] d, int[] k, int[] r, int[] t) {
    int[] inv = new int[8];
    Sm2Scalar.add(t, d, ONE);
    Sm2Scalar.invert(inv, t);
    Sm2Scalar.mul(t, r, d);
    Sm2Scalar.sub(t, k, t);
    Sm2Scalar.mul(s, inv, t);
    Arrays.fill(inv, 0);
  }

  /** Test access to {@link #signatureValue}: requires valid d, k and r; null when r + k = n. */
  static BigInteger signatureS(BigInteger d, BigInteger k, BigInteger r) {
    int[] dl = Sm2Field.fromBigInteger(d);
    int[] kl = Sm2Field.fromBigInteger(k);
    int[] rl = Sm2Field.fromBigInteger(r);
    int[] t = new int[8];
    Sm2Scalar.add(t, rl, kl);
    if (Sm2Field.isZero(t) != 0) {
      return null;
    }
    int[] s = new int[8];
    signatureValue(s, dl, kl, rl, t);
    return Sm2Field.toBigInteger(s);
  }

  /**
   * SM2 verification without an inversion: checks that (s*G + t*p).x is congruent to {@code r - e}
   * modulo n, by comparing X with c * Z^2 for both field representatives c of that residue.
   * Requires r and s in [1, n - 1] and t = r + s mod n non-zero. All values here are public.
   *
   * @return false for any invalid or out-of-range argument
   */
  public static boolean verify(AbstractECPoint p, BigInteger r, BigInteger s, byte[] e) {
    if (r == null || s == null || e == null || e.length != SCALAR_BYTES || !isSupported(p)) {
      return false;
    }
    if (r.signum() <= 0 || s.signum() <= 0 || !Sm2Scalar.inRange(r) || !Sm2Scalar.inRange(s)) {
      return false;
    }
    BigInteger t = r.add(s).mod(Sm2Scalar.N_BIG);
    if (t.signum() == 0) {
      return false;
    }
    Sm2Group.Point q =
        Sm2Group.wnafGeneratorPlusPoint(
            Sm2Field.fromBigInteger(s),
            Sm2Field.fromBigInteger(t),
            limbs(p.getXCoord()),
            limbs(p.getYCoord()));
    if (q.isInfinity()) {
      return false;
    }
    int[] zz = new int[8];
    int[] rhs = new int[8];
    Sm2Field.sqr(zz, q.z);
    BigInteger c = r.subtract(new BigInteger(1, e)).mod(Sm2Scalar.N_BIG);
    Sm2Field.mul(rhs, Sm2Field.fromBigInteger(c), zz);
    if (Sm2Field.isEqual(rhs, q.x) != 0) {
      return true;
    }
    BigInteger c2 = c.add(Sm2Scalar.N_BIG);
    if (c2.compareTo(Sm2Field.P_BIG) < 0) {
      Sm2Field.mul(rhs, Sm2Field.fromBigInteger(c2), zz);
      return Sm2Field.isEqual(rhs, q.x) != 0;
    }
    return false;
  }

  /**
   * Picks an ephemeral scalar k for encryption and returns {C1 = k*G, shared = k*pub}.
   *
   * @throws IllegalArgumentException for an invalid public key
   * @throws IllegalStateException when the random source fails
   */
  public static AbstractECPoint[] encapsulate(AbstractECPoint pub) {
    requireSupported(pub);
    int[] k = newNonce();
    try {
      Sm2Group.Point base = new Sm2Group.Point();
      base.setAffine(limbs(pub.getXCoord()), limbs(pub.getYCoord()));
      AbstractECPoint c1 = toPoint(Sm2Group.mulGenerator(k), pub.getCurve());
      AbstractECPoint shared = toSecretPoint(Sm2Group.mulVariable(base, k), pub.getCurve());
      return new AbstractECPoint[] {c1, shared};
    } finally {
      Arrays.fill(k, 0);
    }
  }

  /** Computes d * c1 for a private key of 32 big-endian bytes and a validated finite point. */
  public static AbstractECPoint sharedPoint(byte[] d, AbstractECPoint c1) {
    requireSupported(c1);
    int[] dl = scalarLimbs(d);
    try {
      if (privateKeyMask(dl) == 0) {
        throw new IllegalArgumentException("Invalid private key");
      }
      Sm2Group.Point base = new Sm2Group.Point();
      base.setAffine(limbs(c1.getXCoord()), limbs(c1.getYCoord()));
      return toSecretPoint(Sm2Group.mulVariable(base, dl), c1.getCurve());
    } finally {
      Arrays.fill(dl, 0);
    }
  }

  /**
   * Computes (d + x * r) * (pub + y * rnd), the key exchange's shared point, where x comes from the
   * own ephemeral key and y from the peer's. d and r are secret and must be in [1, n - 2]; x, y and
   * both points are public.
   *
   * @return the point, which may be the point at infinity for the caller to reject
   */
  public static AbstractECPoint keyExchangePoint(
      BigInteger d,
      BigInteger r,
      BigInteger x,
      BigInteger y,
      AbstractECPoint pub,
      AbstractECPoint rnd) {
    requireSupported(pub);
    requireSupported(rnd);
    requireHalfWidth(x);
    requireHalfWidth(y);
    int[] dl = privateKeyLimbs(d);
    int[] rl = null;
    int[] t = new int[8];
    try {
      rl = privateKeyLimbs(r);
      Sm2Scalar.mul(t, Sm2Field.fromBigInteger(x), rl);
      Sm2Scalar.add(t, t, dl);
      Sm2Group.Point sum = new Sm2Group.Point();
      sum.setAffine(limbs(pub.getXCoord()), limbs(pub.getYCoord()));
      Sm2Group.wnafAdd(
          sum, Sm2Field.fromBigInteger(y), limbs(rnd.getXCoord()), limbs(rnd.getYCoord()));
      if (sum.isInfinity()) {
        return pub.getCurve().getInfinity();
      }
      return toSecretPoint(Sm2Group.mulVariable(sum, t), pub.getCurve());
    } finally {
      Arrays.fill(dl, 0);
      Arrays.fill(t, 0);
      if (rl != null) {
        Arrays.fill(rl, 0);
      }
    }
  }

  private static void requireHalfWidth(BigInteger x) {
    if (x == null || x.signum() <= 0 || x.bitLength() > 128) {
      throw new IllegalArgumentException("Invalid key exchange value");
    }
  }

  /**
   * Best-effort erasure of a secret point this class returned, once it is no longer needed. Any
   * other point, such as a public key or the generator, is left untouched.
   */
  public static void wipe(AbstractECPoint secret) {
    if (secret == null || secret.isInfinity()) {
      return;
    }
    for (AbstractECElement e : new AbstractECElement[] {secret.getXCoord(), secret.getYCoord()}) {
      if (e instanceof FpElement) {
        ((FpElement) e).eraseIfSecret();
      }
    }
  }

  /** Test access: d + x * r mod n. */
  static BigInteger keyExchangeT(BigInteger d, BigInteger x, BigInteger r) {
    int[] t = new int[8];
    Sm2Scalar.mul(t, Sm2Field.fromBigInteger(x), Sm2Field.fromBigInteger(r));
    Sm2Scalar.add(t, t, Sm2Field.fromBigInteger(d));
    return Sm2Field.toBigInteger(t);
  }
}
