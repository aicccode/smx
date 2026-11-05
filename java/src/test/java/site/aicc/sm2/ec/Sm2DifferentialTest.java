package site.aicc.sm2.ec;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.junit.Test;

/**
 * Differential tests of the limb arithmetic against BigInteger and a slow affine reference, with
 * fixed seeds, on edge values and on bit patterns that force long carry chains.
 */
public class Sm2DifferentialTest {
  private static final BigInteger P = Sm2Field.P_BIG;
  private static final BigInteger N = Sm2Scalar.N_BIG;
  private static final BigInteger TWO_256 = BigInteger.ONE.shiftLeft(256);
  private static final BigInteger A = P.subtract(BigInteger.valueOf(3));
  private static final BigInteger[] G = {Sm2Group.GX_BIG, Sm2Group.GY_BIG};

  private static BigInteger val(long v) {
    return BigInteger.valueOf(v);
  }

  /** Values near every structural boundary of the given modulus. */
  private static List<BigInteger> edges(BigInteger m) {
    List<BigInteger> out = new ArrayList<>();
    for (long small : new long[] {0, 1, 2, 3, 4, 5, 0xFFFFFFFFL, 0x100000000L}) {
      out.add(val(small));
      out.add(m.subtract(val(small + 1)));
    }
    for (int bit : new int[] {32, 64, 96, 128, 160, 192, 224, 248, 252, 255}) {
      BigInteger pow = BigInteger.ONE.shiftLeft(bit);
      out.add(pow);
      out.add(pow.subtract(BigInteger.ONE));
      out.add(pow.add(BigInteger.ONE));
    }
    out.add(m.shiftRight(1));
    out.add(m.shiftRight(1).add(BigInteger.ONE));
    List<BigInteger> reduced = new ArrayList<>();
    for (BigInteger v : out) {
      reduced.add(v.mod(m));
    }
    return reduced;
  }

  /** Random value whose limbs often are all zeros or all ones, forcing maximal carries. */
  private static BigInteger patterned(Random r, BigInteger m) {
    int[] limbs = new int[8];
    for (int i = 0; i < 8; i++) {
      int kind = r.nextInt(4);
      limbs[i] = kind == 0 ? 0 : kind == 1 ? -1 : r.nextInt();
    }
    return Sm2Field.toBigInteger(limbs).mod(m);
  }

  private static int[] limbs(BigInteger v) {
    return Sm2Field.fromBigInteger(v);
  }

  private static void same(String what, BigInteger expected, int[] actual) {
    assertEquals(what, expected, Sm2Field.toBigInteger(actual));
  }

  // ---------------------------------------------------------------- field

  private static void checkFieldPair(BigInteger a, BigInteger b) {
    int[] la = limbs(a);
    int[] lb = limbs(b);
    int[] r = new int[8];
    Sm2Field.mul(r, la, lb);
    same("mul", a.multiply(b).mod(P), r);
    Sm2Field.add(r, la, lb);
    same("add", a.add(b).mod(P), r);
    Sm2Field.sub(r, la, lb);
    same("sub", a.subtract(b).mod(P), r);
    Sm2Field.sqr(r, la);
    same("sqr", a.multiply(a).mod(P), r);
    Sm2Field.neg(r, la);
    same("neg", a.negate().mod(P), r);
    assertEquals(a.signum() == 0, Sm2Field.isZero(la) != 0);
    assertEquals(a.equals(b), Sm2Field.isEqual(la, lb) != 0);
    // Aliased output.
    int[] alias = la.clone();
    Sm2Field.mul(alias, alias, lb);
    same("mul alias", a.multiply(b).mod(P), alias);
    alias = la.clone();
    Sm2Field.sub(alias, lb, alias);
    same("sub alias", b.subtract(a).mod(P), alias);
    alias = la.clone();
    Sm2Field.sqr(alias, alias);
    same("sqr alias", a.multiply(a).mod(P), alias);
  }

  @Test
  public void fieldEdgeValues() {
    List<BigInteger> edges = edges(P);
    for (BigInteger a : edges) {
      for (BigInteger b : edges) {
        checkFieldPair(a, b);
      }
    }
  }

  @Test
  public void fieldRandomAndPatterned() {
    Random r = new Random(1);
    for (int i = 0; i < 200000; i++) {
      BigInteger a = i % 2 == 0 ? new BigInteger(256, r).mod(P) : patterned(r, P);
      BigInteger b = i % 3 == 0 ? new BigInteger(256, r).mod(P) : patterned(r, P);
      checkFieldPair(a, b);
    }
  }

  @Test
  public void fieldMulAcceptsUnreducedMaximum() {
    // Not produced by the library, but the reduction must hold for the largest limb values.
    BigInteger max = TWO_256.subtract(BigInteger.ONE);
    int[] r = new int[8];
    Sm2Field.mul(r, limbs(max), limbs(max));
    same("max*max", max.multiply(max).mod(P), r);
    Sm2Field.sqr(r, limbs(max));
    same("max^2", max.multiply(max).mod(P), r);
    Sm2Field.mul(r, limbs(P), limbs(P));
    same("p*p", BigInteger.ZERO, r);
    Sm2Field.mul(r, limbs(P), limbs(max));
    same("p*max", BigInteger.ZERO, r);
  }

  @Test
  public void bytesRoundTrip() {
    Random r = new Random(2);
    for (int i = 0; i < 2000; i++) {
      BigInteger v = patterned(r, P);
      byte[] out = new byte[33];
      Sm2Field.toBytes(limbs(v), out, 1);
      assertEquals(v, new BigInteger(1, java.util.Arrays.copyOfRange(out, 1, 33)));
      assertArrayEquals(limbs(v), Sm2Field.fromBytes(out, 1));
    }
  }

  // ---------------------------------------------------------------- inversion

  @Test
  public void inversionMatchesBigInteger() {
    Random r = new Random(3);
    int[] out = new int[8];
    List<BigInteger> forP = edges(P);
    List<BigInteger> forN = edges(N);
    for (int i = 0; i < 40000; i++) {
      forP.add(i % 2 == 0 ? new BigInteger(256, r).mod(P) : patterned(r, P));
      forN.add(i % 2 == 0 ? new BigInteger(256, r).mod(N) : patterned(r, N));
    }
    for (BigInteger v : forP) {
      Sm2Group.invert(out, limbs(v));
      same("inv p", v.signum() == 0 ? BigInteger.ZERO : v.modInverse(P), out);
    }
    for (BigInteger v : forN) {
      Sm2Scalar.invert(out, limbs(v));
      same("inv n", v.signum() == 0 ? BigInteger.ZERO : v.modInverse(N), out);
    }
    // Output aliasing the input.
    int[] alias = limbs(val(12345));
    Sm2Group.invert(alias, alias);
    same("alias", val(12345).modInverse(P), alias);
  }

  // ---------------------------------------------------------------- scalars

  @Test
  public void scalarArithmetic() {
    Random r = new Random(4);
    List<BigInteger> edges = edges(N);
    List<BigInteger[]> pairs = new ArrayList<>();
    for (BigInteger a : edges) {
      for (BigInteger b : edges) {
        pairs.add(new BigInteger[] {a, b});
      }
    }
    for (int i = 0; i < 50000; i++) {
      pairs.add(new BigInteger[] {patterned(r, N), new BigInteger(256, r).mod(N)});
    }
    int[] out = new int[8];
    for (BigInteger[] p : pairs) {
      Sm2Scalar.mul(out, limbs(p[0]), limbs(p[1]));
      same("mul", p[0].multiply(p[1]).mod(N), out);
      Sm2Scalar.add(out, limbs(p[0]), limbs(p[1]));
      same("add", p[0].add(p[1]).mod(N), out);
      Sm2Scalar.sub(out, limbs(p[0]), limbs(p[1]));
      same("sub", p[0].subtract(p[1]).mod(N), out);
    }
    for (BigInteger v :
        new BigInteger[] {
          N,
          N.add(BigInteger.ONE),
          TWO_256.subtract(BigInteger.ONE),
          BigInteger.ZERO,
          N.subtract(BigInteger.ONE)
        }) {
      Sm2Scalar.reduceOnce(out, limbs(v));
      same("reduceOnce", v.mod(N), out);
    }
  }

  @Test
  public void signatureValueMatchesFormula() {
    Random r = new Random(5);
    for (int i = 0; i < 5000; i++) {
      BigInteger d =
          i < 3 ? val(i + 1) : new BigInteger(256, r).mod(N.subtract(val(2))).add(BigInteger.ONE);
      BigInteger k = patterned(r, N).add(BigInteger.ONE).min(N.subtract(BigInteger.ONE));
      BigInteger rv = patterned(r, N);
      BigInteger expected =
          rv.add(k).equals(N)
              ? null
              : d.add(BigInteger.ONE).modInverse(N).multiply(k.subtract(rv.multiply(d))).mod(N);
      assertEquals(expected, Sm2Engine.signatureS(d, k, rv));
    }
    assertNull(Sm2Engine.signatureS(val(5), val(9), N.subtract(val(9))));
    assertTrue(Sm2Engine.isSigningKeyInRange(BigInteger.ONE));
    assertTrue(Sm2Engine.isSigningKeyInRange(N.subtract(val(2))));
    assertFalse(Sm2Engine.isSigningKeyInRange(BigInteger.ZERO));
    assertFalse(Sm2Engine.isSigningKeyInRange(N.subtract(BigInteger.ONE)));
    assertFalse(Sm2Engine.isSigningKeyInRange(val(-1)));
  }

  @Test
  public void keyExchangeScalarMatchesFormula() {
    Random r = new Random(6);
    for (int i = 0; i < 5000; i++) {
      BigInteger d = patterned(r, N);
      BigInteger x = BigInteger.ONE.shiftLeft(127).add(new BigInteger(127, r));
      BigInteger rv = patterned(r, N);
      assertEquals(d.add(x.multiply(rv)).mod(N), Sm2Engine.keyExchangeT(d, x, rv));
    }
  }

  // ---------------------------------------------------------------- reference group

  /** Slow affine group law; null is the point at infinity. */
  private static BigInteger[] refAdd(BigInteger[] a, BigInteger[] b) {
    if (a == null) {
      return b;
    }
    if (b == null) {
      return a;
    }
    BigInteger lambda;
    if (a[0].equals(b[0])) {
      if (a[1].add(b[1]).mod(P).signum() == 0) {
        return null;
      }
      lambda =
          a[0].multiply(a[0]).multiply(val(3)).add(A).multiply(a[1].shiftLeft(1).modInverse(P));
    } else {
      lambda = b[1].subtract(a[1]).multiply(b[0].subtract(a[0]).modInverse(P));
    }
    lambda = lambda.mod(P);
    BigInteger x = lambda.multiply(lambda).subtract(a[0]).subtract(b[0]).mod(P);
    BigInteger y = lambda.multiply(a[0].subtract(x)).subtract(a[1]).mod(P);
    return new BigInteger[] {x, y};
  }

  private static BigInteger[] refMul(BigInteger[] p, BigInteger k) {
    BigInteger[] q = null;
    for (int i = k.bitLength() - 1; i >= 0; i--) {
      q = refAdd(q, q);
      if (k.testBit(i)) {
        q = refAdd(q, p);
      }
    }
    return q;
  }

  private static BigInteger[] refNeg(BigInteger[] p) {
    return new BigInteger[] {p[0], p[1].negate().mod(P)};
  }

  private static Sm2Group.Point toJacobian(BigInteger[] p, Random r) {
    Sm2Group.Point q = new Sm2Group.Point();
    if (p == null) {
      return q;
    }
    q.setAffine(limbs(p[0]), limbs(p[1]));
    if (r != null) {
      // Randomize Z so the formulas see a general Jacobian representative.
      BigInteger z = new BigInteger(255, r).mod(P.subtract(BigInteger.ONE)).add(BigInteger.ONE);
      q.x = limbs(p[0].multiply(z).multiply(z).mod(P));
      q.y = limbs(p[1].multiply(z).multiply(z).multiply(z).mod(P));
      q.z = limbs(z);
    }
    return q;
  }

  private static void samePoint(String what, BigInteger[] expected, Sm2Group.Point actual) {
    if (expected == null) {
      assertTrue(what + " expected infinity", actual.isInfinity());
      return;
    }
    assertFalse(what + " unexpected infinity", actual.isInfinity());
    int[] x = new int[8];
    int[] y = new int[8];
    Sm2Group.toAffine(actual, x, y);
    same(what + " x", expected[0], x);
    same(what + " y", expected[1], y);
  }

  private static void checkAdditions(BigInteger[] a, BigInteger[] b, Random r) {
    BigInteger[] expected = refAdd(a, b);
    Sm2Group.Work w = new Sm2Group.Work();
    Sm2Group.Point q;
    if (b != null) {
      q = toJacobian(a, r);
      Sm2Group.addAffineVt(q, limbs(b[0]), limbs(b[1]), w);
      samePoint("addAffineVt", expected, q);
      q = toJacobian(a, r);
      Sm2Group.addAffineMasked(q, limbs(b[0]), limbs(b[1]), 0, w);
      samePoint("addAffineMasked", expected, q);
    } else {
      q = toJacobian(a, r);
      Sm2Group.addAffineMasked(q, new int[8], new int[8], -1, w);
      samePoint("addAffineMasked zero digit", expected, q);
    }
    q = toJacobian(a, r);
    Sm2Group.addVt(q, toJacobian(b, r), w);
    samePoint("addVt", expected, q);
    q = toJacobian(a, r);
    Sm2Group.addMasked(q, toJacobian(b, r), b == null ? -1 : 0, w);
    samePoint("addMasked", expected, q);
  }

  private static List<BigInteger[]> somePoints(Random r, int count) {
    List<BigInteger[]> points = new ArrayList<>();
    points.add(G);
    for (BigInteger k :
        new BigInteger[] {val(2), val(3), N.subtract(BigInteger.ONE), N.subtract(val(2))}) {
      points.add(refMul(G, k));
    }
    for (int i = 0; i < count; i++) {
      points.add(refMul(G, new BigInteger(256, r).mod(N)));
    }
    return points;
  }

  @Test
  public void formulasIncludingExceptionalCases() {
    Random r = new Random(7);
    Sm2Group.Work w = new Sm2Group.Work();
    List<BigInteger[]> points = somePoints(r, 20);
    for (BigInteger[] a : points) {
      Sm2Group.Point d = toJacobian(a, r);
      Sm2Group.dbl(d, w);
      samePoint("dbl", refAdd(a, a), d);
      checkAdditions(a, a, r); // P + P
      checkAdditions(a, refNeg(a), r); // P + (-P)
      checkAdditions(null, a, r); // infinity + P
      checkAdditions(a, null, r); // P + infinity
      for (BigInteger[] b : points) {
        checkAdditions(a, b, r);
      }
    }
    checkAdditions(null, null, r);
    Sm2Group.Point inf = new Sm2Group.Point();
    Sm2Group.dbl(inf, w);
    assertTrue(inf.isInfinity());
  }

  @Test
  public void onCurveCheck() {
    Random r = new Random(8);
    for (BigInteger[] p : somePoints(r, 20)) {
      assertTrue(Sm2Group.isOnCurve(limbs(p[0]), limbs(p[1])));
      assertFalse(Sm2Group.isOnCurve(limbs(p[0]), limbs(p[1].add(BigInteger.ONE).mod(P))));
    }
    assertTrue(Sm2Group.isGenerator(limbs(G[0]), limbs(G[1])));
    assertFalse(Sm2Group.isGenerator(limbs(G[0]), limbs(G[1].negate().mod(P))));
  }

  private static List<BigInteger> interestingScalars(Random r) {
    List<BigInteger> out = new ArrayList<>();
    for (long small = 0; small <= 70; small++) {
      out.add(val(small));
    }
    // Scalars next to n reach the exceptional cases of the last window.
    for (long small = 1; small <= 300; small++) {
      out.add(N.subtract(val(small)));
    }
    for (int bit = 1; bit < 256; bit++) {
      BigInteger pow = BigInteger.ONE.shiftLeft(bit);
      out.add(pow.min(N.subtract(BigInteger.ONE)));
      out.add(pow.subtract(BigInteger.ONE).min(N.subtract(BigInteger.ONE)));
      out.add(pow.add(BigInteger.ONE).min(N.subtract(BigInteger.ONE)));
    }
    for (int i = 0; i < 300; i++) {
      out.add(patterned(r, N));
      out.add(new BigInteger(256, r).mod(N));
    }
    return out;
  }

  @Test
  public void generatorMultiplication() {
    Random r = new Random(9);
    for (BigInteger k : interestingScalars(r)) {
      samePoint("kG " + k.toString(16), refMul(G, k), Sm2Group.mulGenerator(limbs(k)));
    }
  }

  @Test
  public void variableBaseMultiplication() {
    Random r = new Random(10);
    List<BigInteger> scalars = interestingScalars(r);
    BigInteger[] other = refMul(G, new BigInteger(256, r).mod(N));
    int i = 0;
    for (BigInteger k : scalars) {
      BigInteger[] base = i++ % 2 == 0 ? G : other;
      BigInteger[] expected = refMul(base, k);
      samePoint(
          "kP " + k.toString(16), expected, Sm2Group.mulVariable(toJacobian(base, null), limbs(k)));
      if (i % 8 == 0) {
        samePoint("kP jac", expected, Sm2Group.mulVariable(toJacobian(base, r), limbs(k)));
      }
    }
  }

  @Test
  public void wnafDigitsReconstructTheScalar() {
    Random r = new Random(11);
    List<BigInteger> scalars = interestingScalars(r);
    scalars.add(TWO_256.subtract(BigInteger.ONE));
    for (BigInteger k : scalars) {
      for (int bits : new int[] {5, 8}) {
        byte[] digits = Sm2Group.wnaf(limbs(k), bits);
        BigInteger sum = BigInteger.ZERO;
        int lastNonZero = -bits;
        for (int i = 0; i < digits.length; i++) {
          int d = digits[i];
          if (d != 0) {
            assertEquals("odd", 1, Math.abs(d) & 1);
            assertTrue("bound", Math.abs(d) < (1 << (bits - 1)));
            assertTrue("spacing", i - lastNonZero >= bits);
            lastNonZero = i;
            sum = sum.add(val(d).shiftLeft(i));
          }
        }
        assertEquals(k, sum);
      }
    }
  }

  @Test
  public void shamirIncludingCancellation() {
    Random r = new Random(12);
    List<BigInteger> scalars = interestingScalars(r);
    BigInteger[] other = refMul(G, new BigInteger(256, r).mod(N));
    for (int i = 0; i < scalars.size(); i++) {
      BigInteger s = scalars.get(i);
      BigInteger t = scalars.get(scalars.size() - 1 - i);
      BigInteger[] expected = refAdd(refMul(G, s), refMul(other, t));
      samePoint(
          "shamir",
          expected,
          Sm2Group.wnafGeneratorPlusPoint(limbs(s), limbs(t), limbs(other[0]), limbs(other[1])));
      // P = G hits every same-point and opposite-point addition case, including s + t = n.
      BigInteger t2 = N.subtract(s).mod(N);
      samePoint(
          "cancel",
          null,
          Sm2Group.wnafGeneratorPlusPoint(limbs(s), limbs(t2), limbs(G[0]), limbs(G[1])));
      expected = refMul(G, s.add(t).mod(N));
      samePoint(
          "same",
          expected,
          Sm2Group.wnafGeneratorPlusPoint(limbs(s), limbs(t), limbs(G[0]), limbs(G[1])));
    }
  }

  // ---------------------------------------------------------------- engine

  private static final FpCurve CURVE =
      new FpCurve(new DoubleAndAddMultiplier(), P, A, Sm2Group.B_BIG);

  private static AbstractECPoint point(BigInteger[] p) {
    return CURVE.createPoint(p[0], p[1]);
  }

  private static void same(BigInteger[] expected, AbstractECPoint actual) {
    if (expected == null) {
      assertTrue(actual.isInfinity());
    } else {
      assertEquals(expected[0], actual.getXCoord().toBigInteger());
      assertEquals(expected[1], actual.getYCoord().toBigInteger());
    }
  }

  @Test
  public void keyExchangePointMatchesReference() {
    Random r = new Random(13);
    for (int i = 0; i < 300; i++) {
      BigInteger[] pub = refMul(G, new BigInteger(256, r).mod(N));
      BigInteger[] rnd = refMul(G, new BigInteger(256, r).mod(N));
      BigInteger x = BigInteger.ONE.shiftLeft(127).add(new BigInteger(127, r));
      BigInteger t =
          i == 0
              ? BigInteger.ZERO
              : i == 1
                  ? BigInteger.ONE
                  : i == 2 ? N.subtract(BigInteger.ONE) : new BigInteger(256, r).mod(N);
      BigInteger[] expected = refMul(refAdd(pub, refMul(rnd, x)), t);
      same(expected, Sm2Engine.keyExchangePoint(point(pub), point(rnd), x, t));
    }
    // pub = -x * rnd: the inner sum is infinity.
    BigInteger[] rnd = refMul(G, val(7));
    BigInteger x = BigInteger.ONE.shiftLeft(127).add(val(3));
    BigInteger[] pub = refNeg(refMul(rnd, x));
    assertTrue(Sm2Engine.keyExchangePoint(point(pub), point(rnd), x, val(5)).isInfinity());
    // Not eligible: off-curve point, infinity, or out-of-range t.
    AbstractECPoint good = point(G);
    AbstractECPoint bad = CURVE.createPoint(G[0], G[1].add(BigInteger.ONE));
    assertNull(Sm2Engine.keyExchangePoint(bad, good, x, val(5)));
    assertNull(Sm2Engine.keyExchangePoint(good, bad, x, val(5)));
    assertNull(Sm2Engine.keyExchangePoint(CURVE.getInfinity(), good, x, val(5)));
    assertNull(Sm2Engine.keyExchangePoint(good, good, x, N));
  }

  /** Square root in Fp; p = 3 mod 4. Returns null for a non-residue. */
  private static BigInteger sqrt(BigInteger v) {
    BigInteger root = v.modPow(P.add(BigInteger.ONE).shiftRight(2), P);
    return root.multiply(root).mod(P).equals(v) ? root : null;
  }

  @Test
  public void verifyEquationIncludingXAboveOrder() {
    Random r = new Random(14);
    for (int i = 0; i < 300; i++) {
      BigInteger d = new BigInteger(256, r).mod(N.subtract(BigInteger.ONE)).add(BigInteger.ONE);
      BigInteger[] pub = refMul(G, d);
      BigInteger s = new BigInteger(256, r).mod(N);
      BigInteger t = new BigInteger(256, r).mod(N.subtract(BigInteger.ONE)).add(BigInteger.ONE);
      BigInteger[] sum = refAdd(refMul(G, s), refMul(pub, t));
      if (sum == null) {
        continue;
      }
      BigInteger e = new BigInteger(256, r);
      BigInteger rv = e.add(sum[0]).mod(N);
      assertEquals(Boolean.TRUE, Sm2Engine.verify(point(pub), s, t, e, rv));
      assertEquals(
          Boolean.FALSE, Sm2Engine.verify(point(pub), s, t, e, rv.add(BigInteger.ONE).mod(N)));
      assertEquals(Boolean.FALSE, Sm2Engine.verify(point(pub), s, t, e.add(BigInteger.ONE), rv));
      assertEquals(Boolean.TRUE, Sm2Engine.verify(point(pub), s.subtract(N), t, e, rv));
      assertEquals(Boolean.FALSE, Sm2Engine.verify(point(pub), s, t, e, rv.add(N)));
      assertEquals(Boolean.FALSE, Sm2Engine.verify(point(pub), s, t, e, rv.subtract(N)));
    }
    assertEquals(Boolean.FALSE, Sm2Engine.verify(point(G), TWO_256, val(1), val(1), val(1)));
    assertEquals(
        Boolean.FALSE, Sm2Engine.verify(point(G), TWO_256.negate(), val(1), val(1), val(1)));
    // s*G + t*G = infinity is a failure, not an exception.
    assertEquals(
        Boolean.FALSE, Sm2Engine.verify(point(G), N.subtract(val(5)), val(5), val(1), val(1)));
    assertNull(
        Sm2Engine.verify(
            CURVE.createPoint(G[0], G[1].add(BigInteger.ONE)), val(1), val(1), val(1), val(1)));

    // A sum point whose x lies in [n, p) needs the second field representative.
    int found = 0;
    for (BigInteger x = N.add(val(1)); found < 8; x = x.add(BigInteger.ONE)) {
      BigInteger y = sqrt(x.multiply(x).multiply(x).add(A.multiply(x)).add(Sm2Group.B_BIG).mod(P));
      if (y == null) {
        continue;
      }
      found++;
      BigInteger[] target = {x, y};
      BigInteger t = new BigInteger(255, r).add(BigInteger.ONE);
      BigInteger s = new BigInteger(255, r);
      // Solve s*G + t*pub = target for pub.
      BigInteger[] pub = refMul(refAdd(target, refNeg(refMul(G, s))), t.modInverse(N));
      BigInteger e = new BigInteger(256, r);
      BigInteger rv = e.add(x).mod(N);
      assertEquals(Boolean.TRUE, Sm2Engine.verify(point(pub), s, t, e, rv));
      assertEquals(
          Boolean.FALSE, Sm2Engine.verify(point(pub), s, t, e, rv.add(BigInteger.ONE).mod(N)));
    }
  }

  // ---------------------------------------------------------------- public element and point API

  @Test
  public void elementApiMatchesBigInteger() {
    Random r = new Random(15);
    for (int i = 0; i < 3000; i++) {
      BigInteger a = patterned(r, P);
      BigInteger b = i % 2 == 0 ? new BigInteger(256, r).mod(P) : patterned(r, P);
      AbstractECElement ea = CURVE.fromBigInteger(a);
      AbstractECElement eb = CURVE.fromBigInteger(b);
      assertEquals(a, ea.toBigInteger());
      assertEquals(a.add(b).mod(P), ea.add(eb).toBigInteger());
      assertEquals(a.subtract(b).mod(P), ea.subtract(eb).toBigInteger());
      assertEquals(a.multiply(b).mod(P), ea.multiply(eb).toBigInteger());
      assertEquals(a.multiply(a).mod(P), ea.square().toBigInteger());
      assertEquals(a.negate().mod(P), ea.negate().toBigInteger());
      assertEquals(a.signum() == 0, ea.isZero());
      assertEquals(a.equals(BigInteger.ONE), ea.isOne());
      assertEquals(a.bitLength(), ea.bitLength());
      assertEquals(256, ea.getFieldSize());
      assertEquals(a, new BigInteger(1, ea.getEncoded()));
      assertEquals(32, ea.getEncoded().length);
      if (b.signum() != 0) {
        assertEquals(a.multiply(b.modInverse(P)).mod(P), ea.divide(eb).toBigInteger());
        assertEquals(b.modInverse(P), eb.invert().toBigInteger());
      }
      AbstractECElement copy = CURVE.fromBigInteger(a);
      assertEquals(ea, copy);
      assertEquals(ea.hashCode(), copy.hashCode());
      AbstractECElement derived = ea.add(CURVE.fromBigInteger(BigInteger.ZERO));
      assertEquals(ea, derived);
      assertEquals(ea.hashCode(), derived.hashCode());
    }
    AbstractECElement zero = CURVE.fromBigInteger(BigInteger.ZERO);
    assertTrue(zero == zero.negate());
    for (Runnable op :
        new Runnable[] {zero::invert, () -> CURVE.fromBigInteger(val(5)).divide(zero)}) {
      try {
        op.run();
        org.junit.Assert.fail();
      } catch (IllegalArgumentException expected) {
        assertEquals("'x' cannot be zero", expected.getMessage());
      }
    }
    for (BigInteger bad : new BigInteger[] {P, P.add(BigInteger.ONE), val(-1)}) {
      try {
        CURVE.fromBigInteger(bad);
        org.junit.Assert.fail();
      } catch (IllegalArgumentException expected) {
        assertEquals("v is not in Fp", expected.getMessage());
      }
    }
  }

  @Test
  public void pointApiIncludingExceptionalCases() {
    Random r = new Random(16);
    List<BigInteger[]> points = somePoints(r, 8);
    for (BigInteger[] a : points) {
      AbstractECPoint pa = point(a);
      same(refAdd(a, a), pa.twice());
      same(refAdd(a, a), pa.add(point(a)));
      same(null, pa.add(point(refNeg(a))));
      same(null, pa.subtract(point(a)));
      same(a, pa.add(CURVE.getInfinity()));
      same(a, CURVE.getInfinity().add(pa));
      same(refAdd(refAdd(a, a), a), pa.threeTimes());
      same(refMul(a, val(8)), pa.timesPow2(3));
      assertTrue(pa.isValid());
      for (BigInteger[] b : points) {
        same(refAdd(a, b), pa.add(point(b)));
        same(refAdd(refAdd(a, a), b), pa.twicePlus(point(b)));
      }
    }
  }

  @Test
  public void everyMultiplierAgreesOnAndOffTheFastPath() {
    Random r = new Random(17);
    AbstractECMultiplier[] multipliers = {new DoubleAndAddMultiplier(), new WNAFMultiplier()};
    for (AbstractECMultiplier m : multipliers) {
      FpCurve curve = new FpCurve(m, P, A, Sm2Group.B_BIG);
      for (int i = 0; i < 40; i++) {
        BigInteger k = i < 3 ? N.add(val(i)) : new BigInteger(256, r);
        BigInteger[] base = i % 2 == 0 ? G : refMul(G, new BigInteger(255, r));
        BigInteger reduced = k.mod(N);
        AbstractECPoint p = curve.createPoint(base[0], base[1]);
        same(refMul(base, reduced), p.multiply(k));
        same(refMul(refNeg(base), reduced), p.multiply(k.negate()));
      }
    }
    // WNAF takes scalars wider than 256 bits.
    BigInteger wide = BigInteger.ONE.shiftLeft(300).add(val(5));
    FpCurve wnafCurve = new FpCurve(new WNAFMultiplier(), P, A, Sm2Group.B_BIG);
    same(refMul(G, wide.mod(N)), wnafCurve.createPoint(G[0], G[1]).multiply(wide));
    // An off-curve point keeps its generic route and is rejected by the result check.
    AbstractECPoint off = CURVE.createPoint(G[0], G[1].add(BigInteger.ONE));
    try {
      off.multiply(val(5));
      org.junit.Assert.fail();
    } catch (IllegalArgumentException expected) {
      assertEquals("Invalid EC point", expected.getMessage());
    }
  }

  @Test
  public void genericCurvesStillWork() {
    // secp256r1 is unrelated to the SM2 limb code and exercises the BigInteger route.
    BigInteger p =
        new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
    BigInteger a = p.subtract(val(3));
    BigInteger b =
        new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
    BigInteger gx =
        new BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16);
    BigInteger gy =
        new BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16);
    BigInteger n =
        new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
    for (AbstractECMultiplier m :
        new AbstractECMultiplier[] {new DoubleAndAddMultiplier(), new WNAFMultiplier()}) {
      FpCurve curve = new FpCurve(m, p, a, b);
      assertFalse(curve.isSm2());
      AbstractECPoint g = curve.createPoint(gx, gy);
      assertTrue(g.multiply(n).isInfinity());
      AbstractECPoint two = g.multiply(val(2));
      assertEquals(
          new BigInteger("7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978", 16),
          two.getXCoord().toBigInteger());
      assertEquals(g.twice().getXCoord(), two.getXCoord());
      AbstractECPoint seven = g.multiply(val(7));
      assertEquals(seven.getXCoord(), g.multiply(n.add(val(7)).mod(n)).getXCoord());
      assertEquals(g.getXCoord(), g.multiply(val(3)).add(g.multiply(val(2)).negate()).getXCoord());
      // Repeated use hits the per-point tables; mixing multipliers on one point stays correct.
      assertEquals(seven.getXCoord(), g.multiply(val(7)).getXCoord());
      assertEquals(seven.getXCoord(), new WNAFMultiplier().multiply(g, val(7)).getXCoord());
      assertEquals(seven.getXCoord(), new DoubleAndAddMultiplier().multiply(g, val(7)).getXCoord());
      BigInteger wide = BigInteger.ONE.shiftLeft(200).add(val(7));
      assertEquals(
          new DoubleAndAddMultiplier().multiply(g, wide).getXCoord(),
          new WNAFMultiplier().multiply(g, wide).getXCoord());
    }
  }
}
