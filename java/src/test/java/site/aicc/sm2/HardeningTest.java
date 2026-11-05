package site.aicc.sm2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Field;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.Test;
import site.aicc.sm2.ec.AbstractECCurve;
import site.aicc.sm2.ec.AbstractECPoint;
import site.aicc.sm2.ec.DoubleAndAddMultiplier;
import site.aicc.sm2.ec.FpCurve;
import site.aicc.sm2.keygen.ECKeyPair;
import site.aicc.sm2.keygen.ECKeyPairGenerator;
import site.aicc.sm2.keygen.ECPrivateKey;
import site.aicc.sm2.keygen.ECPublicKey;
import site.aicc.sm2.util.ConvertUtil;
import site.aicc.sm2.util.SystemRandom;
import site.aicc.sm3.SM3;
import site.aicc.sm4.SM4;

/** Failure behaviour, limits and concurrency of the public API. */
public class HardeningTest {
  private static final BigInteger N =
      new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16);
  private static final BigInteger NM1 = N.subtract(BigInteger.ONE);
  private static final BigInteger D_A = new BigInteger("6FCBA2EF9AE0AB902BC3BDE3FF915D44", 16);
  private static final BigInteger R_A = new BigInteger("83A2C9C8B96E5AF70BD480B472409A9A", 16);
  private static final BigInteger D_B = new BigInteger("5E35D7D3F3C54DBAC72E61819E730B01", 16);
  private static final BigInteger R_B = new BigInteger("33FE21940342161C55619C4A0C060293", 16);

  private static void rejected(org.junit.function.ThrowingRunnable call) {
    assertThrows(IllegalArgumentException.class, call);
  }

  // ---------------------------------------------------------------- random source

  private static final class FixedRandom extends SecureRandom {
    private static final long serialVersionUID = 1L;
    private final transient byte fill;

    FixedRandom(int fill) {
      this.fill = (byte) fill;
    }

    @Override
    public void nextBytes(byte[] bytes) {
      Arrays.fill(bytes, fill);
    }
  }

  private static final class FailingRandom extends SecureRandom {
    private static final long serialVersionUID = 1L;

    @Override
    public void nextBytes(byte[] bytes) {
      throw new IllegalStateException("device unavailable");
    }
  }

  @Test
  public void brokenRandomSourcesFailCleanly() {
    SM2Initializer init = SM2.getSM2Initializer();
    ECKeyPairGenerator generator = new ECKeyPairGenerator();
    AbstractECCurve curve = init.getCurve();
    AbstractECPoint g = init.getG();
    DoubleAndAddMultiplier m = new DoubleAndAddMultiplier();
    for (SecureRandom bad :
        new SecureRandom[] {new FixedRandom(0), new FixedRandom(0xFF), new FailingRandom()}) {
      IllegalStateException e =
          assertThrows(
              IllegalStateException.class, () -> generator.getECKeyPair(m, curve, g, N, bad));
      assertEquals("Secure random source failed", e.getMessage());
    }
    // A constant in range is a valid scalar: the generator cannot tell, and must not loop.
    ECKeyPair pair = generator.getECKeyPair(m, curve, g, N, new FixedRandom(0x11));
    assertEquals(
        new BigInteger("1111111111111111111111111111111111111111111111111111111111111111", 16),
        pair.getBIPriKey());
    assertTrue(SystemRandom.get() != null);
  }

  @Test
  public void generatorRejectsParametersThatWouldLoopForever() {
    SM2Initializer init = SM2.getSM2Initializer();
    ECKeyPairGenerator generator = new ECKeyPairGenerator();
    DoubleAndAddMultiplier m = new DoubleAndAddMultiplier();
    for (BigInteger n :
        new BigInteger[] {BigInteger.ZERO, BigInteger.ONE, BigInteger.valueOf(2), null}) {
      rejected(() -> generator.getECKeyPair(m, init.getCurve(), init.getG(), n, null));
    }
    rejected(() -> generator.getECKeyPair(null, init.getCurve(), init.getG(), N, null));
    rejected(() -> generator.getECKeyPair(m, null, init.getG(), N, null));
    rejected(() -> generator.getECKeyPair(m, init.getCurve(), null, N, null));
  }

  @Test
  public void generatedScalarsAreNotFiltered() {
    // The first draw of a constant source is returned as is: no shape, weight or sign filter.
    SM2Initializer init = SM2.getSM2Initializer();
    ECKeyPairGenerator generator = new ECKeyPairGenerator();
    DoubleAndAddMultiplier m = new DoubleAndAddMultiplier();
    assertEquals(
        BigInteger.ONE
            .shiftLeft(256)
            .divide(BigInteger.valueOf(255))
            .multiply(BigInteger.valueOf(0x80)),
        generator
            .getECKeyPair(m, init.getCurve(), init.getG(), N, new FixedRandom(0x80))
            .getBIPriKey());
    assertEquals(
        BigInteger.ONE.shiftLeft(256).divide(BigInteger.valueOf(255)),
        generator
            .getECKeyPair(m, init.getCurve(), init.getG(), N, new FixedRandom(0x01))
            .getBIPriKey());
  }

  // ---------------------------------------------------------------- key exchange

  private static AbstractECPoint pub(BigInteger d) {
    return SM2.getPublicKey(d);
  }

  private static SM2KeySwapParams sideB(int len) {
    return SM2.getSb(len, pub(D_A), pub(R_A), pub(D_B), D_B, pub(R_B), R_B, "a", "b");
  }

  @Test
  public void keyLengthBounds() {
    for (int bad : new int[] {0, -1, Integer.MIN_VALUE, (1 << 20) + 1, Integer.MAX_VALUE}) {
      SM2KeySwapParams r = sideB(bad);
      assertFalse(r.isSuccess());
      assertNull(r.getKb());
    }
    assertEquals(2, sideB(1).getKb().length());
    assertEquals(2 << 20, sideB(1 << 20).getKb().length());
  }

  @Test
  public void keyExchangeValidatesEveryPeerValue() {
    AbstractECPoint good = pub(D_A);
    AbstractECCurve curve = good.getCurve();
    AbstractECPoint off = curve.createPoint(good.getXCoord().toBigInteger(), BigInteger.ONE);
    AbstractECPoint[] badPoints = {off, curve.getInfinity(), null};
    byte[] sb = ConvertUtil.hexToByte(sideB(16).getSb());
    AbstractECPoint pA = pub(D_A);
    AbstractECPoint rA = pub(R_A);
    AbstractECPoint pB = pub(D_B);
    AbstractECPoint rB = pub(R_B);
    for (AbstractECPoint bad : badPoints) {
      assertFalse(SM2.getSb(16, bad, rA, pB, D_B, rB, R_B, "a", "b").isSuccess());
      assertFalse(SM2.getSb(16, pA, bad, pB, D_B, rB, R_B, "a", "b").isSuccess());
      assertFalse(SM2.getSb(16, pA, rA, bad, D_B, rB, R_B, "a", "b").isSuccess());
      assertFalse(SM2.getSb(16, pA, rA, pB, D_B, bad, R_B, "a", "b").isSuccess());
      assertFalse(SM2.getSa(16, bad, rB, pA, D_A, rA, R_A, "a", "b", sb).isSuccess());
      assertFalse(SM2.getSa(16, pB, bad, pA, D_A, rA, R_A, "a", "b", sb).isSuccess());
      assertFalse(SM2.getSa(16, pB, rB, bad, D_A, rA, R_A, "a", "b", sb).isSuccess());
      assertFalse(SM2.getSa(16, pB, rB, pA, D_A, bad, R_A, "a", "b", sb).isSuccess());
    }
    for (BigInteger bad :
        new BigInteger[] {null, BigInteger.ZERO, BigInteger.ONE.negate(), NM1, N}) {
      assertFalse(SM2.getSb(16, pA, rA, pB, bad, rB, R_B, "a", "b").isSuccess());
      assertFalse(SM2.getSb(16, pA, rA, pB, D_B, rB, bad, "a", "b").isSuccess());
      assertFalse(SM2.getSa(16, pB, rB, pA, bad, rA, R_A, "a", "b", sb).isSuccess());
      assertFalse(SM2.getSa(16, pB, rB, pA, D_A, rA, bad, "a", "b", sb).isSuccess());
    }
    for (byte[] bad : new byte[][] {null, {}, new byte[31], new byte[33], new byte[32]}) {
      assertFalse(SM2.getSa(16, pB, rB, pA, D_A, rA, R_A, "a", "b", bad).isSuccess());
    }
    char[] longId = new char[8192];
    Arrays.fill(longId, 'i');
    String tooLong = new String(longId);
    assertFalse(SM2.getSb(16, pA, rA, pB, D_B, rB, R_B, tooLong, "b").isSuccess());
    assertFalse(SM2.getSb(16, pA, rA, pB, D_B, rB, R_B, "a", tooLong).isSuccess());
    assertFalse(SM2.getSb(16, pA, rA, pB, D_B, rB, R_B, null, "b").isSuccess());
    assertFalse(SM2.getSb(16, pA, rA, pB, D_B, rB, R_B, "\uD800", "b").isSuccess());
    assertTrue(SM2.getSa(16, pB, rB, pA, D_A, rA, R_A, "a", "b", sb).isSuccess());
    SM2KeySwapParams b = sideB(16);
    assertFalse(SM2.checkSa(null, b.getZa(), b.getZb(), rA, rB, new byte[32]));
    assertFalse(SM2.checkSa(curve.getInfinity(), b.getZa(), b.getZb(), rA, rB, new byte[32]));
    assertFalse(SM2.checkSa(b.getV(), null, b.getZb(), rA, rB, new byte[32]));
    assertFalse(SM2.checkSa(b.getV(), b.getZa(), b.getZb(), null, rB, new byte[32]));
    assertFalse(SM2.checkSa(b.getV(), b.getZa(), b.getZb(), rA, rB, null));
    assertFalse(SM2.checkSa(b.getV(), b.getZa(), b.getZb(), rA, rB, new byte[0]));
    assertFalse(SM2.checkSa(b.getV(), b.getZa(), b.getZb(), rA, rB, new byte[31]));
    assertFalse(SM2.checkSa(b.getV(), b.getZa(), b.getZb(), rA, rB, new byte[32]));
  }

  /** Own public values that do not belong to the private values are refused on both sides. */
  @Test
  public void keyExchangeRejectsMismatchedOwnKeys() {
    AbstractECPoint pA = pub(D_A);
    AbstractECPoint rA = pub(R_A);
    AbstractECPoint pB = pub(D_B);
    AbstractECPoint rB = pub(R_B);
    AbstractECPoint other = pub(BigInteger.valueOf(12345));
    assertFalse(SM2.getSb(16, pA, rA, other, D_B, rB, R_B, "a", "b").isSuccess());
    assertFalse(SM2.getSb(16, pA, rA, pB, D_B, other, R_B, "a", "b").isSuccess());
    byte[] sb = ConvertUtil.hexToByte(sideB(16).getSb());
    assertFalse(SM2.getSa(16, pB, rB, other, D_A, rA, R_A, "a", "b", sb).isSuccess());
    assertFalse(SM2.getSa(16, pB, rB, pA, D_A, other, R_A, "a", "b", sb).isSuccess());
    assertTrue(SM2.getSa(16, pB, rB, pA, D_A, rA, R_A, "a", "b", sb).isSuccess());
  }

  /**
   * Interop regression (BouncyCastle 1.86): a 1-byte key that happens to be 00 is a valid result of
   * the key exchange, not an error. A has d = ra = n - 2, B has d = 3.
   */
  @Test
  public void keyExchangeAcceptsAnAllZeroDerivedKey() {
    BigInteger nMinus2 = N.subtract(BigInteger.valueOf(2));
    BigInteger dB = BigInteger.valueOf(3);
    BigInteger rb =
        new BigInteger("03482a3222c8c7ed544e7410e18ea9f9f4f282e8cbddd9431c66664ea966d81b", 16);
    String idA = "ALICE123@YAHOO.COM";
    char[] repeated = new char[70];
    String idB = new String(repeated).replace("\0", "id-");
    AbstractECPoint pA = pub(nMinus2);
    AbstractECPoint pB = pub(dB);
    AbstractECPoint rB = pub(rb);
    assertEquals(
        "0456cefd60d7c87c000d58ef57fa73ba4d9c0dfa08c08a7331495c2e1da3f2bd52ce481818337e760997aca31f07150e429217b3e6d093718f9087f2c568f5dc3c",
        ConvertUtil.byteToHex(pA.getEncoded()));
    SM2KeySwapParams b = SM2.getSb(1, pA, pA, pB, dB, rB, rb, idA, idB);
    assertTrue(b.getMessage(), b.isSuccess());
    assertEquals("00", b.getKb());
    SM2KeySwapParams a =
        SM2.getSa(1, pB, rB, pA, nMinus2, pA, nMinus2, idA, idB, ConvertUtil.hexToByte(b.getSb()));
    assertTrue(a.getMessage(), a.isSuccess());
    assertEquals("00", a.getKa());
    assertTrue(
        SM2.checkSa(b.getV(), b.getZa(), b.getZb(), pA, rB, ConvertUtil.hexToByte(a.getSa())));
  }

  /** Coordinates with leading zero bytes must hash fixed-width on both sides. */
  @Test
  public void sharedPointsWithShortCoordinatesAgree() {
    Random r = new Random(21);
    int shortSeen = 0;
    for (int i = 0; i < 4000 && shortSeen < 4; i++) {
      BigInteger da = new BigInteger(255, r).add(BigInteger.ONE);
      BigInteger ra = new BigInteger(255, r).add(BigInteger.ONE);
      SM2KeySwapParams b = SM2.getSb(16, pub(da), pub(ra), pub(D_B), D_B, pub(R_B), R_B, "a", "b");
      assertTrue(b.isSuccess());
      AbstractECPoint v = b.getV();
      if (v.getXCoord().toBigInteger().bitLength() <= 248
          || v.getYCoord().toBigInteger().bitLength() <= 248) {
        shortSeen++;
      }
      SM2KeySwapParams a =
          SM2.getSa(
              16,
              pub(D_B),
              pub(R_B),
              pub(da),
              da,
              pub(ra),
              ra,
              "a",
              "b",
              ConvertUtil.hexToByte(b.getSb()));
      assertTrue(a.isSuccess());
      assertEquals(b.getKb(), a.getKa());
    }
    assertTrue("no short coordinate in 4000 exchanges", shortSeen > 0);
  }

  // ---------------------------------------------------------------- curves and points

  private static final BigInteger P =
      new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16);
  private static final BigInteger A = P.subtract(BigInteger.valueOf(3));
  private static final BigInteger B =
      new BigInteger("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16);

  @Test
  public void curveEqualsTerminatesAndComparesParameters() {
    DoubleAndAddMultiplier m = new DoubleAndAddMultiplier();
    FpCurve one = new FpCurve(m, P, A, B);
    FpCurve two = new FpCurve(m, P, A, B);
    FpCurve other = new FpCurve(m, P, A, B.add(BigInteger.ONE));
    assertEquals(one, two);
    assertEquals(one.hashCode(), two.hashCode());
    assertNotEquals(one, other);
    assertNotEquals(one, null);
    assertNotEquals(one, "curve");
  }

  @Test
  public void fieldModuliThatWouldHangAreRejected() {
    DoubleAndAddMultiplier m = new DoubleAndAddMultiplier();
    BigInteger one = BigInteger.ONE;
    for (BigInteger q :
        new BigInteger[] {
          null,
          BigInteger.ZERO,
          one.negate(),
          BigInteger.valueOf(4),
          BigInteger.valueOf(15),
          P.add(BigInteger.valueOf(2)),
          one.shiftLeft(4096).add(one)
        }) {
      rejected(() -> new FpCurve(m, q, one, one));
    }
    rejected(() -> new FpCurve(null, P, A, B));
    rejected(() -> new FpCurve(m, P, null, B));
    rejected(() -> new FpCurve(m, P, P, B));
    rejected(() -> new FpCurve(m, P, A, B, BigInteger.ZERO, null));
    rejected(() -> new FpCurve(m, P, A, B, null, BigInteger.ZERO));
  }

  @Test
  public void unboundedLoopsAndForeignElementsAreRejected() {
    AbstractECPoint p = pub(D_A);
    rejected(() -> p.timesPow2(Integer.MAX_VALUE));
    rejected(() -> p.timesPow2(-1));
    rejected(() -> p.add(null));
    rejected(() -> p.subtract(null));
    rejected(() -> p.twicePlus(null));
    rejected(() -> p.multiply(null));
    FpCurve other =
        new FpCurve(
            new DoubleAndAddMultiplier(), BigInteger.valueOf(23), BigInteger.ONE, BigInteger.ONE);
    AbstractECPoint foreign = other.createPoint(BigInteger.ZERO, BigInteger.ONE);
    rejected(() -> p.add(foreign));
    rejected(() -> p.getXCoord().add(foreign.getXCoord()));
    rejected(() -> p.getXCoord().multiply(null));
    AbstractECPoint off = p.getCurve().createPoint(BigInteger.ONE, BigInteger.ONE);
    rejected(() -> off.multiply(BigInteger.TEN));
    rejected(() -> p.multiply(BigInteger.ONE.shiftLeft(256)));
    rejected(() -> new ECKeyPair(null, null));
    ECPublicKey publicKey = new ECPublicKey(p);
    ECPrivateKey privateKey = new ECPrivateKey(D_A);
    rejected(() -> new ECKeyPair(privateKey, publicKey));
    rejected(() -> new ECPrivateKey(null));
    rejected(() -> new ECPrivateKey(BigInteger.ZERO));
    rejected(() -> new ECPublicKey(null));
    rejected(() -> new ECPublicKey(off));
    rejected(() -> new ECPublicKey(p.getCurve().getInfinity()));
  }

  @Test
  public void domainParametersAreValidated() {
    String[] good = {
      P.toString(16),
      A.toString(16),
      B.toString(16),
      N.toString(16),
      "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
      "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"
    };
    assertTrue(new SM2Initializer(good, new DoubleAndAddMultiplier()).isStandardDomain());
    rejected(() -> new SM2Initializer(null, new DoubleAndAddMultiplier()));
    rejected(() -> new SM2Initializer(good, null));
    rejected(() -> new SM2Initializer(new String[5], new DoubleAndAddMultiplier()));
    for (int i = 0; i < good.length; i++) {
      for (String bad : new String[] {null, "", "zz", "-1", "+1", "1", "F" + good[i]}) {
        String[] copy = good.clone();
        copy[i] = bad;
        // a and b may be anything below p as far as parsing goes, so a value of 1 changes the
        // curve,
        // which G then fails to lie on.
        rejected(() -> new SM2Initializer(copy, new DoubleAndAddMultiplier()));
      }
    }
    // A singular curve, whose logarithms are easy: the cusp y^2 = x^3 with n = p.
    String[] cusp = {good[0], "0", "0", good[0], "4", "8"};
    rejected(() -> new SM2Initializer(cusp, new DoubleAndAddMultiplier()));
    DoubleAndAddMultiplier curveMultiplier = new DoubleAndAddMultiplier();
    rejected(() -> new FpCurve(curveMultiplier, P, BigInteger.ZERO, BigInteger.ZERO));
    // a = -3, b = 2 has discriminant -108 + 108 = 0: a node.
    rejected(() -> new FpCurve(curveMultiplier, P, A, BigInteger.valueOf(2)));
    // Anomalous: n = p.
    String[] anomalous = good.clone();
    anomalous[3] = good[0];
    rejected(() -> new SM2Initializer(anomalous, new DoubleAndAddMultiplier()));
    // G of the wrong order: the group order is not n.
    String[] wrongOrder = good.clone();
    wrongOrder[3] = N.nextProbablePrime().toString(16);
    rejected(() -> new SM2Initializer(wrongOrder, new DoubleAndAddMultiplier()));
  }

  // ---------------------------------------------------------------- SM3 limits and hygiene

  @Test
  public void sm3RejectsMessagesPastTheLengthField() throws Exception {
    SM3 sm3 = new SM3();
    Field field = SM3.class.getDeclaredField("messageBytes");
    field.setAccessible(true);
    long max = (1L << 61) - 1;
    field.setLong(sm3, max - 1);
    sm3.update((byte) 1);
    rejected(() -> sm3.update((byte) 1));
    rejected(() -> sm3.update(new byte[1], 0, 1));
    assertEquals(max, field.getLong(sm3));
  }

  /** The 64-bit length is what is written: a message of 2^32 bits differs from an empty one. */
  @Test
  public void sm3LengthFieldIsSixtyFourBits() throws Exception {
    SM3 sm3 = new SM3();
    Field field = SM3.class.getDeclaredField("messageBytes");
    field.setAccessible(true);
    field.setLong(sm3, 1L << 29);
    String withLength = sm3.finish().getHashCode();
    assertNotEquals(new SM3().finish().getHashCode(), withLength);
  }

  @Test
  public void sm3ClearsInputAfterFinishing() throws Exception {
    SM3 sm3 = new SM3();
    byte[] secret = new byte[100];
    Arrays.fill(secret, (byte) 0x5A);
    sm3.update(secret, 0, secret.length);
    sm3.finish();
    Field buffer = SM3.class.getDeclaredField("blockBuffer");
    buffer.setAccessible(true);
    assertTrue(Arrays.equals(new byte[64], (byte[]) buffer.get(sm3)));
    Field schedule = SM3.class.getDeclaredField("schedule");
    schedule.setAccessible(true);
    assertTrue(Arrays.equals(new int[68], (int[]) schedule.get(sm3)));
  }

  @Test
  public void midstateCopiesAreIndependentAndComplete() {
    byte[] data = new byte[150];
    new Random(4).nextBytes(data);
    for (int split = 0; split <= data.length; split += 7) {
      SM3 first = new SM3().update(data, 0, split);
      SM3 copy = new SM3();
      copy.update(new byte[9], 0, 9);
      copy.copyFrom(first);
      copy.update(data, split, data.length - split);
      byte[] out = new byte[40];
      copy.finishInto(out, 8);
      first.update(data, split, data.length - split);
      assertEquals(
          ConvertUtil.byteToHex(new SM3().update(data, 0, data.length).finish().getHashBytes()),
          ConvertUtil.byteToHex(Arrays.copyOfRange(out, 8, 40)));
      assertEquals(
          ConvertUtil.byteToHex(new SM3().update(data, 0, data.length).finish().getHashBytes()),
          ConvertUtil.byteToHex(first.finish().getHashBytes()));
    }
  }

  // ---------------------------------------------------------------- errors leak nothing

  @Test
  public void errorsDoNotQuoteSecrets() throws Exception {
    String secretHex = "feedfacecafebeef";
    String badKey = secretHex + secretHex + secretHex + "feedfacecafebeez";
    for (org.junit.function.ThrowingRunnable call :
        Arrays.<org.junit.function.ThrowingRunnable>asList(
            () -> SM2.sm2Sign("id", "m", badKey),
            () -> SM2.sm2Decrypt("00", badKey),
            () -> new SM4().setKey(badKey, "00", true),
            () -> ConvertUtil.hexToByte(badKey))) {
      Throwable t = assertThrows(IllegalArgumentException.class, call);
      assertFalse(t.getMessage().contains("feed"));
      assertFalse(t.getMessage().contains("beez"));
    }
    ECPrivateKey key = new ECPrivateKey(D_A);
    assertFalse(key.toString().toLowerCase().contains(D_A.toString(16)));
    ECKeyPair pair = SM2.genSM2KeyPair();
    assertFalse(pair.toString().contains(pair.getHexPriKey()));
    assertTrue(SM2KdfUtil.isAllZero(new byte[8], 0, 8));
    assertFalse(SM2KdfUtil.isAllZero(new byte[] {0, 0, 0, 1}, 0, 4));
    assertTrue(SM2KdfUtil.isAllZero(new byte[] {1, 0, 0, 1}, 1, 2));
  }

  /** C1 || C3 with a correct C3 over an empty C2 is still rejected: C2 must not be empty. */
  @Test
  public void authenticCiphertextWithoutC2IsRejected() {
    AbstractECPoint c1 = pub(R_A);
    AbstractECPoint shared = pub(D_A).multiply(R_A);
    byte[] x = shared.getXCoord().getEncoded();
    byte[] y = shared.getYCoord().getEncoded();
    byte[] c3 = new SM3().update(x, 0, 32).update(y, 0, 32).finish().getHashBytes();
    String cipher = ConvertUtil.byteToHex(c1.getEncoded()) + ConvertUtil.byteToHex(c3);
    String key = ConvertUtil.byteToHex(ConvertUtil.bigIntegerTo32Bytes(D_A));
    rejected(() -> SM2.sm2Decrypt(cipher, key));
  }

  // ---------------------------------------------------------------- SM4 decoding

  /** The bad-padding path runs the decoder over the whole buffer, exactly as the good path does. */
  @Test
  public void sm4DecodesTheWholeBufferOnEveryPaddingOutcome() throws Exception {
    Field sink = SM4.class.getDeclaredField("decodedLengthSink");
    sink.setAccessible(true);
    SM4 sm4 =
        new SM4()
            .setKey("0123456789abcdeffedcba9876543210", "000102030405060708090a0b0c0d0e0f", true);
    char[] text = new char[47];
    Arrays.fill(text, 'm');
    String good = sm4.encrypt(new String(text));
    // Without its last block the ciphertext ends in plaintext bytes 'm': invalid padding.
    String bad = sm4.encrypt(new String(text) + "m").substring(0, 96);
    assertEquals(new String(text), sm4.decrypt(good));
    assertEquals(48, sink.getInt(null));
    sink.setInt(null, 0);
    rejected(() -> sm4.decrypt(bad));
    assertEquals(48, sink.getInt(null));
  }

  /** The decoded prefix must equal decoding the plaintext alone, for any plaintext bytes. */
  @Test
  public void sm4PrefixDecodingMatchesDirectDecoding() {
    Random r = new Random(23);
    int[] interesting = {
      0x00, 0x41, 0x7F, 0x80, 0xBF, 0xC0, 0xC2, 0xDF, 0xE0, 0xE4, 0xED, 0xEF, 0xF0, 0xF4, 0xF5, 0xFF
    };
    byte[] plain = new byte[47];
    for (int a : interesting) {
      for (int b : interesting) {
        for (int c : interesting) {
          for (int d : interesting) {
            plain[plain.length - 4] = (byte) a;
            plain[plain.length - 3] = (byte) b;
            plain[plain.length - 2] = (byte) c;
            plain[plain.length - 1] = (byte) d;
            checkPrefixDecoding(plain, 1);
          }
        }
      }
    }
    for (int i = 0; i < 20000; i++) {
      int pad = 1 + r.nextInt(16);
      byte[] random = new byte[16 + 16 - pad];
      r.nextBytes(random);
      checkPrefixDecoding(random, pad);
    }
  }

  private static void checkPrefixDecoding(byte[] plain, int pad) {
    byte[] padded = Arrays.copyOf(plain, plain.length + pad);
    Arrays.fill(padded, plain.length, padded.length, (byte) pad);
    String whole = new String(padded, StandardCharsets.UTF_8);
    assertEquals(
        new String(plain, StandardCharsets.UTF_8), whole.substring(0, whole.length() - pad));
  }

  @Test
  public void sm4DecryptToBytesKeepsBinaryPlaintext() throws Exception {
    SM4 sm4 =
        new SM4()
            .setKey("0123456789abcdeffedcba9876543210", "000102030405060708090a0b0c0d0e0f", true);
    String ct = sm4.encrypt("héllo");
    assertTrue(Arrays.equals("héllo".getBytes(StandardCharsets.UTF_8), sm4.decryptToBytes(ct)));
    rejected(() -> sm4.decryptToBytes(ct.toUpperCase()));
    rejected(() -> sm4.decryptToBytes(ct.substring(0, 16)));
    rejected(() -> sm4.decryptToBytes(null));
    rejected(() -> new SM4().decryptToBytes(ct));
  }

  // ---------------------------------------------------------------- non-injective text

  @Test
  public void unpairedSurrogatesCannotCollideWithAQuestionMark() throws Exception {
    assertEquals(
        ConvertUtil.byteToHex("😀".getBytes(StandardCharsets.UTF_8)),
        ConvertUtil.byteToHex(ConvertUtil.utf8Bytes("😀")));
    rejected(() -> ConvertUtil.utf8Bytes("\uD83D"));
    rejected(() -> ConvertUtil.utf8Bytes("\uDE00\uD83D"));
    rejected(() -> ConvertUtil.utf8Bytes("a\uD83Db"));
    rejected(() -> ConvertUtil.utf8Bytes(null));
    String key = ConvertUtil.byteToHex(ConvertUtil.bigIntegerTo32Bytes(D_A));
    String pub = ConvertUtil.byteToHex(pub(D_A).getEncoded());
    String signature = SM2.sm2Sign("id", "?", key);
    assertFalse(SM2.sm2VerifySign("id", signature, "\uD800", pub));
  }

  // ---------------------------------------------------------------- concurrency

  /** Two threads rekey one SM4 object while others encrypt: only whole key states are ever used. */
  @Test
  public void sharedSm4NeverMixesKeyAndIv() throws Exception {
    String key1 = "00112233445566778899aabbccddeeff";
    String iv1 = "0f0e0d0c0b0a09080706050403020100";
    String key2 = "ffeeddccbbaa99887766554433221100";
    String iv2 = "101112131415161718191a1b1c1d1e1f";
    String one = new SM4().setKey(key1, iv1, true).encrypt("concurrency");
    String two = new SM4().setKey(key2, iv2, true).encrypt("concurrency");
    SM4 shared = new SM4().setKey(key1, iv1, true);
    ExecutorService pool = Executors.newFixedThreadPool(4);
    List<Future<Integer>> results = new ArrayList<>();
    for (int t = 0; t < 2; t++) {
      results.add(
          pool.submit(() -> {
            for (int i = 0; i < 20000; i++) {
              shared.setKey(i % 2 == 0 ? key1 : key2, i % 2 == 0 ? iv1 : iv2, true);
            }
            return 0;
          }));
      results.add(
          pool.submit(() -> {
            int bad = 0;
            for (int i = 0; i < 20000; i++) {
              String c = shared.encrypt("concurrency");
              if (!c.equals(one) && !c.equals(two)) {
                bad++;
              }
            }
            return bad;
          }));
    }
    for (Future<Integer> f : results) {
      assertEquals(Integer.valueOf(0), f.get());
    }
    pool.shutdown();
  }

  /** The lazily built tables and shared curve must be safe from a cold start and under load. */
  @Test
  public void parallelSm2OperationsAgree() throws Exception {
    String key = ConvertUtil.byteToHex(ConvertUtil.bigIntegerTo32Bytes(D_A));
    String pub = ConvertUtil.byteToHex(pub(D_A).getEncoded());
    AbstractECPoint shared = pub(D_B);
    String expected = ConvertUtil.byteToHex(shared.multiply(D_A).getEncoded());
    ExecutorService pool = Executors.newFixedThreadPool(6);
    List<Future<Boolean>> results = new ArrayList<>();
    for (int t = 0; t < 6; t++) {
      results.add(
          pool.submit(
              (Callable<Boolean>)
                  () -> {
                    for (int i = 0; i < 150; i++) {
                      String m = "message " + i;
                      if (!SM2.sm2VerifySign("id", SM2.sm2Sign("id", m, key), m, pub)
                          || !m.equals(SM2.sm2Decrypt(SM2.sm2Encrypt(m, pub), key))
                          || !expected.equals(
                              ConvertUtil.byteToHex(shared.multiply(D_A).getEncoded()))) {
                        return false;
                      }
                    }
                    return true;
                  }));
    }
    for (Future<Boolean> f : results) {
      assertTrue(f.get());
    }
    pool.shutdown();
  }

  // ---------------------------------------------------------------- round trips

  @Test
  public void roundTripProperty() throws Exception {
    Random r = new Random(22);
    for (int i = 0; i < 400; i++) {
      ECKeyPair pair = SM2.genSM2KeyPair();
      char[] text = new char[r.nextInt(600)];
      for (int j = 0; j < text.length; j++) {
        text[j] = (char) (0x20 + r.nextInt(0x4E00));
      }
      String message = new String(text);
      String id = Integer.toString(r.nextInt());
      String signature = SM2.sm2Sign(id, message, pair.getHexPriKey());
      assertTrue(SM2.sm2VerifySign(id, signature, message, pair.getHexPubKey()));
      if (message.isEmpty()) {
        rejected(() -> SM2.sm2Encrypt(message, pair.getHexPubKey()));
      } else {
        assertEquals(
            message,
            SM2.sm2Decrypt(SM2.sm2Encrypt(message, pair.getHexPubKey()), pair.getHexPriKey()));
      }
      byte[] key = new byte[16];
      byte[] iv = new byte[16];
      r.nextBytes(key);
      r.nextBytes(iv);
      SM4 sm4 = new SM4().setKey(ConvertUtil.byteToHex(key), ConvertUtil.byteToHex(iv), true);
      assertEquals(message, sm4.decrypt(sm4.encrypt(message)));
    }
  }
}
