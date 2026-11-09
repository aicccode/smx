package site.aicc.fuzz;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Executable;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import site.aicc.sm2.SM2;
import site.aicc.sm2.SM2Cipher;
import site.aicc.sm2.SM2Initializer;
import site.aicc.sm2.SM2KeySwap;
import site.aicc.sm2.SM2KeySwapParams;
import site.aicc.sm2.ec.AbstractECCurve;
import site.aicc.sm2.ec.AbstractECElement;
import site.aicc.sm2.ec.AbstractECMultiplier;
import site.aicc.sm2.ec.AbstractECPoint;
import site.aicc.sm2.ec.DoubleAndAddMultiplier;
import site.aicc.sm2.ec.FpCurve;
import site.aicc.sm2.ec.FpElement;
import site.aicc.sm2.ec.FpPoint;
import site.aicc.sm2.ec.Sm2Engine;
import site.aicc.sm2.ec.WNAFMultiplier;
import site.aicc.sm2.keygen.ECKey;
import site.aicc.sm2.keygen.ECKeyPair;
import site.aicc.sm2.keygen.ECKeyPairGenerator;
import site.aicc.sm2.keygen.ECPrivateKey;
import site.aicc.sm2.keygen.ECPublicKey;
import site.aicc.sm2.util.ConvertUtil;
import site.aicc.sm2.util.SystemRandom;
import site.aicc.sm3.SM3;
import site.aicc.sm4.SM4;
import site.aicc.sm9.SM9;
import site.aicc.sm9.SM9CipherMode;
import site.aicc.sm9.SM9Encapsulation;
import site.aicc.sm9.SM9ExchangeResult;
import site.aicc.sm9.SM9KeyPair;

/**
 * Seeded malformed-input harness over the whole public surface, found by reflection: every public
 * or protected method and public constructor receives arguments drawn from valid values, mutated
 * values and extremes. It asserts only the failure convention: {@link IllegalArgumentException} for
 * bad input, or {@link IllegalStateException} when a hostile random source is among the arguments.
 * Any other exception or error is a finding.
 *
 * <p>Run: {@code java -cp target/classes:target/test-classes site.aicc.fuzz.PublicApiFuzz
 * [casesPerMethod] [threads] [seed]}
 */
public final class PublicApiFuzz {
  private static final BigInteger N =
      new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16);
  private static final BigInteger P =
      new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16);
  private static final String[] PARAMS = {
    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
    "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
    "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
    "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"
  };
  private static final String[] P256_PARAMS = {
    "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
    "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
    "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
    "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
  };

  private static final Class<?>[] TARGETS = {
    SM2.class,
    SM2Cipher.class,
    SM2KeySwap.class,
    SM2Initializer.class,
    SM2KeySwapParams.class,
    SM3.class,
    SM4.class,
    ConvertUtil.class,
    SystemRandom.class,
    Sm2Engine.class,
    FpCurve.class,
    AbstractECCurve.class,
    FpElement.class,
    AbstractECElement.class,
    FpPoint.class,
    AbstractECPoint.class,
    DoubleAndAddMultiplier.class,
    WNAFMultiplier.class,
    AbstractECMultiplier.class,
    ECKeyPair.class,
    ECKeyPairGenerator.class,
    ECPrivateKey.class,
    ECPublicKey.class,
    ECKey.class,
    SM9.class,
    SM9KeyPair.class,
    SM9Encapsulation.class,
    SM9ExchangeResult.class
  };

  /** Fixed SM9 keys (GB/T 38635.5 master keys) and values made with them, as seeds. */
  private static final String SM9_KS =
      "000130e78459d78545cb54c587e02cf480ce0b66340f319f348a1d5b1f2dc5f4";

  private static final String SM9_KE =
      "0001edee3778f441f8dea3d9fa0acc4e07ee36c93f9a08618af4ad85cede1c22";
  private static final String SM9_MPK_S = SM9.signMasterPublicKey(SM9_KS);
  private static final String SM9_MPK_E = SM9.encMasterPublicKey(SM9_KE);
  private static final String SM9_DS = SM9.genSignUserKey(SM9_KS, "Alice");
  private static final String SM9_DE = SM9.genEncUserKey(SM9_KE, "Bob");
  private static final SM9KeyPair SM9_PAIR = SM9.exchangeInit("Bob", SM9_MPK_E);
  private static final SM9Encapsulation SM9_KEM = SM9.encapsulate("Bob", SM9_MPK_E, 32);
  private static final SM9ExchangeResult SM9_RESULT =
      SM9.exchangeRespond(
          16,
          "Alice",
          "Bob",
          SM9_MPK_E,
          SM9.genEncUserKey(SM9_KE, "Bob".getBytes(java.nio.charset.StandardCharsets.UTF_8), 2),
          SM9_PAIR.getPrivateKey(),
          SM9_PAIR.getPublicKey(),
          SM9.exchangeInit("Alice", SM9_MPK_E).getPublicKey());

  private static final SM2Initializer STANDARD =
      new SM2Initializer(PARAMS, new DoubleAndAddMultiplier());
  private static final SM2Initializer CUSTOM =
      new SM2Initializer(P256_PARAMS, new DoubleAndAddMultiplier());
  private static final FpCurve CURVE =
      new FpCurve(
          new DoubleAndAddMultiplier(),
          P,
          new BigInteger(PARAMS[1], 16),
          new BigInteger(PARAMS[2], 16));
  private static final FpCurve WNAF_CURVE =
      new FpCurve(
          new WNAFMultiplier(), P, new BigInteger(PARAMS[1], 16), new BigInteger(PARAMS[2], 16));
  private static final FpCurve SMALL_CURVE =
      new FpCurve(
          new DoubleAndAddMultiplier(), BigInteger.valueOf(23), BigInteger.ONE, BigInteger.ONE);
  private static final BigInteger D =
      new BigInteger("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8", 16);
  private static final String D_HEX = D.toString(16);
  private static final String PUB_HEX =
      "0409f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020"
          + "ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13";
  private static final String SIG_HEX =
      "f5a03b0648d2c4630eeac513e1bb81a15944da3827d5b74143ac7eaceee720b3"
          + "h"
          + "b1b6aa29df212fd8763182bc0d421ca1bb9038fd1f7f42d4840b69c485bbc1aa";
  private static final String CT_HEX;
  private static final String[] SEEDS;

  static {
    try {
      CT_HEX = SM2.sm2Encrypt("fuzz seed", PUB_HEX);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
    SEEDS =
        new String[] {
          D_HEX,
          PUB_HEX,
          SIG_HEX,
          CT_HEX,
          "0123456789abcdeffedcba9876543210",
          "1234567812345678",
          "bd73e45045b9139bf5d9f533719cfcfd",
          "message digest",
          "sixteen byte key",
          PUB_HEX.substring(2),
          SM9_KS,
          SM9_MPK_S,
          SM9_MPK_E,
          SM9_DS,
          SM9_DE,
          SM9.sign("fuzz seed", SM9_DS, SM9_MPK_S),
          SM9.encrypt("fuzz seed", "Bob", SM9_MPK_E),
          SM9_KEM.getCiphertext(),
          SM9_PAIR.getPublicKey(),
          SM9_RESULT.getSb(),
          "Alice",
          "Bob"
        };
  }

  /** A generator whose output is constant or which throws. */
  private static final class HostileRandom extends SecureRandom {
    private static final long serialVersionUID = 1L;
    private final transient int mode;

    HostileRandom(int mode) {
      this.mode = mode;
    }

    @Override
    public void nextBytes(byte[] bytes) {
      if (mode < 0) {
        throw new IllegalStateException("device gone");
      }
      Arrays.fill(bytes, (byte) mode);
    }
  }

  private static String string(Random r) {
    switch (r.nextInt(12)) {
      case 0:
        return null;
      case 1:
        return "";
      case 2:
        return SEEDS[r.nextInt(SEEDS.length)];
      case 3:
      case 4:
      case 5:
        return mutate(SEEDS[r.nextInt(SEEDS.length)], r);
      case 6:
        return randomChars(r, r.nextInt(80), "0123456789abcdefABCDEF");
      case 7:
        return randomChars(r, r.nextInt(150), "0123456789abcdefgh+- zZé０٣𐀀");
      case 8:
        return randomChars(r, 64, "0123456789abcdef");
      case 9:
        return randomChars(r, 130, "0123456789abcdef");
      case 10:
        return randomChars(r, 129, "0123456789abcdefh");
      default:
        return r.nextInt(50) == 0
            ? randomChars(r, 20000, "abcdef012")
            : randomChars(r, r.nextInt(40), "\u0000\u007f\u0080￿éa");
    }
  }

  private static String randomChars(Random r, int len, String alphabet) {
    char[] c = new char[len];
    for (int i = 0; i < len; i++) {
      c[i] = alphabet.charAt(r.nextInt(alphabet.length()));
    }
    return new String(c);
  }

  private static String mutate(String seed, Random r) {
    if (seed.isEmpty()) {
      return seed;
    }
    StringBuilder b = new StringBuilder(seed);
    int edits = 1 + r.nextInt(3);
    for (int i = 0; i < edits && b.length() > 0; i++) {
      int at = r.nextInt(b.length());
      switch (r.nextInt(6)) {
        case 0:
          b.setCharAt(at, "0f+-ghé\ud800".charAt(r.nextInt(8)));
          break;
        case 1:
          b.deleteCharAt(at);
          break;
        case 2:
          b.insert(at, "0af\u0000 ".charAt(r.nextInt(5)));
          break;
        case 3:
          b.setLength(at);
          break;
        case 4:
          b.append(seed, 0, Math.min(seed.length(), r.nextInt(8)));
          break;
        default:
          b.setCharAt(at, (char) (b.charAt(at) ^ 1));
          break;
      }
    }
    return b.toString();
  }

  private static byte[] bytes(Random r) {
    switch (r.nextInt(10)) {
      case 0:
        return null;
      case 1:
        return new byte[0];
      case 2:
        return hexOrRandom(PUB_HEX, r);
      case 3:
        return hexOrRandom(CT_HEX, r);
      case 4:
        return hexOrRandom(D_HEX, r);
      case 5:
        return sized(r, new int[] {31, 32, 33, 64, 65, 66, 96, 97, 98}[r.nextInt(9)]);
      case 6:
        return new byte[r.nextInt(70)];
      default:
        return sized(r, r.nextInt(200));
    }
  }

  private static byte[] hexOrRandom(String hex, Random r) {
    byte[] b = ConvertUtil.hexToByte(hex);
    if (r.nextBoolean() && b.length > 0) {
      b[r.nextInt(b.length)] ^= (byte) (1 << r.nextInt(8));
    }
    return b;
  }

  private static byte[] sized(Random r, int n) {
    byte[] b = new byte[n];
    r.nextBytes(b);
    return b;
  }

  private static BigInteger big(Random r) {
    switch (r.nextInt(14)) {
      case 0:
        return null;
      case 1:
        return BigInteger.ZERO;
      case 2:
        return BigInteger.ONE;
      case 3:
        return BigInteger.ONE.negate();
      case 4:
        return N;
      case 5:
        return N.subtract(BigInteger.ONE);
      case 6:
        return N.subtract(BigInteger.valueOf(2));
      case 7:
        return P;
      case 8:
        return BigInteger.ONE.shiftLeft(256);
      case 9:
        return BigInteger.ONE.shiftLeft(256 + r.nextInt(600));
      case 10:
        return r.nextInt(40) == 0
            ? BigInteger.ONE.shiftLeft(65530 + r.nextInt(12))
            : new BigInteger(255, r).negate();
      case 11:
        return D;
      default:
        return new BigInteger(1 + r.nextInt(257), r);
    }
  }

  private static int intValue(Random r) {
    int[] pool = {
      0,
      1,
      -1,
      2,
      4,
      16,
      31,
      32,
      33,
      64,
      128,
      256,
      257,
      1 << 16,
      1 << 20,
      (1 << 20) + 1,
      1 << 24,
      (1 << 24) + 1,
      Integer.MAX_VALUE,
      Integer.MIN_VALUE,
      Integer.MAX_VALUE - 7
    };
    return r.nextBoolean() ? pool[r.nextInt(pool.length)] : r.nextInt(300) - 20;
  }

  private static AbstractECPoint point(Random r) {
    switch (r.nextInt(12)) {
      case 0:
        return null;
      case 1:
        return CURVE.getInfinity();
      case 2:
        return CURVE.createPoint(BigInteger.ONE, BigInteger.ONE);
      case 3:
        return CURVE.createPoint(new BigInteger(255, r), new BigInteger(255, r));
      case 4:
        return CURVE.createPoint(BigInteger.ZERO, BigInteger.ZERO);
      case 5:
        return r.nextInt(8) == 0
            ? CUSTOM.getG()
            : SMALL_CURVE.createPoint(
                BigInteger.valueOf(r.nextInt(23)), BigInteger.valueOf(r.nextInt(23)));
      case 6:
        return WNAF_CURVE.decodePoint(ConvertUtil.hexToByte(PUB_HEX));
      case 7:
        return STANDARD.getG();
      default:
        return CURVE.decodePoint(ConvertUtil.hexToByte(PUB_HEX));
    }
  }

  private static AbstractECElement element(Random r) {
    switch (r.nextInt(7)) {
      case 0:
        return null;
      case 1:
        return CURVE.fromBigInteger(BigInteger.ZERO);
      case 2:
        return CURVE.fromBigInteger(BigInteger.ONE);
      case 3:
        return SMALL_CURVE.fromBigInteger(BigInteger.valueOf(r.nextInt(23)));
      case 4:
        return CURVE.fromBigInteger(P.subtract(BigInteger.ONE));
      default:
        return CURVE.fromBigInteger(new BigInteger(255, r));
    }
  }

  private static AbstractECCurve curve(Random r) {
    switch (r.nextInt(6)) {
      case 0:
        return null;
      case 1:
        return SMALL_CURVE;
      case 2:
        return WNAF_CURVE;
      default:
        return CURVE;
    }
  }

  private static AbstractECMultiplier multiplier(Random r) {
    switch (r.nextInt(3)) {
      case 0:
        return null;
      case 1:
        return new WNAFMultiplier();
      default:
        return new DoubleAndAddMultiplier();
    }
  }

  private static ECKey key(Random r) {
    switch (r.nextInt(4)) {
      case 0:
        return null;
      case 1:
        return new ECPrivateKey(D);
      default:
        return new ECPublicKey(CURVE.decodePoint(ConvertUtil.hexToByte(PUB_HEX)));
    }
  }

  private static Object argument(Class<?> type, Random r, boolean[] hostile) {
    if (type == String.class) {
      return string(r);
    }
    if (type == byte[].class) {
      return bytes(r);
    }
    if (type == BigInteger.class) {
      return big(r);
    }
    if (type == int.class) {
      return intValue(r);
    }
    if (type == boolean.class) {
      return r.nextBoolean();
    }
    if (type == byte.class) {
      return (byte) r.nextInt();
    }
    if (type == int[].class) {
      switch (r.nextInt(4)) {
        case 0:
          return null;
        case 1:
          return new int[0];
        default:
          int[] words = new int[r.nextInt(12)];
          for (int i = 0; i < words.length; i++) {
            words[i] = r.nextInt();
          }
          return words;
      }
    }
    if (type == String[].class) {
      switch (r.nextInt(5)) {
        case 0:
          return null;
        case 1:
          return new String[r.nextInt(8)];
        case 2:
          return PARAMS.clone();
        default:
          String[] copy = PARAMS.clone();
          copy[r.nextInt(6)] = string(r);
          return copy;
      }
    }
    if (type == AbstractECPoint.class || type == FpPoint.class) {
      return point(r);
    }
    if (type == AbstractECElement.class || type == FpElement.class) {
      return element(r);
    }
    if (type == AbstractECCurve.class || type == FpCurve.class) {
      return curve(r);
    }
    if (type == AbstractECMultiplier.class) {
      return multiplier(r);
    }
    if (type == SM2Initializer.class) {
      int pick = r.nextInt(20);
      return pick == 0 ? null : pick == 1 ? CUSTOM : STANDARD;
    }
    if (type == SecureRandom.class) {
      int pick = r.nextInt(6);
      if (pick == 0) {
        return null;
      }
      if (pick == 1) {
        return SystemRandom.get();
      }
      hostile[0] = true;
      return new HostileRandom(pick == 2 ? -1 : pick == 3 ? 0 : pick == 4 ? 0xFF : r.nextInt(256));
    }
    if (type == SM3.class) {
      return r.nextInt(5) == 0 ? null : new SM3();
    }
    if (type == ECKey.class) {
      return key(r);
    }
    if (type == Object.class) {
      int pick = r.nextInt(4);
      return pick == 0 ? null : pick == 1 ? CURVE : pick == 2 ? (Object) element(r) : string(r);
    }
    if (type == SM9CipherMode.class) {
      int pick = r.nextInt(5);
      return pick == 0 ? null : pick % 2 == 0 ? SM9CipherMode.STREAM : SM9CipherMode.SM4;
    }
    if (type == AbstractECPoint[].class) {
      if (r.nextInt(4) == 0) {
        return null;
      }
      AbstractECPoint[] points = new AbstractECPoint[r.nextInt(5)];
      for (int i = 0; i < points.length; i++) {
        points[i] = point(r);
      }
      return points;
    }
    throw new IllegalStateException("no generator for " + type);
  }

  private static Object receiver(Class<?> type, Random r) throws IOException {
    if (type == SM2.class) {
      return null;
    }
    if (type == SM3.class) {
      SM3 sm3 = new SM3();
      if (r.nextBoolean()) {
        sm3.update("abc");
      }
      return sm3;
    }
    if (type == SM4.class) {
      SM4 sm4 = new SM4();
      return r.nextInt(4) == 0 ? sm4 : sm4.setKey(SEEDS[4], SEEDS[6], true);
    }
    if (type == SM2Cipher.class) {
      return new SM2Cipher();
    }
    if (type == SM2KeySwap.class) {
      return new SM2KeySwap();
    }
    if (type == SM2KeySwapParams.class) {
      return new SM2KeySwapParams();
    }
    if (type == ConvertUtil.class) {
      return new ConvertUtil();
    }
    if (type == SM2Initializer.class) {
      return r.nextInt(20) == 0 ? CUSTOM : STANDARD;
    }
    if (type == FpCurve.class || type == AbstractECCurve.class) {
      return r.nextInt(4) == 0 ? SMALL_CURVE : CURVE;
    }
    if (type == FpElement.class || type == AbstractECElement.class) {
      AbstractECElement e = element(r);
      return e == null ? CURVE.fromBigInteger(BigInteger.TEN) : e;
    }
    if (type == FpPoint.class || type == AbstractECPoint.class) {
      AbstractECPoint p = point(r);
      return p == null ? CURVE.getInfinity() : p;
    }
    if (type == DoubleAndAddMultiplier.class || type == AbstractECMultiplier.class) {
      return new DoubleAndAddMultiplier();
    }
    if (type == WNAFMultiplier.class) {
      return new WNAFMultiplier();
    }
    if (type == ECKeyPair.class) {
      return new ECKeyPair(new ECPublicKey(generator()), new ECPrivateKey(D));
    }
    if (type == ECKeyPairGenerator.class) {
      return new ECKeyPairGenerator();
    }
    if (type == ECPrivateKey.class) {
      return new ECPrivateKey(D);
    }
    if (type == SM9KeyPair.class) {
      return SM9_PAIR;
    }
    if (type == SM9Encapsulation.class) {
      return SM9_KEM;
    }
    if (type == SM9ExchangeResult.class) {
      return SM9_RESULT;
    }
    if (type == ECPublicKey.class || type == ECKey.class) {
      return new ECPublicKey(generator());
    }
    return null;
  }

  private static AbstractECPoint generator() {
    return CURVE.decodePoint(ConvertUtil.hexToByte(PUB_HEX));
  }

  private static boolean isExposed(int modifiers) {
    return Modifier.isPublic(modifiers) || Modifier.isProtected(modifiers);
  }

  private static List<Executable> targets() {
    List<Executable> out = new ArrayList<>();
    for (Class<?> type : TARGETS) {
      for (Method m : type.getDeclaredMethods()) {
        if (isExposed(m.getModifiers()) && !m.isSynthetic()) {
          m.setAccessible(true);
          out.add(m);
        }
      }
      if (!Modifier.isAbstract(type.getModifiers())) {
        for (Constructor<?> c : type.getDeclaredConstructors()) {
          if (isExposed(c.getModifiers())) {
            c.setAccessible(true);
            out.add(c);
          }
        }
      }
    }
    return out;
  }

  /** Result of one executable: cases run, and failures keyed by method and exception. */
  public static final class Report {
    public final Map<String, Long> casesPerMethod = new TreeMap<>();
    public final Map<String, String> findings = new ConcurrentHashMap<>();
    public final AtomicLong slowestNanos = new AtomicLong();
    public volatile String slowest = "";
  }

  private static String describe(Object[] args) {
    StringBuilder b = new StringBuilder();
    for (Object a : args) {
      String s;
      if (a == null) {
        s = "null";
      } else if (a instanceof byte[]) {
        s = "bytes[" + ((byte[]) a).length + "]";
      } else if (a instanceof String) {
        String t = (String) a;
        s = '"' + (t.length() > 40 ? t.substring(0, 40) + "..(" + t.length() + ")" : t) + '"';
      } else {
        s =
            a.getClass().getSimpleName()
                + (a instanceof BigInteger ? ":" + ((BigInteger) a).bitLength() : "");
      }
      b.append(s).append(", ");
    }
    return b.toString();
  }

  private static void runOne(Executable target, long cases, long seed, Report report) {
    Random r = new Random(seed ^ target.toString().hashCode());
    Class<?>[] types = target.getParameterTypes();
    String name =
        target.getDeclaringClass().getSimpleName()
            + "."
            + target.getName()
            + Arrays.toString(types).replace("class ", "");
    long done = 0;
    for (long i = 0; i < cases; i++) {
      boolean[] hostile = {false};
      Object[] args = new Object[types.length];
      for (int a = 0; a < types.length; a++) {
        args[a] = argument(types[a], r, hostile);
      }
      Object self;
      try {
        self =
            target instanceof Method && !Modifier.isStatic(target.getModifiers())
                ? receiver(target.getDeclaringClass(), r)
                : null;
      } catch (IOException e) {
        throw new IllegalStateException(e);
      }
      long start = System.nanoTime();
      try {
        if (target instanceof Method) {
          ((Method) target).invoke(self, args);
        } else {
          ((Constructor<?>) target).newInstance(args);
        }
      } catch (InvocationTargetException e) {
        Throwable cause = e.getCause();
        boolean allowed =
            cause instanceof IllegalArgumentException
                || (cause instanceof IllegalStateException
                    && (hostile[0] || "No completed SM3 hash".equals(cause.getMessage())));
        if (!allowed) {
          report.findings.putIfAbsent(
              name + " -> " + cause.getClass().getName(),
              String.valueOf(cause.getMessage())
                  + " | args: "
                  + describe(args)
                  + " at "
                  + firstFrame(cause));
        }
      } catch (ReflectiveOperationException | IllegalArgumentException e) {
        report.findings.putIfAbsent(name + " -> harness " + e, describe(args));
      }
      long elapsed = System.nanoTime() - start;
      if (elapsed > report.slowestNanos.get()) {
        report.slowestNanos.set(elapsed);
        report.slowest = name + " " + describe(args);
      }
      done++;
    }
    synchronized (report.casesPerMethod) {
      report.casesPerMethod.put(name, done);
    }
  }

  private static String firstFrame(Throwable t) {
    StackTraceElement[] s = t.getStackTrace();
    return s.length == 0 ? "?" : s[0].toString();
  }

  /** Runs the harness and returns what it found. */
  public static Report run(long casesPerMethod, int threads, long seed)
      throws InterruptedException {
    Report report = new Report();
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    for (Executable target : targets()) {
      pool.submit(() -> {
        try {
          runOne(target, casesPerMethod, seed, report);
        } catch (Throwable t) {
          report.findings.put("harness " + target, String.valueOf(t));
        }
      });
    }
    pool.shutdown();
    pool.awaitTermination(6, TimeUnit.HOURS);
    return report;
  }

  /** Entry point. */
  public static void main(String[] args) throws Exception {
    long cases = args.length > 0 ? Long.parseLong(args[0]) : 200_000;
    int threads = args.length > 1 ? Integer.parseInt(args[1]) : 4;
    long seed = args.length > 2 ? Long.parseLong(args[2]) : 20261105L;
    long start = System.nanoTime();
    Report report = run(cases, threads, seed);
    long total = 0;
    for (Map.Entry<String, Long> e : report.casesPerMethod.entrySet()) {
      total += e.getValue();
    }
    System.out.printf(
        Locale.ROOT,
        "methods=%d cases=%d seed=%d seconds=%.0f slowest=%.1fms %s%n",
        report.casesPerMethod.size(),
        total,
        seed,
        (System.nanoTime() - start) / 1e9,
        report.slowestNanos.get() / 1e6,
        report.slowest);
    for (Map.Entry<String, Long> e : report.casesPerMethod.entrySet()) {
      if (e.getValue() < cases) {
        System.out.println("SHORT " + e.getKey() + " " + e.getValue());
      }
    }
    new TreeMap<>(report.findings)
        .forEach((k, v) -> System.out.println("FINDING " + k + "\n    " + v));
    System.out.println("findings=" + report.findings.size());
  }
}
