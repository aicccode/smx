import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;
import java.util.Random;
import site.aicc.sm2.SM2;
import site.aicc.sm2.SM2KeySwapParams;
import site.aicc.sm2.ec.AbstractECPoint;
import site.aicc.sm2.keygen.ECKeyPair;
import site.aicc.sm2.util.ConvertUtil;
import site.aicc.sm3.SM3;
import site.aicc.sm4.SM4;

/** One benchmark for both sides: it calls only API present at 3397c6d and at HEAD. */
public final class MacBench {
  private static final String ID = "1234567812345678";
  private static final long WARMUP_NANOS = 2_000_000_000L;
  private static final long SAMPLE_NANOS = 200_000_000L;
  private static final int SAMPLES = 7;
  private static volatile long sink;

  private interface Op {
    void run() throws Exception;
  }

  private MacBench() {}

  private static double sample(Op op, long nanos) throws Exception {
    long start = System.nanoTime();
    long end = start + nanos;
    long count = 0;
    long now;
    do {
      op.run();
      count++;
      now = System.nanoTime();
    } while (now < end);
    return (now - start) / 1000.0 / count;
  }

  private static void bench(String name, Op op) throws Exception {
    sample(op, WARMUP_NANOS);
    double[] s = new double[SAMPLES];
    for (int i = 0; i < SAMPLES; i++) {
      s[i] = sample(op, SAMPLE_NANOS);
    }
    Arrays.sort(s);
    System.out.printf(Locale.ROOT, "%s\t%.3f\t%.3f%n", name, s[SAMPLES / 2], s[0]);
  }

  private static String ascii(int len, int seed) {
    char[] c = new char[len];
    Random r = new Random(seed);
    for (int i = 0; i < len; i++) {
      c[i] = (char) ('a' + r.nextInt(26));
    }
    return new String(c);
  }

  private static void check(boolean ok, String what) {
    if (!ok) {
      throw new IllegalStateException("self-check failed: " + what);
    }
  }

  /** One complete exchange with fresh ephemeral keys; returns the agreed key after every check. */
  private static String exchange(ECKeyPair a, ECKeyPair b) {
    ECKeyPair ra = SM2.genSM2KeyPair();
    ECKeyPair rb = SM2.genSM2KeyPair();
    AbstractECPoint pA = a.getPointPubKey();
    AbstractECPoint pB = b.getPointPubKey();
    AbstractECPoint rA = ra.getPointPubKey();
    AbstractECPoint rB = rb.getPointPubKey();
    SM2KeySwapParams sideB =
        SM2.getSb(16, pA, rA, pB, b.getBIPriKey(), rB, rb.getBIPriKey(), ID, ID);
    check(sideB.isSuccess(), "key exchange B");
    SM2KeySwapParams sideA =
        SM2.getSa(
            16, pB, rB, pA, a.getBIPriKey(), rA, ra.getBIPriKey(), ID, ID,
            ConvertUtil.hexToByte(sideB.getSb()));
    check(sideA.isSuccess(), "key exchange A, which checks Sb");
    check(
        SM2.checkSa(
            sideB.getV(), sideB.getZa(), sideB.getZb(), rA, rB,
            ConvertUtil.hexToByte(sideA.getSa())),
        "key exchange Sa");
    check(sideA.getKa().equals(sideB.getKb()), "key exchange keys");
    return sideA.getKa();
  }

  /** Entry point. */
  public static void main(String[] args) throws Exception {
    String[] sizeNames = {"64B", "1KB", "1MB"};
    int[] hashSizes = {64, 1024, 1 << 20};
    for (int i = 0; i < 3; i++) {
      byte[] data = new byte[hashSizes[i]];
      new Random(i).nextBytes(data);
      bench(
          "sm3/" + sizeNames[i],
          () -> sink += new SM3().update(data, 0, data.length).finish().getHashBytes()[0]);
    }

    String key = "0123456789abcdeffedcba9876543210";
    String iv = "000102030405060708090a0b0c0d0e0f";
    bench("sm4/key_schedule", () -> sink += new SM4().setKey(key, iv, true).hashCode());
    SM4 sm4 = new SM4().setKey(key, iv, true);
    String[] names = {"16B", "1KB", "1MB"};
    int[] sizes = {16, 1024, 1 << 20};
    String[] texts = new String[3];
    String[] ciphers = new String[3];
    for (int i = 0; i < 3; i++) {
      texts[i] = ascii(sizes[i], i);
      ciphers[i] = sm4.encrypt(texts[i]);
      check(ciphers[i].length() == 2 * (sizes[i] + 16), "sm4 padding adds a block");
      check(texts[i].equals(sm4.decrypt(ciphers[i])), "sm4 round trip");
    }
    for (int i = 0; i < 3; i++) {
      String text = texts[i];
      bench("sm4/cbc_encrypt/" + names[i], () -> sink += sm4.encrypt(text).length());
    }
    for (int i = 0; i < 3; i++) {
      String cipher = ciphers[i];
      bench("sm4/cbc_decrypt/" + names[i], () -> sink += sm4.decrypt(cipher).length());
    }

    ECKeyPair pair = SM2.genSM2KeyPair();
    String pub = pair.getHexPubKey();
    String pri = pair.getHexPriKey();
    String message = ascii(32, 7);
    check(message.getBytes(StandardCharsets.UTF_8).length == 32, "32-byte message");
    String signature = SM2.sm2Sign(ID, message, pri);
    check(SM2.sm2VerifySign(ID, signature, message, pub), "verify");
    check(!SM2.sm2VerifySign(ID, signature, message + "x", pub), "verify rejects a changed message");
    String cipher = SM2.sm2Encrypt(message, pub);
    check(message.equals(SM2.sm2Decrypt(cipher, pri)), "sm2 round trip");
    ECKeyPair longA = SM2.genSM2KeyPair();
    ECKeyPair longB = SM2.genSM2KeyPair();
    check(exchange(longA, longB).length() == 32, "16-byte shared key");

    bench("sm2/keygen", () -> sink += SM2.genSM2KeyPair().getHexPubKey().length());
    bench("sm2/sign", () -> sink += SM2.sm2Sign(ID, message, pri).length());
    bench(
        "sm2/verify",
        () -> {
          if (!SM2.sm2VerifySign(ID, signature, message, pub)) {
            throw new IllegalStateException("verify");
          }
        });
    bench("sm2/encrypt/32B", () -> sink += SM2.sm2Encrypt(message, pub).length());
    bench("sm2/decrypt/32B", () -> sink += SM2.sm2Decrypt(cipher, pri).length());
    bench("sm2/key_exchange", () -> sink += exchange(longA, longB).length());
  }
}
