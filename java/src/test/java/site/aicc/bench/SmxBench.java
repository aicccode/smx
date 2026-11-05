package site.aicc.bench;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Locale;
import site.aicc.sm2.SM2;
import site.aicc.sm2.SM2KeySwapParams;
import site.aicc.sm2.ec.AbstractECPoint;
import site.aicc.sm2.keygen.ECKeyPair;
import site.aicc.sm2.util.ConvertUtil;
import site.aicc.sm3.SM3;
import site.aicc.sm4.SM4;

/**
 * Throughput benchmark built on {@link System#nanoTime()}; it only uses API that exists in the
 * unoptimized implementation too, so the same class runs against both.
 *
 * <p>Run: {@code java -cp target/classes:target/test-classes site.aicc.bench.SmxBench [warmupMs]
 * [measureMs] [rounds] [nameFilter]}
 */
public final class SmxBench {
  private static volatile long sink;
  private static String filter = "";

  private interface Op {
    void run() throws Exception;
  }

  private SmxBench() {}

  private static double measure(Op op, long millis) throws Exception {
    long end = System.nanoTime() + millis * 1_000_000L;
    long start = System.nanoTime();
    long count = 0;
    long now;
    do {
      op.run();
      count++;
      now = System.nanoTime();
    } while (now < end);
    return (double) (now - start) / count;
  }

  private static void bench(String name, int bytes, long warmup, long measure, int rounds, Op op)
      throws Exception {
    if (!name.contains(filter)) {
      return;
    }
    measure(op, warmup);
    double best = Double.MAX_VALUE;
    for (int i = 0; i < rounds; i++) {
      best = Math.min(best, measure(op, measure));
    }
    String rate = "";
    if (bytes > 0) {
      rate = String.format(Locale.ROOT, "%10.1f MB/s", bytes * 1000.0 / best);
    }
    System.out.printf(
        Locale.ROOT, "%-24s %14.1f ns/op %12.1f op/s %s%n", name, best, 1e9 / best, rate);
  }

  private static byte[] pattern(int len) {
    byte[] data = new byte[len];
    for (int i = 0; i < len; i++) {
      data[i] = (byte) (i * 31 + 7);
    }
    return data;
  }

  private static String ascii(int len) {
    char[] chars = new char[len];
    Arrays.fill(chars, 'm');
    return new String(chars);
  }

  /** Entry point. */
  public static void main(String[] args) throws Exception {
    long warmup = args.length > 0 ? Long.parseLong(args[0]) : 3000;
    long measure = args.length > 1 ? Long.parseLong(args[1]) : 1500;
    int rounds = args.length > 2 ? Integer.parseInt(args[2]) : 3;
    filter = args.length > 3 ? args[3] : "";

    System.out.println(
        "java " + System.getProperty("java.version") + " " + System.getProperty("java.vm.name"));

    for (int size : new int[] {64, 1024, 1 << 20}) {
      byte[] data = pattern(size);
      bench(
          "sm3 " + size + "B",
          size,
          warmup,
          measure,
          rounds,
          () -> sink += new SM3().update(data, 0, data.length).finish().getHashBytes()[0]);
    }

    String key = "0123456789abcdeffedcba9876543210";
    String iv = "000102030405060708090a0b0c0d0e0f";
    bench(
        "sm4 key schedule",
        0,
        warmup,
        measure,
        rounds,
        () -> sink += new SM4().setKey(key, iv, true).hashCode());
    SM4 sm4 = new SM4().setKey(key, iv, true);
    for (int size : new int[] {16, 1024, 1 << 20}) {
      // PKCS#7 adds a full block when the input is block aligned; size counts plaintext only.
      String text = ascii(size);
      String cipher = sm4.encrypt(text);
      bench(
          "sm4 enc " + size + "B",
          size,
          warmup,
          measure,
          rounds,
          () -> sink += sm4.encrypt(text).length());
      bench(
          "sm4 dec " + size + "B",
          size,
          warmup,
          measure,
          rounds,
          () -> sink += sm4.decrypt(cipher).length());
    }

    ECKeyPair pair = SM2.genSM2KeyPair();
    String pub = pair.getHexPubKey();
    String pri = pair.getHexPriKey();
    String id = "ALICE123@YAHOO.COM";
    String message = "encryption standard";
    String signature = SM2.sm2Sign(id, message, pri);
    String shortCipher = SM2.sm2Encrypt(message, pub);
    String mega = ascii(1 << 20);
    String megaCipher = SM2.sm2Encrypt(mega, pub);

    bench("sm2 keygen", 0, warmup, measure, rounds, () -> sink += SM2.genSM2KeyPair().hashCode());
    bench(
        "sm2 sign",
        0,
        warmup,
        measure,
        rounds,
        () -> sink += SM2.sm2Sign(id, message, pri).length());
    bench(
        "sm2 verify",
        0,
        warmup,
        measure,
        rounds,
        () -> {
          if (!SM2.sm2VerifySign(id, signature, message, pub)) {
            throw new IllegalStateException();
          }
        });
    bench(
        "sm2 encrypt 19B",
        0,
        warmup,
        measure,
        rounds,
        () -> sink += SM2.sm2Encrypt(message, pub).length());
    bench(
        "sm2 decrypt 19B",
        0,
        warmup,
        measure,
        rounds,
        () -> sink += SM2.sm2Decrypt(shortCipher, pri).length());
    bench(
        "sm2 encrypt 1MB",
        1 << 20,
        warmup,
        measure,
        rounds,
        () -> sink += SM2.sm2Encrypt(mega, pub).length());
    bench(
        "sm2 decrypt 1MB",
        1 << 20,
        warmup,
        measure,
        rounds,
        () -> sink += SM2.sm2Decrypt(megaCipher, pri).length());

    BigInteger dA =
        new BigInteger("6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE", 16);
    BigInteger ra =
        new BigInteger("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563", 16);
    BigInteger dB =
        new BigInteger("5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53", 16);
    BigInteger rb =
        new BigInteger("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80", 16);
    AbstractECPoint pA = SM2.getPublicKey(dA);
    AbstractECPoint rA = SM2.getPublicKey(ra);
    AbstractECPoint pB = SM2.getPublicKey(dB);
    AbstractECPoint rB = SM2.getPublicKey(rb);
    byte[] sb = ConvertUtil.hexToByte(SM2.getSb(16, pA, rA, pB, dB, rB, rb, "a", "b").getSb());
    bench(
        "sm2 key exchange B",
        0,
        warmup,
        measure,
        rounds,
        () -> {
          SM2KeySwapParams r = SM2.getSb(16, pA, rA, pB, dB, rB, rb, "a", "b");
          sink += r.getKb().length();
        });
    bench(
        "sm2 key exchange A",
        0,
        warmup,
        measure,
        rounds,
        () -> {
          SM2KeySwapParams r = SM2.getSa(16, pB, rB, pA, dA, rA, ra, "a", "b", sb);
          sink += r.getKa().length();
        });
    bench("sm2 G*k", 0, warmup, measure, rounds, () -> sink += SM2.getPublicKey(dA).hashCode());
    bench("sm2 P*k", 0, warmup, measure, rounds, () -> sink += pB.multiply(dA).hashCode());
  }
}
