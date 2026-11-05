import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;

/**
 * BouncyCastle SM2, SM3 and SM4 benchmark, for comparison with the SMX implementations.
 *
 * <p>Uses the lightweight API directly, with no JCA provider overhead. Build and run:
 *
 * <pre>
 * javac -cp bcprov.jar BcBench.java
 * taskset -c 6,7 java -cp .:bcprov.jar BcBench [warmup ms] [round ms] [rounds]
 * </pre>
 *
 * <p>The operations match the SMX benchmarks: SM4 is CBC with PKCS#7 padding, and SM2 signing uses
 * the default user ID over a 32-byte message. Each case reports the best round after warm-up.
 */
public final class BcBench {
  private static final byte[] SM2_ID = "1234567812345678".getBytes();
  private static long sink;

  private BcBench() {}

  private interface Op {
    long run() throws Exception;
  }

  private static void bench(String name, Op op, long warmupMs, long roundMs, int rounds)
      throws Exception {
    long warmupEnd = System.nanoTime() + warmupMs * 1_000_000L;
    while (System.nanoTime() < warmupEnd) {
      sink += op.run();
    }
    double best = Double.MAX_VALUE;
    for (int r = 0; r < rounds; r++) {
      long start = System.nanoTime();
      long end = start + roundMs * 1_000_000L;
      long iterations = 0;
      long t = start;
      while (t < end) {
        sink += op.run();
        iterations++;
        t = System.nanoTime();
      }
      best = Math.min(best, (t - start) / 1e3 / iterations);
    }
    System.out.printf("%-28s %14.3f us/op%n", name, best);
  }

  private static byte[] sm4(boolean encrypt, byte[] key, byte[] iv, byte[] input) throws Exception {
    PaddedBufferedBlockCipher cipher =
        new PaddedBufferedBlockCipher(
            CBCBlockCipher.newInstance(new SM4Engine()), new PKCS7Padding());
    cipher.init(encrypt, new ParametersWithIV(new KeyParameter(key), iv));
    byte[] out = new byte[cipher.getOutputSize(input.length)];
    int n = cipher.processBytes(input, 0, input.length, out, 0);
    n += cipher.doFinal(out, n);
    byte[] result = new byte[n];
    System.arraycopy(out, 0, result, 0, n);
    return result;
  }

  public static void main(String[] args) throws Exception {
    long warmup = args.length > 0 ? Long.parseLong(args[0]) : 5000;
    long round = args.length > 1 ? Long.parseLong(args[1]) : 700;
    int rounds = args.length > 2 ? Integer.parseInt(args[2]) : 3;
    System.out.println(
        new org.bouncycastle.jce.provider.BouncyCastleProvider().getInfo()
            + " on Java "
            + System.getProperty("java.version")
            + " "
            + System.getProperty("java.vm.name"));

    SecureRandom random = new SecureRandom();

    int[] sm3Sizes = {64, 1024, 1024 * 1024};
    String[] sm3Labels = {"64B", "1KB", "1MB"};
    for (int i = 0; i < sm3Sizes.length; i++) {
      byte[] data = new byte[sm3Sizes[i]];
      random.nextBytes(data);
      bench(
          "SM3 " + sm3Labels[i],
          () -> {
            SM3Digest digest = new SM3Digest();
            digest.update(data, 0, data.length);
            byte[] out = new byte[32];
            digest.doFinal(out, 0);
            return out[0];
          },
          warmup,
          round,
          rounds);
    }

    byte[] key = new byte[16];
    byte[] iv = new byte[16];
    random.nextBytes(key);
    random.nextBytes(iv);
    bench(
        "SM4 key schedule",
        () -> {
          SM4Engine engine = new SM4Engine();
          engine.init(true, new KeyParameter(key));
          return engine.getBlockSize();
        },
        warmup,
        round,
        rounds);

    int[] sm4Sizes = {16, 1024, 1024 * 1024};
    String[] sm4Labels = {"16B", "1KB", "1MB"};
    for (int i = 0; i < sm4Sizes.length; i++) {
      byte[] plain = new byte[sm4Sizes[i]];
      random.nextBytes(plain);
      byte[] cipher = sm4(true, key, iv, plain);
      bench(
          "SM4 encrypt " + sm4Labels[i], () -> sm4(true, key, iv, plain)[0], warmup, round, rounds);
      bench(
          "SM4 decrypt " + sm4Labels[i],
          () -> sm4(false, key, iv, cipher)[0],
          warmup,
          round,
          rounds);
    }

    X9ECParameters x9 = GMNamedCurves.getByName("sm2p256v1");
    ECDomainParameters domain =
        new ECDomainParameters(x9.getCurve(), x9.getG(), x9.getN(), x9.getH());
    ECKeyPairGenerator generator = new ECKeyPairGenerator();
    generator.init(new ECKeyGenerationParameters(domain, random));
    bench(
        "SM2 keygen",
        () -> {
          AsymmetricCipherKeyPair pair = generator.generateKeyPair();
          BigInteger d = ((ECPrivateKeyParameters) pair.getPrivate()).getD();
          return d.intValue();
        },
        warmup,
        round,
        rounds);

    AsymmetricCipherKeyPair pair = generator.generateKeyPair();
    ECPrivateKeyParameters priv = (ECPrivateKeyParameters) pair.getPrivate();
    ECPublicKeyParameters pub = (ECPublicKeyParameters) pair.getPublic();
    byte[] message = new byte[32];
    random.nextBytes(message);

    SM2Signer signer = new SM2Signer();
    signer.init(true, new ParametersWithID(new ParametersWithRandom(priv, random), SM2_ID));
    SM2Signer verifier = new SM2Signer();
    verifier.init(false, new ParametersWithID(pub, SM2_ID));
    bench(
        "SM2 sign",
        () -> {
          signer.update(message, 0, message.length);
          return signer.generateSignature()[0];
        },
        warmup,
        round,
        rounds);
    signer.update(message, 0, message.length);
    byte[] signature = signer.generateSignature();
    bench(
        "SM2 verify",
        () -> {
          verifier.update(message, 0, message.length);
          if (!verifier.verifySignature(signature)) {
            throw new IllegalStateException("verify failed");
          }
          return 1;
        },
        warmup,
        round,
        rounds);

    SM2Engine encryptor = new SM2Engine(SM2Engine.Mode.C1C3C2);
    encryptor.init(true, new ParametersWithRandom(pub, random));
    SM2Engine decryptor = new SM2Engine(SM2Engine.Mode.C1C3C2);
    decryptor.init(false, priv);
    byte[] secret = new byte[32];
    random.nextBytes(secret);
    bench(
        "SM2 encrypt 32B",
        () -> encryptor.processBlock(secret, 0, secret.length)[0],
        warmup,
        round,
        rounds);
    byte[] encrypted = encryptor.processBlock(secret, 0, secret.length);
    bench(
        "SM2 decrypt 32B",
        () -> decryptor.processBlock(encrypted, 0, encrypted.length)[0],
        warmup,
        round,
        rounds);

    System.out.println("sink " + (sink & 1));
  }
}
