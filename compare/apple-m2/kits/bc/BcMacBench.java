import java.security.SecureRandom;
import java.util.Arrays;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.SM2KeyExchange;
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
import org.bouncycastle.crypto.params.SM2KeyExchangePrivateParameters;
import org.bouncycastle.crypto.params.SM2KeyExchangePublicParameters;
import org.bouncycastle.crypto.signers.SM2Signer;

/**
 * BouncyCastle SM2, SM3 and SM4 benchmark in the shared Mac kit format.
 *
 * <p>Prints {@code <name>\t<median_us>\t<min_us>}: per operation a 2 s warm-up, then 7 samples of
 * at least 200 ms. Uses the lightweight API directly, without JCA.
 */
public final class BcMacBench {
  private static final byte[] ID_A = "1234567812345678".getBytes();
  private static final byte[] ID_B = "1234567812345678".getBytes();
  private static final int SAMPLES = 7;
  private static final long SAMPLE_NS = Long.getLong("sampleNs", 200_000_000L);
  private static final long WARMUP_NS = Long.getLong("warmupNs", 2_000_000_000L);
  private static long sink;

  private BcMacBench() {}

  private interface Op {
    long run() throws Exception;
  }

  private static void bench(String name, Op op) throws Exception {
    long warmupEnd = System.nanoTime() + WARMUP_NS;
    while (System.nanoTime() < warmupEnd) {
      sink += op.run();
    }
    double[] samples = new double[SAMPLES];
    for (int s = 0; s < SAMPLES; s++) {
      long start = System.nanoTime();
      long t = start;
      long n = 0;
      while (t - start < SAMPLE_NS) {
        sink += op.run();
        n++;
        t = System.nanoTime();
      }
      samples[s] = (t - start) / 1e3 / n;
    }
    Arrays.sort(samples);
    System.out.printf("%s\t%.4f\t%.4f%n", name, samples[SAMPLES / 2], samples[0]);
  }

  private static byte[] sm4(boolean encrypt, byte[] key, byte[] iv, byte[] input) throws Exception {
    PaddedBufferedBlockCipher cipher =
        new PaddedBufferedBlockCipher(
            CBCBlockCipher.newInstance(new SM4Engine()), new PKCS7Padding());
    cipher.init(encrypt, new ParametersWithIV(new KeyParameter(key), iv));
    byte[] out = new byte[cipher.getOutputSize(input.length)];
    int n = cipher.processBytes(input, 0, input.length, out, 0);
    n += cipher.doFinal(out, n);
    return n == out.length ? out : Arrays.copyOf(out, n);
  }

  public static void main(String[] args) throws Exception {
    System.err.println(
        new org.bouncycastle.jce.provider.BouncyCastleProvider().getInfo()
            + " on Java "
            + System.getProperty("java.version")
            + " "
            + System.getProperty("java.vm.name")
            + " "
            + System.getProperty("os.arch"));
    SecureRandom random = new SecureRandom();

    int[] sizes = {64, 1024, 1024 * 1024};
    String[] sm3Names = {"sm3/64B", "sm3/1KB", "sm3/1MB"};
    for (int i = 0; i < 3; i++) {
      byte[] data = new byte[sizes[i]];
      random.nextBytes(data);
      bench(
          sm3Names[i],
          () -> {
            SM3Digest digest = new SM3Digest();
            digest.update(data, 0, data.length);
            byte[] out = new byte[32];
            digest.doFinal(out, 0);
            return out[0];
          });
    }

    byte[] key = new byte[16];
    byte[] iv = new byte[16];
    random.nextBytes(key);
    random.nextBytes(iv);
    bench(
        "sm4/key_schedule",
        () -> {
          SM4Engine engine = new SM4Engine();
          engine.init(true, new KeyParameter(key));
          return engine.getBlockSize();
        });
    int[] sm4Sizes = {16, 1024, 1024 * 1024};
    String[] labels = {"16B", "1KB", "1MB"};
    byte[][] plains = new byte[3][];
    byte[][] ciphers = new byte[3][];
    for (int i = 0; i < 3; i++) {
      plains[i] = new byte[sm4Sizes[i]];
      random.nextBytes(plains[i]);
      ciphers[i] = sm4(true, key, iv, plains[i]);
      if (!Arrays.equals(sm4(false, key, iv, ciphers[i]), plains[i])) {
        throw new IllegalStateException("SM4 round trip");
      }
    }
    for (int i = 0; i < 3; i++) {
      byte[] p = plains[i];
      bench("sm4/cbc_encrypt/" + labels[i], () -> sm4(true, key, iv, p)[0]);
    }
    for (int i = 0; i < 3; i++) {
      byte[] c = ciphers[i];
      bench("sm4/cbc_decrypt/" + labels[i], () -> sm4(false, key, iv, c)[0]);
    }

    X9ECParameters x9 = GMNamedCurves.getByName("sm2p256v1");
    ECDomainParameters domain =
        new ECDomainParameters(x9.getCurve(), x9.getG(), x9.getN(), x9.getH());
    ECKeyPairGenerator generator = new ECKeyPairGenerator();
    generator.init(new ECKeyGenerationParameters(domain, random));
    bench(
        "sm2/keygen",
        () ->
            ((ECPublicKeyParameters) generator.generateKeyPair().getPublic())
                .getQ()
                .getAffineXCoord()
                .toBigInteger()
                .intValue());

    AsymmetricCipherKeyPair pair = generator.generateKeyPair();
    ECPrivateKeyParameters priv = (ECPrivateKeyParameters) pair.getPrivate();
    ECPublicKeyParameters pub = (ECPublicKeyParameters) pair.getPublic();
    byte[] message = new byte[32];
    random.nextBytes(message);
    SM2Signer signer = new SM2Signer();
    signer.init(true, new ParametersWithID(new ParametersWithRandom(priv, random), ID_A));
    SM2Signer verifier = new SM2Signer();
    verifier.init(false, new ParametersWithID(pub, ID_A));
    bench(
        "sm2/sign",
        () -> {
          signer.update(message, 0, message.length);
          return signer.generateSignature()[0];
        });
    signer.update(message, 0, message.length);
    byte[] signature = signer.generateSignature();
    bench(
        "sm2/verify",
        () -> {
          verifier.update(message, 0, message.length);
          if (!verifier.verifySignature(signature)) {
            throw new IllegalStateException("verify failed");
          }
          return 1;
        });

    SM2Engine encryptor = new SM2Engine(SM2Engine.Mode.C1C3C2);
    encryptor.init(true, new ParametersWithRandom(pub, random));
    SM2Engine decryptor = new SM2Engine(SM2Engine.Mode.C1C3C2);
    decryptor.init(false, priv);
    byte[] secret = new byte[32];
    random.nextBytes(secret);
    bench("sm2/encrypt/32B", () -> encryptor.processBlock(secret, 0, secret.length)[0]);
    byte[] encrypted = encryptor.processBlock(secret, 0, secret.length);
    if (!Arrays.equals(decryptor.processBlock(encrypted, 0, encrypted.length), secret)) {
      throw new IllegalStateException("SM2 round trip");
    }
    bench("sm2/decrypt/32B", () -> decryptor.processBlock(encrypted, 0, encrypted.length)[0]);

    // One full exchange with confirmation: fresh ephemeral keys for both sides, B computes K, S_B
    // and its expected S_A; A checks S_B, computes K and S_A; B checks S_A.
    AsymmetricCipherKeyPair staticA = generator.generateKeyPair();
    AsymmetricCipherKeyPair staticB = generator.generateKeyPair();
    bench(
        "sm2/key_exchange",
        () -> {
          AsymmetricCipherKeyPair ephA = generator.generateKeyPair();
          AsymmetricCipherKeyPair ephB = generator.generateKeyPair();
          SM2KeyExchange b = new SM2KeyExchange();
          b.init(
              new ParametersWithID(
                  new SM2KeyExchangePrivateParameters(
                      false,
                      (ECPrivateKeyParameters) staticB.getPrivate(),
                      (ECPrivateKeyParameters) ephB.getPrivate()),
                  ID_B));
          byte[][] bResult =
              b.calculateKeyWithConfirmation(
                  128,
                  null,
                  new ParametersWithID(
                      new SM2KeyExchangePublicParameters(
                          (ECPublicKeyParameters) staticA.getPublic(),
                          (ECPublicKeyParameters) ephA.getPublic()),
                      ID_A));
          SM2KeyExchange a = new SM2KeyExchange();
          a.init(
              new ParametersWithID(
                  new SM2KeyExchangePrivateParameters(
                      true,
                      (ECPrivateKeyParameters) staticA.getPrivate(),
                      (ECPrivateKeyParameters) ephA.getPrivate()),
                  ID_A));
          byte[][] aResult =
              a.calculateKeyWithConfirmation(
                  128,
                  bResult[1],
                  new ParametersWithID(
                      new SM2KeyExchangePublicParameters(
                          (ECPublicKeyParameters) staticB.getPublic(),
                          (ECPublicKeyParameters) ephB.getPublic()),
                      ID_B));
          if (!org.bouncycastle.util.Arrays.constantTimeAreEqual(aResult[1], bResult[2])
              || !Arrays.equals(aResult[0], bResult[0])) {
            throw new IllegalStateException("key exchange mismatch");
          }
          return aResult[0][0];
        });
    System.err.println("sink " + (sink & 1));
  }
}
