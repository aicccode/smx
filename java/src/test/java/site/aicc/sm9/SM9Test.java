package site.aicc.sm9;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static site.aicc.sm9.SM9VectorsTest.rejects;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Random;
import org.junit.Test;
import site.aicc.sm2.util.ConvertUtil;

/** Round trips, tampering, wrong inputs, and cross-checks of the arithmetic layers. */
public class SM9Test {
  private static final SM9KeyPair SIGN_MASTER = SM9.genSignMasterKey();
  private static final SM9KeyPair ENC_MASTER = SM9.genEncMasterKey();
  private static final String ALICE_SIGN = SM9.genSignUserKey(SIGN_MASTER.getPrivateKey(), "Alice");
  private static final String BOB_ENC = SM9.genEncUserKey(ENC_MASTER.getPrivateKey(), "Bob");

  private static String flipHex(String hex, int index) {
    char c = hex.charAt(index);
    char d = c == '0' ? '1' : '0';
    return hex.substring(0, index) + d + hex.substring(index + 1);
  }

  // ---------------------------------------------------------------- arithmetic

  @Test
  public void fieldMatchesBigInteger() {
    Random rnd = new Random(1);
    BigInteger q = Fp.Q_BIG;
    for (int i = 0; i < 200; i++) {
      BigInteger a = new BigInteger(256, rnd).mod(q);
      BigInteger b = i == 0 ? q.subtract(BigInteger.ONE) : new BigInteger(256, rnd).mod(q);
      int[] x = Fp.fromBigInteger(a);
      int[] y = Fp.fromBigInteger(b);
      int[] r = new int[Fp.L];
      Fp.mul(r, 0, x, 0, y, 0);
      assertEquals(a.multiply(b).mod(q), Fp.toBigInteger(r, 0));
      Fp.add(r, 0, x, 0, y, 0);
      assertEquals(a.add(b).mod(q), Fp.toBigInteger(r, 0));
      Fp.sub(r, 0, x, 0, y, 0);
      assertEquals(a.subtract(b).mod(q), Fp.toBigInteger(r, 0));
      Fp.neg(r, 0, x, 0);
      assertEquals(a.negate().mod(q), Fp.toBigInteger(r, 0));
      Fp.half(r, 0, x, 0);
      assertEquals(a.multiply(BigInteger.valueOf(2).modInverse(q)).mod(q), Fp.toBigInteger(r, 0));
      Fp.inv(r, 0, x, 0);
      assertEquals(a.signum() == 0 ? BigInteger.ZERO : a.modInverse(q), Fp.toBigInteger(r, 0));
    }
    int[] z = new int[Fp.L];
    Fp.neg(z, 0, z, 0);
    assertTrue(Fp.isZero(z, 0) != 0);
  }

  @Test
  public void scalarFieldMatchesBigInteger() {
    Random rnd = new Random(2);
    BigInteger n = Fn.N_BIG;
    for (int i = 0; i < 100; i++) {
      BigInteger a = new BigInteger(256, rnd).mod(n);
      BigInteger b = new BigInteger(256, rnd).mod(n);
      int[] x = Fn.fromBigInteger(a);
      int[] y = Fn.fromBigInteger(b);
      assertEquals(a.add(b).mod(n), new BigInteger(1, Fn.toBytes(Fn.add(x, y))));
      assertEquals(a.subtract(b).mod(n), new BigInteger(1, Fn.toBytes(Fn.sub(x, y))));
      assertEquals(a.multiply(b).mod(n), new BigInteger(1, Fn.toBytes(Fn.mul(x, y))));
      assertEquals(a.modInverse(n), new BigInteger(1, Fn.toBytes(Fn.inv(x))));
    }
    assertEquals(0, Fn.isValidScalar(new int[8]));
    assertEquals(0, Fn.isValidScalar(Fn.N.clone()));
    assertEquals(-1, Fn.isValidScalar(Fn.fromBigInteger(n.subtract(BigInteger.ONE))));
  }

  private static int[] randomGt(long seed) {
    int[] k = Fn.fromBigInteger(new BigInteger(250, new Random(seed)));
    return Pairing.pow(Pairing.pair(G1.P1, G2.P2), k);
  }

  @Test
  public void towerIdentities() {
    int[] g = randomGt(3);
    int[] h = randomGt(4);
    int[] a = new int[Fp12.L];
    int[] b = new int[Fp12.L];
    Fp12.sqr(a, g);
    Fp12.mul(b, g, g);
    assertTrue(Fp12.equal(a, b) != 0);
    Fp12.cyclotomicSqr(b, g);
    assertTrue(Fp12.equal(a, b) != 0);
    Fp12.inv(a, g);
    Fp12.mul(a, a, g);
    assertTrue(Fp12.equal(a, Fp12.one()) != 0);
    // In GT the inverse is the conjugate.
    Fp12.conj6(a, g);
    Fp12.mul(a, a, g);
    assertTrue(Fp12.equal(a, Fp12.one()) != 0);
    // Frobenius is a homomorphism and frob^2 = frob o frob.
    Fp12.mul(a, g, h);
    Fp12.frobenius(a, a, 1);
    int[] fg = new int[Fp12.L];
    int[] fh = new int[Fp12.L];
    Fp12.frobenius(fg, g, 1);
    Fp12.frobenius(fh, h, 1);
    Fp12.mul(b, fg, fh);
    assertTrue(Fp12.equal(a, b) != 0);
    Fp12.frobenius(a, fg, 1);
    Fp12.frobenius(b, g, 2);
    assertTrue(Fp12.equal(a, b) != 0);
    Fp12.frobenius(a, b, 1);
    Fp12.frobenius(b, g, 3);
    assertTrue(Fp12.equal(a, b) != 0);
    // g^N = 1; the fixed-base table gives the same powers; g^q = frob(g).
    assertTrue(Fp12.equal(Pairing.pow(g, Fn.N), Fp12.one()) != 0);
    int[] comb = Pairing.combTable(g);
    for (long seed = 10; seed < 14; seed++) {
      int[] k = Fn.fromBigInteger(new BigInteger(256, new Random(seed)));
      assertTrue(Fp12.equal(Pairing.pow(g, k), Pairing.powComb(comb, k)) != 0);
    }
    Fp12.frobenius(a, g, 1);
    assertTrue(Fp12.equal(Pairing.pow(g, Fp.words(Fp.Q_BIG)), a) != 0);
  }

  @Test
  public void pairingIsBilinear() {
    BigInteger a = new BigInteger(255, new Random(5)).mod(Fn.N_BIG);
    BigInteger b = new BigInteger(255, new Random(6)).mod(Fn.N_BIG);
    int[] ka = Fn.fromBigInteger(a);
    int[] kb = Fn.fromBigInteger(b);
    int[] e = Pairing.pair(G1.P1, G2.P2);
    int[] lhs = Pairing.pair(G1.mul(G1.P1, ka), G2.mul(G2.P2, kb));
    int[] rhs = Pairing.pow(e, Fn.mul(ka, kb));
    assertArrayEquals(Fp12.encode(rhs), Fp12.encode(lhs));
    assertNotEquals(
        ConvertUtil.byteToHex(Fp12.encode(e)), ConvertUtil.byteToHex(Fp12.encode(Fp12.one())));
    assertArrayEquals(Fp12.encode(Fp12.one()), Fp12.encode(Pairing.pair(G1.infinity(), G2.P2)));
    assertArrayEquals(Fp12.encode(Fp12.one()), Fp12.encode(Pairing.pair(G1.P1, G2.infinity())));
  }

  @Test
  public void groupLaws() {
    int[] k = Fn.fromBigInteger(BigInteger.valueOf(7));
    int[] p = G1.mul(G1.P1, k);
    int[] q = G1.infinity();
    for (int i = 0; i < 7; i++) {
      G1.add(q, q, G1.P1);
    }
    assertTrue(G1.equal(p, q));
    int[] d = new int[G1.L];
    G1.add(d, p, G1.neg(p));
    assertTrue(G1.isInfinity(d));
    assertTrue(G1.isInfinity(G1.mul(G1.P1, Fn.N)));
    assertTrue(G2.isInfinity(G2.mul(G2.P2, Fn.N)));
    int[] p2 = G2.mul(G2.P2, k);
    int[] q2 = G2.infinity();
    for (int i = 0; i < 7; i++) {
      G2.add(q2, q2, G2.P2);
    }
    assertTrue(G2.equal(p2, q2));
    int[] dd = G2.infinity();
    G2.dbl(dd, G2.P2);
    int[] aa = G2.infinity();
    G2.add(aa, G2.P2, G2.P2);
    assertTrue(G2.equal(dd, aa));
    for (long seed = 20; seed < 24; seed++) {
      int[] r = Fn.fromBigInteger(new BigInteger(256, new Random(seed)));
      assertTrue(G1.equal(G1.mul(G1.P1, r), G1.mulGenerator(r)));
      assertTrue(G2.equal(G2.mul(G2.P2, r), G2.mulGenerator(r)));
    }
    assertTrue(G1.isInfinity(G1.mulGenerator(Fn.N)));
    assertTrue(G2.isInfinity(G2.mulGenerator(Fn.N)));
    assertTrue(G2.inSubgroup(G2.P2));
    assertTrue(G2.inSubgroup(G2.toAffineProjective(p2)));
    // A twist point outside G2: on the curve, but rejected by the subgroup check.
    assertNull(G2.decode(ConvertUtil.hexToByte(notInSubgroup())));
  }

  private static String notInSubgroup() {
    return (String)
        ((java.util.Map<?, ?>) ((java.util.List<?>) loadInvalid().get("g2")).get(6)).get("value");
  }

  private static java.util.Map<?, ?> loadInvalid() {
    try {
      java.io.File f =
          new java.io.File(System.getProperty("user.dir"), "../testvectors/sm9-vectors.json");
      String text =
          new String(java.nio.file.Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
      return (java.util.Map<?, ?>)
          ((java.util.Map<?, ?>) MiniJson.parse(text)).get("invalid_points");
    } catch (java.io.IOException e) {
      throw new AssertionError(e);
    }
  }

  // ---------------------------------------------------------------- signatures

  @Test
  public void signatureRoundTripAndTampering() {
    String mpk = SIGN_MASTER.getPublicKey();
    assertEquals(mpk, SM9.signMasterPublicKey(SIGN_MASTER.getPrivateKey()));
    for (String msg : new String[] {"", "a", "Chinese IBS standard", "中文消息"}) {
      String sig = SM9.sign(msg, ALICE_SIGN, mpk);
      assertEquals(194, sig.length());
      assertTrue(SM9.verify(msg, sig, "Alice", mpk));
      assertFalse(SM9.verify(msg + "x", sig, "Alice", mpk));
      assertFalse(SM9.verify(msg, sig, "Alicf", mpk));
      assertFalse(
          SM9.verify(
              msg.getBytes(StandardCharsets.UTF_8),
              sig,
              "Alice".getBytes(StandardCharsets.UTF_8),
              mpk,
              2));
      for (int i : new int[] {0, 63, 66, 100, 193}) {
        assertFalse("flip " + i, SM9.verify(msg, flipHex(sig, i), "Alice", mpk));
      }
      assertFalse(SM9.verify(msg, sig.toUpperCase(Locale.ROOT), "Alice", mpk));
      assertTrue(SM9.verify(msg, sig, "Alice", mpk.toUpperCase(Locale.ROOT)));
      assertFalse(SM9.verify(msg, sig, "Alice", SM9.genSignMasterKey().getPublicKey()));
    }
    assertNotEquals(SM9.sign("m", ALICE_SIGN, mpk), SM9.sign("m", ALICE_SIGN, mpk));
    assertFalse(SM9.verify(null, "", "Alice", mpk));
    assertFalse(SM9.verify("m", null, "Alice", mpk));
    assertFalse(SM9.verify("m", SM9.sign("m", ALICE_SIGN, mpk), null, mpk));
    assertFalse(SM9.verify("m", SM9.sign("m", ALICE_SIGN, mpk), "Alice", null));
    // h = 0 and h = N are out of range.
    String sig = SM9.sign("m", ALICE_SIGN, mpk);
    String zeroH =
        "0000000000000000000000000000000000000000000000000000000000000000" + sig.substring(64);
    assertFalse(SM9.verify("m", zeroH, "Alice", mpk));
    String nH = Fn.N_BIG.toString(16) + sig.substring(64);
    assertFalse(SM9.verify("m", nH, "Alice", mpk));
  }

  @Test
  public void hidIsHonoured() {
    byte[] id = "Alice".getBytes(StandardCharsets.UTF_8);
    String mpk = SIGN_MASTER.getPublicKey();
    for (int hid : new int[] {0, 0x83, 255}) {
      String ds = SM9.genSignUserKey(SIGN_MASTER.getPrivateKey(), id, hid);
      String sig = SM9.sign("x".getBytes(StandardCharsets.UTF_8), ds, mpk);
      assertTrue(SM9.verify("x".getBytes(StandardCharsets.UTF_8), sig, id, mpk, hid));
      assertFalse(SM9.verify("x".getBytes(StandardCharsets.UTF_8), sig, id, mpk, 1));
    }
    rejects("hid 256", () -> SM9.genSignUserKey(SIGN_MASTER.getPrivateKey(), id, 256));
    rejects("hid -1", () -> SM9.genEncUserKey(ENC_MASTER.getPrivateKey(), id, -1));
  }

  // ---------------------------------------------------------------- encryption

  @Test
  public void encryptionRoundTripsAndTampering() {
    String mpk = ENC_MASTER.getPublicKey();
    assertEquals(mpk, SM9.encMasterPublicKey(ENC_MASTER.getPrivateKey()));
    for (SM9CipherMode mode : SM9CipherMode.values()) {
      for (String msg : new String[] {"a", "Chinese IBE standard", "0123456789abcdef", "中文"}) {
        String ct = SM9.encrypt(msg, "Bob", mpk, mode);
        assertEquals(msg, SM9.decrypt(ct, "Bob", BOB_ENC, mode));
        rejects("wrong id", () -> SM9.decrypt(ct, "Bob2", BOB_ENC, mode));
        SM9CipherMode other = mode == SM9CipherMode.SM4 ? SM9CipherMode.STREAM : SM9CipherMode.SM4;
        if (ct.length() == 2 * (97 + 16)) {
          // A 16-byte C2 derives the same 48 KDF bytes in both modes, so the MAC holds in either
          // (the ciphertext does not record the mode); the wrong mode cannot give the plaintext.
          try {
            assertNotEquals(msg, SM9.decrypt(ct, "Bob", BOB_ENC, other));
          } catch (IllegalArgumentException expected) {
            // SM4 unpadding of a stream ciphertext usually fails.
          }
        } else {
          rejects("wrong mode", () -> SM9.decrypt(ct, "Bob", BOB_ENC, other));
        }
        String otherKey = SM9.genEncUserKey(ENC_MASTER.getPrivateKey(), "Carol");
        rejects("wrong key", () -> SM9.decrypt(ct, "Bob", otherKey, mode));
        for (int i : new int[] {2, 129, 131, 193, 194, ct.length() - 1}) {
          rejects("flip " + i, () -> SM9.decrypt(flipHex(ct, i), "Bob", BOB_ENC, mode));
        }
        rejects("upper case", () -> SM9.decrypt(ct.toUpperCase(Locale.ROOT), "Bob", BOB_ENC, mode));
        rejects(
            "truncated", () -> SM9.decrypt(ct.substring(0, ct.length() - 2), "Bob", BOB_ENC, mode));
        rejects("extended", () -> SM9.decrypt(ct + "00", "Bob", BOB_ENC, mode));
        assertEquals(msg, SM9.decrypt(ct, "Bob", BOB_ENC.toUpperCase(Locale.ROOT), mode));
      }
    }
    rejects("empty plaintext", () -> SM9.encrypt("", "Bob", mpk));
    rejects(
        "empty plaintext sm4",
        () -> SM9.encrypt(new byte[0], new byte[0], mpk, 3, SM9CipherMode.SM4));
    rejects("null mode", () -> SM9.encrypt("a", "Bob", mpk, null));
    rejects(
        "only C1 and C3",
        () -> SM9.decrypt(SM9.encrypt("a", "Bob", mpk).substring(0, 194), "Bob", BOB_ENC));
    byte[] big = new byte[100_000];
    new Random(9).nextBytes(big);
    byte[] id = "Bob".getBytes(StandardCharsets.UTF_8);
    for (SM9CipherMode mode : SM9CipherMode.values()) {
      String ct = SM9.encrypt(big, id, mpk, SM9.HID_ENCRYPT, mode);
      assertArrayEquals(big, SM9.decryptToBytes(ct, id, BOB_ENC, mode));
    }
  }

  @Test
  public void encapsulationRoundTrip() {
    String mpk = ENC_MASTER.getPublicKey();
    for (int len : new int[] {1, 16, 32, 33, 1000}) {
      SM9Encapsulation kc = SM9.encapsulate("Bob", mpk, len);
      assertEquals(2 * len, kc.getKey().length());
      assertEquals(kc.getKey(), SM9.decapsulate(kc.getCiphertext(), "Bob", BOB_ENC, len));
      assertNotEquals(kc.getKey(), SM9.decapsulate(kc.getCiphertext(), "Bob2", BOB_ENC, len));
      rejects(
          "upper",
          () -> SM9.decapsulate(kc.getCiphertext().toUpperCase(Locale.ROOT), "Bob", BOB_ENC, len));
      rejects(
          "tampered", () -> SM9.decapsulate(flipHex(kc.getCiphertext(), 129), "Bob", BOB_ENC, len));
    }
    rejects("len 0", () -> SM9.encapsulate("Bob", mpk, 0));
    rejects("len too big", () -> SM9.encapsulate("Bob", mpk, SM9.MAX_KEY_BYTES + 1));
    SM9Encapsulation kc = SM9.encapsulate("Bob", mpk, 16);
    rejects("dec len 0", () -> SM9.decapsulate(kc.getCiphertext(), "Bob", BOB_ENC, 0));
  }

  // ---------------------------------------------------------------- key exchange

  @Test
  public void keyExchangeRoundTripAndMismatch() {
    String ke = ENC_MASTER.getPrivateKey();
    String mpk = ENC_MASTER.getPublicKey();
    String deA = SM9.genEncUserKey(ke, "Alice".getBytes(StandardCharsets.UTF_8), SM9.HID_EXCHANGE);
    String deB = SM9.genEncUserKey(ke, "Bob".getBytes(StandardCharsets.UTF_8), SM9.HID_EXCHANGE);
    SM9KeyPair a = SM9.exchangeInit("Bob", mpk);
    SM9KeyPair b = SM9.exchangeInit("Alice", mpk);
    SM9ExchangeResult rb =
        SM9.exchangeRespond(
            32, "Alice", "Bob", mpk, deB, b.getPrivateKey(), b.getPublicKey(), a.getPublicKey());
    assertTrue(rb.getMessage(), rb.isSuccess());
    SM9ExchangeResult ra =
        SM9.exchangeConfirm(
            32,
            "Alice",
            "Bob",
            mpk,
            deA,
            a.getPrivateKey(),
            a.getPublicKey(),
            b.getPublicKey(),
            rb.getSb());
    assertTrue(ra.getMessage(), ra.isSuccess());
    assertEquals(rb.getSharedKey(), ra.getSharedKey());
    assertEquals(64, ra.getSharedKey().length());
    assertTrue(SM9.exchangeCheck(rb.getS2(), ra.getSa()));
    assertFalse(SM9.exchangeCheck(rb.getS2(), flipHex(ra.getSa(), 5)));
    assertFalse(SM9.exchangeCheck(rb.getS2(), ra.getSa().toUpperCase(Locale.ROOT)));
    assertFalse(SM9.exchangeCheck(null, ra.getSa()));
    assertFalse(SM9.exchangeCheck(rb.getS2(), rb.getSb()));
    // A tampered S_B makes A fail without a key.
    SM9ExchangeResult bad =
        SM9.exchangeConfirm(
            32,
            "Alice",
            "Bob",
            mpk,
            deA,
            a.getPrivateKey(),
            a.getPublicKey(),
            b.getPublicKey(),
            flipHex(rb.getSb(), 0));
    assertFalse(bad.isSuccess());
    assertNull(bad.getSharedKey());
    // Mismatched identities or keys: S_B no longer matches.
    SM9ExchangeResult wrongId =
        SM9.exchangeConfirm(
            32,
            "Alice",
            "Bobby",
            mpk,
            deA,
            a.getPrivateKey(),
            a.getPublicKey(),
            b.getPublicKey(),
            rb.getSb());
    assertFalse(wrongId.isSuccess());
    String deC = SM9.genEncUserKey(ke, "Carol".getBytes(StandardCharsets.UTF_8), SM9.HID_EXCHANGE);
    SM9ExchangeResult wrongKey =
        SM9.exchangeConfirm(
            32,
            "Alice",
            "Bob",
            mpk,
            deC,
            a.getPrivateKey(),
            a.getPublicKey(),
            b.getPublicKey(),
            rb.getSb());
    assertFalse(wrongKey.isSuccess());
    SM9ExchangeResult wrongR =
        SM9.exchangeConfirm(
            32,
            "Alice",
            "Bob",
            mpk,
            deA,
            b.getPrivateKey(),
            a.getPublicKey(),
            b.getPublicKey(),
            rb.getSb());
    assertFalse(wrongR.isSuccess());
    SM9ExchangeResult len0 =
        SM9.exchangeRespond(
            0, "Alice", "Bob", mpk, deB, b.getPrivateKey(), b.getPublicKey(), a.getPublicKey());
    assertFalse(len0.isSuccess());
    SM9ExchangeResult nullId =
        SM9.exchangeRespond(
            16,
            (String) null,
            "Bob",
            mpk,
            deB,
            b.getPrivateKey(),
            b.getPublicKey(),
            a.getPublicKey());
    assertFalse(nullId.isSuccess());
  }

  @Test
  public void sm4EcbHook() {
    byte[] key = ConvertUtil.hexToByte("0123456789abcdeffedcba9876543210");
    byte[] ct = site.aicc.sm4.SM4.ecbEncrypt(key, key);
    // GB/T 32907 example block, then a full block of padding.
    assertEquals(32, ct.length);
    assertEquals(
        "681edf34d206965e86b3e94f536e4246", ConvertUtil.byteToHex(java.util.Arrays.copyOf(ct, 16)));
    assertArrayEquals(key, site.aicc.sm4.SM4.ecbDecrypt(key, ct));
    byte[] bad = ct.clone();
    bad[31] ^= 1;
    rejects("bad padding", () -> site.aicc.sm4.SM4.ecbDecrypt(key, bad));
    rejects("bad length", () -> site.aicc.sm4.SM4.ecbDecrypt(key, new byte[15]));
    rejects("bad key", () -> site.aicc.sm4.SM4.ecbEncrypt(new byte[15], key));
  }

  // ---------------------------------------------------------------- keys

  @Test
  public void keyInputRules() {
    String ks = SIGN_MASTER.getPrivateKey();
    assertEquals(
        SM9.genSignUserKey(ks, "Alice"), SM9.genSignUserKey(ks.toUpperCase(Locale.ROOT), "Alice"));
    assertEquals(ALICE_SIGN, SM9.genSignUserKey(ks, "Alice".getBytes(StandardCharsets.UTF_8), 1));
    assertNotEquals(ALICE_SIGN, SM9.genSignUserKey(ks, "alice"));
    rejects("short key", () -> SM9.genSignUserKey(ks.substring(2), "Alice"));
    rejects("null id", () -> SM9.genSignUserKey(ks, (String) null));
    rejects("lone surrogate", () -> SM9.genSignUserKey(ks, "\ud800"));
    rejects("enc key as sign key", () -> SM9.sign("m", BOB_ENC, SIGN_MASTER.getPublicKey()));
    rejects(
        "sign key as enc key",
        () -> SM9.decrypt(SM9.encrypt("m", "Bob", ENC_MASTER.getPublicKey()), "Bob", ALICE_SIGN));
    rejects("sign master as enc master", () -> SM9.encrypt("m", "Bob", SIGN_MASTER.getPublicKey()));
    SM9KeyPair other = SM9.genSignMasterKey();
    assertNotEquals(SIGN_MASTER.getPrivateKey(), other.getPrivateKey());
    assertEquals(64, other.getPrivateKey().length());
    assertEquals(258, other.getPublicKey().length());
    assertEquals(130, SM9.genEncMasterKey().getPublicKey().length());
    assertEquals(258, BOB_ENC.length());
    assertEquals(130, ALICE_SIGN.length());
    // An empty identity is allowed.
    String empty = SM9.genSignUserKey(ks, "");
    assertTrue(
        SM9.verify(
            "m", SM9.sign("m", empty, SIGN_MASTER.getPublicKey()), "", SIGN_MASTER.getPublicKey()));
  }
}
