package site.aicc.sm9;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.junit.BeforeClass;
import org.junit.Test;
import site.aicc.sm2.util.ConvertUtil;

/**
 * Reproduces every vector of {@code testvectors/sm9-vectors.json}: the worked examples of GB/T
 * 38635.5, the extra vectors of the shared generator, and every invalid point and scalar.
 */
public class SM9VectorsTest {
  private static Map<String, Object> root;

  @BeforeClass
  public static void load() throws Exception {
    File file = new File(System.getProperty("user.dir"), "../testvectors/sm9-vectors.json");
    if (!file.isFile()) {
      file = new File("testvectors/sm9-vectors.json");
    }
    String text = new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
    root = map(MiniJson.parse(text));
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> map(Object o) {
    return (Map<String, Object>) o;
  }

  @SuppressWarnings("unchecked")
  private static List<Object> list(Object o) {
    return (List<Object>) o;
  }

  private static String str(Map<String, Object> m, String key) {
    Object v = m.get(key);
    if (v == null) {
      throw new AssertionError("missing " + key);
    }
    return (String) v;
  }

  private static int num(Map<String, Object> m, String key) {
    return ((Long) m.get(key)).intValue();
  }

  private static byte[] utf8(String s) {
    return s.getBytes(StandardCharsets.UTF_8);
  }

  private static byte[] unhex(String s) {
    return ConvertUtil.hexToByte(s);
  }

  private static Map<String, Object> standard(String name) {
    return map(map(root.get("standard")).get(name));
  }

  private static Map<String, Object> extra() {
    return map(root.get("extra"));
  }

  @Test
  public void parametersMatch() {
    Map<String, Object> p = map(root.get("params"));
    assertEquals(str(p, "q"), Fp.Q_BIG.toString(16));
    assertEquals(str(p, "n"), Fn.N_BIG.toString(16));
    assertEquals(str(p, "P1"), ConvertUtil.byteToHex(G1.encode(G1.P1)));
    assertEquals(str(p, "P2"), ConvertUtil.byteToHex(G2.encode(G2.P2)));
    assertEquals(SM9.HID_SIGN, num(p, "hid_sign"));
    assertEquals(SM9.HID_EXCHANGE, num(p, "hid_exchange"));
    assertEquals(SM9.HID_ENCRYPT, num(p, "hid_encrypt"));
  }

  @Test
  public void standardSignature() {
    Map<String, Object> v = standard("sign");
    String ks = str(v, "master_private_key");
    String mpk = str(v, "master_public_key");
    assertEquals(mpk, SM9.signMasterPublicKey(ks));
    SM9Core.MasterKey master = SM9Core.signMaster(unhex(mpk));
    assertEquals(str(v, "pairing_g"), ConvertUtil.byteToHex(Fp12.encode(master.pairing)));
    byte[] id = utf8(str(v, "user_id"));
    int hid = num(v, "hid");
    String ds = SM9.genSignUserKey(ks, id, hid);
    assertEquals(str(v, "user_private_key"), ds);
    byte[] msg = utf8(str(v, "message"));
    String sig = SM9.signWithRandom(msg, ds, mpk, str(v, "r"));
    assertEquals(str(v, "signature"), sig);
    assertTrue(SM9.verify(msg, sig, id, mpk, hid));
    assertTrue(SM9.verify(str(v, "message"), sig, str(v, "user_id"), mpk));
    assertFalse(SM9.verify(msg, sig, utf8("Bob"), mpk, hid));
  }

  @Test
  public void standardKeyExchange() {
    Map<String, Object> v = standard("exchange");
    assertEquals(SM9.HID_EXCHANGE, num(v, "hid"));
    checkExchange(v, str(v, "master_private_key"), str(v, "master_public_key"));
  }

  @Test
  public void standardEncapsulation() {
    Map<String, Object> v = standard("encapsulate");
    assertEquals(SM9.HID_ENCRYPT, num(v, "hid"));
    String mpk = str(v, "master_public_key");
    assertEquals(mpk, SM9.encMasterPublicKey(str(v, "master_private_key")));
    checkEncapsulation(v, str(v, "master_private_key"), mpk);
  }

  @Test
  public void standardEncryption() {
    Map<String, Object> v = standard("encrypt");
    assertEquals(SM9.HID_ENCRYPT, num(v, "hid"));
    String mpk = str(v, "master_public_key");
    assertEquals(mpk, SM9.encMasterPublicKey(str(v, "master_private_key")));
    checkEncryption(v, str(v, "master_private_key"), mpk, utf8(str(v, "plaintext")));
  }

  @Test
  public void extraMasterKeys() {
    Map<String, Object> e = extra();
    assertEquals(
        str(e, "sign_master_public_key"),
        SM9.signMasterPublicKey(str(e, "sign_master_private_key")));
    assertEquals(
        str(e, "enc_master_public_key"), SM9.encMasterPublicKey(str(e, "enc_master_private_key")));
  }

  @Test
  public void extraSignatures() {
    Map<String, Object> e = extra();
    String ks = str(e, "sign_master_private_key");
    String mpk = str(e, "sign_master_public_key");
    List<Object> cases = list(e.get("sign"));
    assertEquals(4, cases.size());
    for (Object o : cases) {
      Map<String, Object> v = map(o);
      byte[] id = utf8(str(v, "user_id"));
      String ds = SM9.genSignUserKey(ks, id, SM9.HID_SIGN);
      assertEquals(str(v, "user_private_key"), ds);
      byte[] msg = unhex(str(v, "message_hex"));
      String sig = SM9.signWithRandom(msg, ds, mpk, str(v, "r"));
      assertEquals(str(v, "signature"), sig);
      assertTrue(SM9.verify(msg, sig, id, mpk, SM9.HID_SIGN));
    }
  }

  @Test
  public void extraEncryption() {
    Map<String, Object> e = extra();
    List<Object> cases = list(e.get("encrypt"));
    assertEquals(4, cases.size());
    for (Object o : cases) {
      Map<String, Object> v = map(o);
      checkEncryption(
          v,
          str(e, "enc_master_private_key"),
          str(e, "enc_master_public_key"),
          unhex(str(v, "plaintext_hex")));
    }
  }

  @Test
  public void extraEncapsulation() {
    Map<String, Object> e = extra();
    List<Object> cases = list(e.get("encapsulate"));
    assertEquals(4, cases.size());
    for (Object o : cases) {
      checkEncapsulation(map(o), str(e, "enc_master_private_key"), str(e, "enc_master_public_key"));
    }
  }

  @Test
  public void extraKeyExchange() {
    Map<String, Object> e = extra();
    List<Object> cases = list(e.get("exchange"));
    assertEquals(3, cases.size());
    for (Object o : cases) {
      checkExchange(map(o), str(e, "enc_master_private_key"), str(e, "enc_master_public_key"));
    }
  }

  private static void checkEncryption(
      Map<String, Object> v, String ke, String mpk, byte[] plaintext) {
    byte[] id = utf8(str(v, "user_id"));
    String de = SM9.genEncUserKey(ke, id, SM9.HID_ENCRYPT);
    assertEquals(str(v, "user_private_key"), de);
    String r = str(v, "r");
    String stream =
        SM9.encryptWithRandom(plaintext, id, mpk, SM9.HID_ENCRYPT, SM9CipherMode.STREAM, r);
    assertEquals(str(v, "ciphertext_stream"), stream);
    String sm4 = SM9.encryptWithRandom(plaintext, id, mpk, SM9.HID_ENCRYPT, SM9CipherMode.SM4, r);
    assertEquals(str(v, "ciphertext_sm4"), sm4);
    assertEquals(
        ConvertUtil.byteToHex(plaintext),
        ConvertUtil.byteToHex(SM9.decryptToBytes(stream, id, de, SM9CipherMode.STREAM)));
    assertEquals(
        ConvertUtil.byteToHex(plaintext),
        ConvertUtil.byteToHex(SM9.decryptToBytes(sm4, id, de, SM9CipherMode.SM4)));
  }

  private static void checkEncapsulation(Map<String, Object> v, String ke, String mpk) {
    byte[] id = utf8(str(v, "user_id"));
    String de = SM9.genEncUserKey(ke, id, SM9.HID_ENCRYPT);
    assertEquals(str(v, "user_private_key"), de);
    int klen = num(v, "key_len");
    SM9Encapsulation kc = SM9.encapsulateWithRandom(id, mpk, klen, SM9.HID_ENCRYPT, str(v, "r"));
    assertEquals(str(v, "key"), kc.getKey());
    assertEquals(str(v, "ciphertext"), kc.getCiphertext());
    assertEquals(str(v, "key"), SM9.decapsulate(kc.getCiphertext(), id, de, klen));
  }

  private static void checkExchange(Map<String, Object> v, String ke, String mpk) {
    byte[] idA = utf8(str(v, "id_a"));
    byte[] idB = utf8(str(v, "id_b"));
    String deA = SM9.genEncUserKey(ke, idA, SM9.HID_EXCHANGE);
    String deB = SM9.genEncUserKey(ke, idB, SM9.HID_EXCHANGE);
    assertEquals(str(v, "user_private_key_a"), deA);
    assertEquals(str(v, "user_private_key_b"), deB);
    String ra = str(v, "r_a");
    String rb = str(v, "r_b");
    String pointA = SM9.exchangeInitWithRandom(idB, mpk, SM9.HID_EXCHANGE, ra);
    String pointB = SM9.exchangeInitWithRandom(idA, mpk, SM9.HID_EXCHANGE, rb);
    assertEquals(str(v, "R_a"), pointA);
    assertEquals(str(v, "R_b"), pointB);
    int klen = num(v, "key_len");
    SM9ExchangeResult b = SM9.exchangeRespond(klen, idA, idB, mpk, deB, rb, pointB, pointA);
    assertTrue(b.getMessage(), b.isSuccess());
    assertEquals(str(v, "shared_key"), b.getSharedKey());
    assertEquals(str(v, "s_b"), b.getSb());
    SM9ExchangeResult a =
        SM9.exchangeConfirm(klen, idA, idB, mpk, deA, ra, pointA, pointB, b.getSb());
    assertTrue(a.getMessage(), a.isSuccess());
    assertEquals(str(v, "shared_key"), a.getSharedKey());
    assertEquals(str(v, "s_a"), a.getSa());
    assertTrue(SM9.exchangeCheck(b.getS2(), a.getSa()));
  }

  @Test
  public void invalidG1PointsAreRejected() {
    Map<String, Object> e = extra();
    String ke = str(e, "enc_master_private_key");
    String mpk = str(e, "enc_master_public_key");
    String de = SM9.genEncUserKey(ke, utf8("Bob"), SM9.HID_ENCRYPT);
    String deX = SM9.genEncUserKey(ke, utf8("Bob"), SM9.HID_EXCHANGE);
    String deA = SM9.genEncUserKey(ke, utf8("Alice"), SM9.HID_EXCHANGE);
    String ksMpk = str(e, "sign_master_public_key");
    SM9KeyPair a = SM9.exchangeInit("Bob", mpk);
    SM9KeyPair b = SM9.exchangeInit("Alice", mpk);
    List<Object> points = list(map(root.get("invalid_points")).get("g1"));
    assertEquals(10, points.size());
    for (Object o : points) {
      Map<String, Object> p = map(o);
      String name = str(p, "name");
      String bad = str(p, "value");
      rejects(name + " as Ppub-e", () -> SM9.encrypt("m", "Bob", bad));
      rejects(name + " as Ppub-e (KEM)", () -> SM9.encapsulate("Bob", bad, 16));
      rejects(name + " as Ppub-e (init)", () -> SM9.exchangeInit("Bob", bad));
      rejects(name + " as ds", () -> SM9.sign("m", bad, ksMpk));
      rejects(name + " as KEM C", () -> SM9.decapsulate(bad, "Bob", de, 16));
      String ct = bad + "00000000000000000000000000000000000000000000000000000000000000000000";
      rejects(name + " as C1", () -> SM9.decrypt(ct, "Bob", de));
      assertFalse(
          name + " as R_A",
          SM9.exchangeRespond(
                  16, "Alice", "Bob", mpk, deX, b.getPrivateKey(), b.getPublicKey(), bad)
              .isSuccess());
      assertFalse(
          name + " as R_B",
          SM9.exchangeConfirm(
                  16, "Alice", "Bob", mpk, deA, a.getPrivateKey(), a.getPublicKey(), bad, zeros(64))
              .isSuccess());
      if (bad.length() == 130) {
        String sig = zeros(64) + bad;
        assertFalse(name + " as S", SM9.verify("m", sig.toLowerCase(Locale.ROOT), "Alice", ksMpk));
      }
    }
  }

  @Test
  public void invalidG2PointsAreRejected() {
    Map<String, Object> e = extra();
    String ks = str(e, "sign_master_private_key");
    String ds = SM9.genSignUserKey(ks, "Alice");
    String sig = SM9.sign("m", ds, str(e, "sign_master_public_key"));
    String mpk = str(e, "enc_master_public_key");
    SM9KeyPair a = SM9.exchangeInit("Bob", mpk);
    SM9KeyPair b = SM9.exchangeInit("Alice", mpk);
    String ct = SM9.encrypt("m", "Bob", mpk);
    SM9Encapsulation kc = SM9.encapsulate("Bob", mpk, 16);
    List<Object> points = list(map(root.get("invalid_points")).get("g2"));
    assertEquals(8, points.size());
    for (Object o : points) {
      Map<String, Object> p = map(o);
      String name = str(p, "name");
      String bad = str(p, "value");
      rejects(name + " as Ppub-s", () -> SM9.sign("m", ds, bad));
      assertFalse(name + " as Ppub-s (verify)", SM9.verify("m", sig, "Alice", bad));
      rejects(name + " as de", () -> SM9.decrypt(ct, "Bob", bad));
      rejects(name + " as de (KEM)", () -> SM9.decapsulate(kc.getCiphertext(), "Bob", bad, 16));
      assertFalse(
          name + " as de_B",
          SM9.exchangeRespond(
                  16,
                  "Alice",
                  "Bob",
                  mpk,
                  bad,
                  b.getPrivateKey(),
                  b.getPublicKey(),
                  a.getPublicKey())
              .isSuccess());
    }
  }

  @Test
  public void invalidScalarsAreRejected() {
    List<Object> scalars = list(root.get("invalid_scalars"));
    assertEquals(6, scalars.size());
    String mpk = str(extra(), "enc_master_public_key");
    String deA =
        SM9.genEncUserKey(
            str(extra(), "enc_master_private_key"),
            "Alice".getBytes(StandardCharsets.UTF_8),
            SM9.HID_EXCHANGE);
    SM9KeyPair a = SM9.exchangeInit("Bob", mpk);
    SM9KeyPair b = SM9.exchangeInit("Alice", mpk);
    for (Object o : scalars) {
      Map<String, Object> s = map(o);
      String name = str(s, "name");
      String bad = str(s, "value");
      rejects(name, () -> SM9.signMasterPublicKey(bad));
      rejects(name, () -> SM9.encMasterPublicKey(bad));
      rejects(name, () -> SM9.genSignUserKey(bad, "Alice"));
      rejects(name, () -> SM9.genEncUserKey(bad, "Alice"));
      assertFalse(
          name + " as r_A",
          SM9.exchangeConfirm(
                  16, "Alice", "Bob", mpk, deA, bad, a.getPublicKey(), b.getPublicKey(), zeros(64))
              .isSuccess());
    }
    String max = (String) root.get("max_valid_master_private_key");
    assertEquals(Fn.N_BIG.subtract(java.math.BigInteger.ONE).toString(16), max);
    String pub = SM9.signMasterPublicKey(max);
    assertEquals(SM9.signMasterPublicKey(max.toUpperCase(Locale.ROOT)), pub);
    SM9.encMasterPublicKey(max);
    String ds = SM9.genSignUserKey(max, "Alice");
    assertTrue(SM9.verify("m", SM9.sign("m", ds, pub), "Alice", pub));
  }

  private static String zeros(int n) {
    StringBuilder b = new StringBuilder();
    for (int i = 0; i < n; i++) {
      b.append('0');
    }
    return b.toString();
  }

  interface Call {
    void run() throws Exception;
  }

  static void rejects(String what, Call call) {
    try {
      call.run();
      fail(what + " was accepted");
    } catch (IllegalArgumentException expected) {
      // The one failure type for invalid input.
    } catch (Exception e) {
      throw new AssertionError(what + " threw " + e, e);
    }
  }
}
