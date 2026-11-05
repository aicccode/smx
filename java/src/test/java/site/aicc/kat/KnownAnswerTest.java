package site.aicc.kat;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.Test;
import site.aicc.sm2.SM2;
import site.aicc.sm2.SM2KeySwapParams;
import site.aicc.sm2.ec.AbstractECPoint;
import site.aicc.sm2.util.ConvertUtil;
import site.aicc.sm3.SM3;
import site.aicc.sm4.SM4;

/**
 * Known-answer tests. Standard vectors come from GB/T 32905, GB/T 32907 and GB/T 32918.5; {@code
 * kat-vectors.txt} was written by the unoptimized implementation (commit 3397c6d) and freezes its
 * outputs. This class passes unchanged against that implementation.
 */
public class KnownAnswerTest {
  private static final BigInteger N =
      new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16);

  private static List<String[]> vectors(String kind) throws Exception {
    List<String[]> out = new ArrayList<>();
    try (InputStream in = KnownAnswerTest.class.getResourceAsStream("/site/aicc/kat-vectors.txt");
        BufferedReader reader =
            new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
      String line;
      while ((line = reader.readLine()) != null) {
        // Fields of SM4 vectors can be empty, so keep trailing empties.
        String[] fields = line.split(" ", -1);
        if (fields[0].equals(kind)) {
          out.add(fields);
        }
      }
    }
    assertFalse("no vectors of kind " + kind, out.isEmpty());
    return out;
  }

  private static String utf8(String hex) {
    return new String(ConvertUtil.hexToByte(hex), StandardCharsets.UTF_8);
  }

  private static String encode(AbstractECPoint p) {
    return p.isInfinity() ? "inf" : ConvertUtil.byteToHex(p.getEncoded());
  }

  // ---------------------------------------------------------------- SM3

  @Test
  public void sm3StandardVectors() {
    assertEquals(
        "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0",
        new SM3().update("abc").finish().getHashCode());
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < 16; i++) {
      sb.append("abcd");
    }
    assertEquals(
        "DEBE9FF92275B8A138604889C18E5A4D6FDB70E5387E5765293DCBA39C0C5732",
        new SM3().update(sb.toString()).finish().getHashCode());
  }

  @Test
  public void sm3MillionA() {
    byte[] data = new byte[1000000];
    Arrays.fill(data, (byte) 'a');
    assertEquals(
        "C8AAF89429554029E231941A2ACC0AD61FF2A5ACD8FADD25847A3A732B3B02C3",
        new SM3().update(data, 0, data.length).finish().getHashCode());
  }

  @Test
  public void sm3FrozenLengthsWithEverySplit() throws Exception {
    for (String[] v : vectors("sm3")) {
      int len = Integer.parseInt(v[1]);
      byte[] m = new byte[len + 3];
      for (int i = 0; i < len; i++) {
        m[i + 3] = (byte) (i * 31 + 7);
      }
      assertEquals(v[2], new SM3().update(m, 3, len).finish().getHashCode());
      SM3 single = new SM3();
      for (int i = 0; i < len; i++) {
        single.update(m[i + 3]);
      }
      assertEquals(v[2], single.finish().getHashCode());
      int step = len > 200 ? 37 : 1;
      for (int split = 0; split <= len; split += step) {
        SM3 two = new SM3().update(m, 3, split).update(m, 3 + split, len - split);
        assertEquals(v[2], two.finish().getHashCode());
      }
    }
  }

  @Test
  public void sm3FinishResetsAndKeepsEarlierResults() {
    SM3 sm3 = new SM3();
    assertNull(sm3.getHashCode());
    assertNull(sm3.getHashBytes());
    byte[] first = sm3.update("abc").finish().getHashBytes();
    String firstHex = sm3.getHashCode();
    // An in-progress update does not disturb the published result.
    sm3.update("abc");
    assertEquals(firstHex, sm3.getHashCode());
    byte[] second = sm3.finish().getHashBytes();
    assertArrayEquals(first, second);
    assertTrue("each finish publishes a fresh array", first != second);
    first[0] ^= 1;
    assertEquals(
        "1AB21D8355CFA17F8E61194831E81A8F22BEC8C728FEFB747ED035EB5082AA2B",
        sm3.finish().getHashCode());
  }

  @Test
  public void sm3OutOfRangeAndNonPositiveLengths() {
    SM3 sm3 = new SM3();
    sm3.update((byte[]) null, 0, 0);
    sm3.update(new byte[4], 100, -1);
    try {
      sm3.update(new byte[4], 2, 3);
      fail();
    } catch (IndexOutOfBoundsException expected) {
      assertNotNull(expected);
    }
  }

  // ---------------------------------------------------------------- SM4

  private static final String SM4_KEY = "0123456789abcdeffedcba9876543210";

  /**
   * Encrypts raw blocks with a zero IV; the first block is plain ECB, as the standard specifies.
   */
  private static byte[] sm4Block(SM4 sm4, Method raw, byte[] block) throws Exception {
    String hex = (String) raw.invoke(sm4, block, new byte[16], true);
    return Arrays.copyOf(ConvertUtil.hexToByte(hex), 16);
  }

  private static Method sm4Raw() throws Exception {
    Method raw =
        SM4.class.getDeclaredMethod("processBlocks", byte[].class, byte[].class, boolean.class);
    raw.setAccessible(true);
    return raw;
  }

  @Test
  public void sm4StandardVectorAndMillionIterations() throws Exception {
    SM4 sm4 = new SM4().setKey(SM4_KEY, "00000000000000000000000000000000", true);
    Method raw = sm4Raw();
    byte[] block = ConvertUtil.hexToByte(SM4_KEY);
    block = sm4Block(sm4, raw, block);
    assertEquals("681edf34d206965e86b3e94f536e4246", ConvertUtil.byteToHex(block));
    for (int i = 1; i < 1000000; i++) {
      block = sm4Block(sm4, raw, block);
    }
    assertEquals("595298c7c6fd271f0402f804c33d3f66", ConvertUtil.byteToHex(block));
  }

  @Test
  public void sm4FrozenCbcVectors() throws Exception {
    for (String[] v : vectors("sm4")) {
      SM4 sm4 = new SM4().setKey(utf8(v[2]), utf8(v[3]), Boolean.parseBoolean(v[1]));
      String message = utf8(v[4]);
      assertEquals(v[5], sm4.encrypt(message));
      assertEquals(message, sm4.decrypt(v[5]));
      assertEquals(message, sm4.decrypt(v[5].toUpperCase()));
    }
  }

  @Test
  public void sm4CbcMatchesOpenssl() throws Exception {
    // openssl enc -sm4-cbc -K ffeedd... -iv 000102... (PKCS#7) on "hello, sm4 cbc openssl check!".
    SM4 sm4 =
        new SM4()
            .setKey("ffeeddccbbaa99887766554433221100", "000102030405060708090a0b0c0d0e0f", true);
    assertEquals(OPENSSL_CBC, sm4.encrypt("hello, sm4 cbc openssl check!"));
    assertEquals("hello, sm4 cbc openssl check!", sm4.decrypt(OPENSSL_CBC));
  }

  private static final String OPENSSL_CBC =
      "17dca70797ce0d8be4f3a37c7470400ef015ac7d0cf384b77a1de98e66227bd3";

  @Test
  public void sm4LenientInputsKeepTheirBehavior() throws Exception {
    SM4 sm4 = new SM4().setKey(SM4_KEY, "00000000000000000000000000000000", true);
    String ct = sm4.encrypt("exactly-16-bytes");
    // Trailing partial blocks are dropped.
    assertEquals("exactly-16-bytes", sm4.decrypt(ct + "abcd"));
    // Integer.parseInt semantics: a sign is a legal first character of a hex pair.
    assertEquals(
        new SM4().setKey("0a" + SM4_KEY.substring(2), "00", true).encrypt("x"),
        new SM4().setKey("+a" + SM4_KEY.substring(2), "00", true).encrypt("x"));
    assertEquals(
        new SM4().setKey("f6" + SM4_KEY.substring(2), "00", true).encrypt("x"),
        new SM4().setKey("-a" + SM4_KEY.substring(2), "00", true).encrypt("x"));
    assertEquals(
        new SM4().setKey("0a" + SM4_KEY.substring(2), "00", true).encrypt("x"),
        new SM4().setKey("０a" + SM4_KEY.substring(2), "00", true).encrypt("x"));
    try {
      sm4.decrypt("zz");
      fail();
    } catch (NumberFormatException expected) {
      assertNotNull(expected);
    }
    try {
      sm4.decrypt("abc");
      fail();
    } catch (ArrayIndexOutOfBoundsException expected) {
      assertNotNull(expected);
    }
    try {
      sm4.decrypt("");
      fail();
    } catch (ArrayIndexOutOfBoundsException expected) {
      assertNotNull(expected);
    }
    try {
      new SM4().setKey(SM4_KEY + SM4_KEY, "00", true);
      fail();
    } catch (ArrayIndexOutOfBoundsException expected) {
      assertNotNull(expected);
    }
    // A key that was never set means an all-zero round key schedule and IV.
    SM4 unset = new SM4();
    assertEquals("x", unset.decrypt(unset.encrypt("x")));
    assertEquals(SM4.bytes2Hex(new byte[] {(byte) 0xAB}, true), "AB");
    assertEquals(SM4.bytes2Hex(new byte[] {(byte) 0xAB}, false), "ab");
  }

  // ---------------------------------------------------------------- SM2

  private static final String GBT_D =
      "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8";
  private static final String GBT_PUB =
      "0409F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020"
          + "CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13";
  private static final String GBT_SIG =
      "F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3"
          + "h"
          + "B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA";

  @Test
  public void sm2StandardSignatureVector() throws Exception {
    assertEquals(
        GBT_PUB.toLowerCase(),
        ConvertUtil.byteToHex(SM2.getPublicKey(new BigInteger(GBT_D, 16)).getEncoded()));
    assertTrue(SM2.sm2VerifySign("1234567812345678", GBT_SIG, "message digest", GBT_PUB));
    assertFalse(SM2.sm2VerifySign("1234567812345678", GBT_SIG, "message digesu", GBT_PUB));
    assertFalse(SM2.sm2VerifySign("BOB", GBT_SIG, "message digest", GBT_PUB));
  }

  @Test
  public void sm2FrozenGeneratorMultiples() throws Exception {
    for (String[] v : vectors("gmul")) {
      assertEquals(v[1], v[2], encode(SM2.getPublicKey(new BigInteger(v[1], 16))));
    }
  }

  @Test
  public void sm2FrozenVariableBaseMultiples() throws Exception {
    for (String[] v : vectors("pmul")) {
      AbstractECPoint p = SM2.decodePoint(v[1]);
      assertEquals(v[2], v[3], encode(p.multiply(new BigInteger(v[2], 16))));
    }
  }

  @Test
  public void sm2FrozenCiphertextsDecrypt() throws Exception {
    for (String[] v : vectors("dec")) {
      assertEquals(utf8(v[3]), SM2.sm2Decrypt(v[2], v[1]));
    }
  }

  @Test
  public void sm2FrozenSignaturesVerify() throws Exception {
    for (String[] v : vectors("sig")) {
      String id = utf8(v[2]);
      String message = utf8(v[3]);
      assertTrue(SM2.sm2VerifySign(id, v[4], message, v[1]));
      assertTrue("raw 64-byte key", SM2.sm2VerifySign(id, v[4], message, v[1].substring(2)));
      assertFalse(SM2.sm2VerifySign(id, v[4], message + "x", v[1]));
      assertFalse(SM2.sm2VerifySign(id + "x", v[4], message, v[1]));
    }
  }

  @Test
  public void sm2FrozenKeyExchange() throws Exception {
    for (String[] v : vectors("kx")) {
      int len = Integer.parseInt(v[1]);
      BigInteger dA = new BigInteger(v[2], 16);
      BigInteger ra = new BigInteger(v[3], 16);
      BigInteger dB = new BigInteger(v[4], 16);
      BigInteger rb = new BigInteger(v[5], 16);
      AbstractECPoint pA = SM2.getPublicKey(dA);
      AbstractECPoint rA = SM2.getPublicKey(ra);
      AbstractECPoint pB = SM2.getPublicKey(dB);
      AbstractECPoint rB = SM2.getPublicKey(rb);
      SM2KeySwapParams b = SM2.getSb(len, pA, rA, pB, dB, rB, rb, v[6], v[7]);
      assertTrue(b.isSuccess());
      assertEquals(v[8], b.getKb());
      assertEquals(v[9], b.getSb());
      assertEquals(v[12], encode(b.getV()));
      assertEquals(v[13], ConvertUtil.byteToHex(b.getZa()));
      assertEquals(v[14], ConvertUtil.byteToHex(b.getZb()));
      SM2KeySwapParams a =
          SM2.getSa(len, pB, rB, pA, dA, rA, ra, v[6], v[7], ConvertUtil.hexToByte(v[9]));
      assertTrue(a.isSuccess());
      assertEquals(v[10], a.getKa());
      assertEquals(v[11], a.getSa());
      assertTrue(SM2.checkSa(b.getV(), b.getZa(), b.getZb(), rA, rB, ConvertUtil.hexToByte(v[11])));
      SM2KeySwapParams bad = SM2.getSa(len, pB, rB, pA, dA, rA, ra, v[6], v[7], new byte[32]);
      assertFalse(bad.isSuccess());
      assertEquals("Key exchange failed: B's verification value does not match.", bad.getMessage());
    }
  }

  @Test
  public void sm2SignThenVerifyAndFormat() throws Exception {
    String d = GBT_D.toLowerCase();
    for (int i = 0; i < 40; i++) {
      String sig = SM2.sm2Sign("id", "message " + i, d);
      assertEquals(129, sig.length());
      assertEquals(sig.toLowerCase(), sig);
      assertEquals('h', sig.charAt(64));
      // r and s are always drawn with a non-zero top hex digit.
      assertTrue(sig.charAt(0) != '0' && sig.charAt(65) != '0');
      assertTrue(SM2.sm2VerifySign("id", sig, "message " + i, GBT_PUB));
    }
  }

  @Test
  public void sm2EncryptDecryptRoundTripAndFormat() throws Exception {
    String d = GBT_D.toLowerCase();
    assertNull(SM2.sm2Encrypt("", GBT_PUB));
    for (int len : new int[] {1, 31, 32, 33, 64, 65, 500}) {
      char[] chars = new char[len];
      Arrays.fill(chars, 'q');
      String message = new String(chars);
      String ct = SM2.sm2Encrypt(message, GBT_PUB);
      assertEquals(2 * (65 + 32 + len), ct.length());
      assertEquals(ct.toLowerCase(), ct);
      assertTrue(ct.startsWith("04"));
      assertEquals(message, SM2.sm2Decrypt(ct, d));
    }
  }

  @Test
  public void sm2TamperedCiphertextsAreRejected() throws Exception {
    String d = GBT_D.toLowerCase();
    String ct = SM2.sm2Encrypt("attack at dawn", GBT_PUB);
    int[] flipPositions = {2, 131, 195, ct.length() - 1};
    for (int pos : flipPositions) {
      char c = ct.charAt(pos) == '0' ? '1' : '0';
      String bad = ct.substring(0, pos) + c + ct.substring(pos + 1);
      try {
        SM2.sm2Decrypt(bad, d);
        fail("position " + pos);
      } catch (IllegalArgumentException expected) {
        assertNotNull(expected);
      }
    }
    try {
      SM2.sm2Decrypt(ct.substring(0, 100), d);
      fail();
    } catch (IndexOutOfBoundsException expected) {
      assertNotNull(expected);
    }
    // Wrong key: C3 no longer matches.
    try {
      SM2.sm2Decrypt(ct, "01" + d.substring(2));
      fail();
    } catch (IllegalArgumentException expected) {
      assertEquals("Decryption failed", expected.getMessage());
    }
  }

  /** Quirks of the baseline that are reported rather than fixed, pinned so they cannot drift. */
  @Test
  public void sm2BaselineBehaviorIsPinned() throws Exception {
    String[] parts = GBT_SIG.split("h");
    BigInteger r = new BigInteger(parts[0], 16);
    BigInteger s = new BigInteger(parts[1], 16);
    String message = "message digest";
    String id = "1234567812345678";
    // s is not range checked: s - n (negative) and small s + n are accepted by the baseline.
    assertTrue(
        SM2.sm2VerifySign(id, r.toString(16) + "h" + s.subtract(N).toString(16), message, GBT_PUB));
    // s + n does not fit into 256 bits here, so the multiplier rejects it.
    assertFalse(
        SM2.sm2VerifySign(id, r.toString(16) + "h" + s.add(N).toString(16), message, GBT_PUB));
    assertFalse(
        SM2.sm2VerifySign(id, r.add(N).toString(16) + "h" + s.toString(16), message, GBT_PUB));
    assertFalse(SM2.sm2VerifySign(id, "nothing", message, GBT_PUB));
    assertFalse(SM2.sm2VerifySign(id, "h", message, GBT_PUB));
    assertFalse(SM2.sm2VerifySign(id, "zzhzz", message, GBT_PUB));
    assertFalse(SM2.sm2VerifySign(id, null, message, GBT_PUB));
    // r + s = n, t = 0.
    assertFalse(
        SM2.sm2VerifySign(id, r.toString(16) + "h" + N.subtract(r).toString(16), message, GBT_PUB));
    // s = 0 is computed, not short-circuited, and still fails.
    assertFalse(SM2.sm2VerifySign(id, r.toString(16) + "h0", message, GBT_PUB));
    // The format byte of an encoded point is ignored.
    assertEquals(
        encode(SM2.decodePoint(GBT_PUB)), encode(SM2.decodePoint("07" + GBT_PUB.substring(2))));
    try {
      SM2.decodePoint(GBT_PUB.substring(2));
      fail();
    } catch (IllegalArgumentException expected) {
      assertEquals("Invalid point encoding length", expected.getMessage());
    }
    try {
      SM2.decodePoint(GBT_PUB.substring(0, 128) + "ff");
      fail();
    } catch (IllegalArgumentException expected) {
      assertEquals("Point is not on the curve", expected.getMessage());
    }
    // A scalar wider than 256 bits is rejected by the multiplier installed in SM2.
    try {
      SM2.getPublicKey(BigInteger.ONE.shiftLeft(256));
      fail();
    } catch (IllegalStateException expected) {
      assertEquals("Invalid multiplier", expected.getMessage());
    }
    // sm2Sign reads the key as signed: a key with the top bit set signs as d - 2^256.
    BigInteger big = BigInteger.ONE.shiftLeft(255).add(BigInteger.TEN);
    String sig = SM2.sm2Sign(id, message, big.toString(16));
    String pub = encode(SM2.getPublicKey(big.subtract(BigInteger.ONE.shiftLeft(256))));
    assertTrue(SM2.sm2VerifySign(id, sig, message, pub));
    assertFalse(SM2.sm2VerifySign(id, sig, message, encode(SM2.getPublicKey(big))));
    // d = n - 1 (with a sign byte) has no valid signature: 1 + d is not invertible.
    try {
      SM2.sm2Sign(id, message, "00" + N.subtract(BigInteger.ONE).toString(16));
      fail();
    } catch (ArithmeticException expected) {
      assertNotNull(expected);
    }
  }

  @Test
  public void sm2GeneratedKeysKeepTheirShape() throws Exception {
    for (int i = 0; i < 10; i++) {
      site.aicc.sm2.keygen.ECKeyPair pair = SM2.genSM2KeyPair();
      assertEquals(64, pair.getHexPriKey().length());
      assertEquals(130, pair.getHexPubKey().length());
      AbstractECPoint q = pair.getPointPubKey();
      assertEquals(
          64,
          q.getXCoord().toBigInteger().toByteArray().length
              + q.getYCoord().toBigInteger().toByteArray().length);
      assertEquals(encode(SM2.getPublicKey(pair.getBIPriKey())), pair.getHexPubKey());
    }
  }

  @Test
  public void convertUtilBehavior() {
    assertTrue(ConvertUtil.byteArrayEqual(null, null));
    assertFalse(ConvertUtil.byteArrayEqual(new byte[1], null));
    assertFalse(ConvertUtil.byteArrayEqual(new byte[1], new byte[2]));
    assertTrue(ConvertUtil.byteArrayEqual(new byte[] {1, 2}, new byte[] {1, 2}));
    assertFalse(ConvertUtil.byteArrayEqual(new byte[] {1, 2}, new byte[] {1, 3}));
    assertArrayEquals(new byte[] {(byte) 0xab, 0x0c}, ConvertUtil.hexToByte("AB0c"));
    assertArrayEquals(new byte[] {10}, ConvertUtil.hexToByte("+a"));
    assertArrayEquals(new byte[] {(byte) 0xf6}, ConvertUtil.hexToByte("-a"));
    assertEquals("ab0c", ConvertUtil.byteToHex(new byte[] {(byte) 0xab, 0x0c}));
    assertEquals("AB0C", ConvertUtil.getHexString(new byte[] {(byte) 0xab, 0x0c}, true));
    try {
      ConvertUtil.hexToByte("abc");
      fail();
    } catch (IllegalArgumentException expected) {
      assertEquals("Input is not a hex string", expected.getMessage());
    }
    try {
      ConvertUtil.hexToByte("zz");
      fail();
    } catch (NumberFormatException expected) {
      assertNotNull(expected);
    }
  }
}
