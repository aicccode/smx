package site.aicc.sm2.ec;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.BeforeClass;
import org.junit.Test;
import site.aicc.sm2.SM2;
import site.aicc.sm2.util.ConvertUtil;
import site.aicc.sm3.SM3;
import site.aicc.sm4.SM4;

/** Asserts every case of the shared, independently generated testvectors/security-vectors.json. */
public class SecurityVectorsTest {
  private static Map<String, Object> sm2;
  private static Map<String, Object> sm3;
  private static Map<String, Object> sm4;

  /** A minimal JSON reader, enough for this file; the test tree takes no JSON dependency. */
  private static final class Json {
    private final String text;
    private int pos;

    Json(String text) {
      this.text = text;
    }

    Object value() {
      skip();
      char c = text.charAt(pos);
      if (c == '{') {
        pos++;
        Map<String, Object> map = new LinkedHashMap<>();
        skip();
        while (text.charAt(pos) != '}') {
          String key = string();
          skip();
          pos++; // ':'
          map.put(key, value());
          skip();
          if (text.charAt(pos) == ',') {
            pos++;
            skip();
          }
        }
        pos++;
        return map;
      }
      if (c == '[') {
        pos++;
        List<Object> list = new ArrayList<>();
        skip();
        while (text.charAt(pos) != ']') {
          list.add(value());
          skip();
          if (text.charAt(pos) == ',') {
            pos++;
            skip();
          }
        }
        pos++;
        return list;
      }
      if (c == '"') {
        return string();
      }
      int start = pos;
      while (pos < text.length() && ",]} \n\r\t".indexOf(text.charAt(pos)) < 0) {
        pos++;
      }
      return Long.valueOf(text.substring(start, pos));
    }

    private String string() {
      StringBuilder sb = new StringBuilder();
      pos++;
      while (text.charAt(pos) != '"') {
        char c = text.charAt(pos++);
        if (c == '\\') {
          char e = text.charAt(pos++);
          if (e == 'u') {
            sb.append((char) Integer.parseInt(text.substring(pos, pos + 4), 16));
            pos += 4;
          } else {
            sb.append(e == 'n' ? '\n' : e == 't' ? '\t' : e);
          }
        } else {
          sb.append(c);
        }
      }
      pos++;
      return sb.toString();
    }

    private void skip() {
      while (Character.isWhitespace(text.charAt(pos))) {
        pos++;
      }
    }
  }

  @BeforeClass
  @SuppressWarnings("unchecked")
  public static void load() throws IOException {
    Path path = Paths.get("../testvectors/security-vectors.json");
    if (!Files.exists(path)) {
      path = Paths.get("testvectors/security-vectors.json");
    }
    String text = new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
    Map<String, Object> root = (Map<String, Object>) new Json(text).value();
    sm2 = (Map<String, Object>) root.get("sm2");
    sm3 = (Map<String, Object>) root.get("sm3");
    sm4 = (Map<String, Object>) root.get("sm4");
  }

  @SuppressWarnings("unchecked")
  private static List<Map<String, Object>> cases(Map<String, Object> group, String key) {
    List<Map<String, Object>> list = (List<Map<String, Object>>) group.get(key);
    assertFalse(key, list.isEmpty());
    return list;
  }

  private static String s(Map<String, Object> group, String key) {
    return (String) group.get(key);
  }

  private static int count(Map<String, Object> group, String key) {
    return ((Long) group.get(key)).intValue();
  }

  @SuppressWarnings("unchecked")
  private static List<Long> lengths(String key) {
    return (List<Long>) sm4.get(key);
  }

  private static String hexOf(int bytes) {
    char[] c = new char[bytes * 2];
    Arrays.fill(c, 'a');
    return new String(c);
  }

  private static String repeat(char ch, int count) {
    char[] c = new char[count];
    Arrays.fill(c, ch);
    return new String(c);
  }

  private static void rejected(String name, org.junit.function.ThrowingRunnable call) {
    IllegalArgumentException e = assertThrows(name, IllegalArgumentException.class, call);
    assertTrue(name, e != null);
  }

  // ---------------------------------------------------------------- SM2

  @Test
  public void validKeySignatureAndCiphertext() throws Exception {
    String d = s(sm2, "private_key");
    String pub = s(sm2, "public_key");
    String id = s(sm2, "user_id");
    String message = s(sm2, "message");
    assertEquals(pub, ConvertUtil.byteToHex(SM2.getPublicKey(new BigInteger(d, 16)).getEncoded()));
    assertEquals(pub, ConvertUtil.byteToHex(SM2.decodePoint(pub).getEncoded()));
    String signature = s(sm2, "r") + "h" + s(sm2, "s");
    assertTrue(SM2.sm2VerifySign(id, signature, message, pub));
    assertEquals(s(sm2, "plaintext"), SM2.sm2Decrypt(s(sm2, "ciphertext"), d));
    String own = SM2.sm2Sign(id, message, d);
    assertTrue(SM2.sm2VerifySign(id, own, message, pub));
    assertEquals(s(sm2, "plaintext"), SM2.sm2Decrypt(SM2.sm2Encrypt(s(sm2, "plaintext"), pub), d));
  }

  @Test
  public void fixedNonceReproducesTheStandardSignature() {
    byte[] e = digest(s(sm2, "user_id"), s(sm2, "message"), s(sm2, "public_key"));
    byte[] signature =
        Sm2Engine.signWithNonce(
            Sm2Field.fromBytes(ConvertUtil.hexToByte(s(sm2, "private_key")), 0),
            Sm2Field.fromBytes(ConvertUtil.hexToByte(s(sm2, "nonce_k")), 0),
            e);
    assertArrayEquals(ConvertUtil.hexToByte(s(sm2, "r") + s(sm2, "s")), signature);
  }

  /** Recomputes e by hand from the standard's formula, independently of the library's Z code. */
  private static byte[] digest(String id, String message, String pub) {
    byte[] idBytes = id.getBytes(StandardCharsets.UTF_8);
    SM3 z = new SM3();
    int bits = idBytes.length * 8;
    z.update((byte) (bits >> 8)).update((byte) bits).update(idBytes, 0, idBytes.length);
    byte[] domain =
        ConvertUtil.hexToByte(
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"
                + "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"
                + "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"
                + "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"
                + pub.substring(2));
    z.update(domain, 0, domain.length);
    byte[] zHash = z.finish().getHashBytes();
    byte[] m = message.getBytes(StandardCharsets.UTF_8);
    return new SM3().update(zHash, 0, 32).update(m, 0, m.length).finish().getHashBytes();
  }

  @Test
  public void maximumPrivateKeyIsValid() throws Exception {
    String max = s(sm2, "n_minus_2_is_max_valid_private_key");
    AbstractECPoint pub = SM2.getPublicKey(new BigInteger(max, 16));
    String hexPub = ConvertUtil.byteToHex(pub.getEncoded());
    String signature = SM2.sm2Sign("id", "m", max);
    assertTrue(SM2.sm2VerifySign("id", signature, "m", hexPub));
    assertEquals("m", SM2.sm2Decrypt(SM2.sm2Encrypt("m", hexPub), max));
  }

  @Test
  public void invalidPublicKeys() {
    String signature = s(sm2, "r") + "h" + s(sm2, "s");
    for (Map<String, Object> c : cases(sm2, "invalid_public_keys")) {
      String name = s(c, "name");
      String value = s(c, "value");
      rejected(name, () -> SM2.decodePoint(value));
      rejected(name, () -> SM2.sm2Encrypt("m", value));
      assertFalse(name, SM2.sm2VerifySign(s(sm2, "user_id"), signature, s(sm2, "message"), value));
    }
  }

  @Test
  public void invalidPrivateKeys() {
    for (Map<String, Object> c : cases(sm2, "invalid_private_keys")) {
      String name = s(c, "name");
      String value = s(c, "value");
      rejected(name, () -> SM2.sm2Sign("id", "m", value));
      rejected(name, () -> SM2.sm2Decrypt(s(sm2, "ciphertext"), value));
    }
  }

  @Test
  public void invalidSignatures() {
    String id = s(sm2, "user_id");
    String message = s(sm2, "message");
    String pub = s(sm2, "public_key");
    for (Map<String, Object> c : cases(sm2, "invalid_signatures")) {
      assertFalse(s(c, "name"), SM2.sm2VerifySign(id, s(c, "r") + "h" + s(c, "s"), message, pub));
    }
  }

  @Test
  public void invalidCiphertexts() {
    String d = s(sm2, "private_key");
    for (Map<String, Object> c : cases(sm2, "invalid_ciphertexts")) {
      String name = s(c, "name");
      IllegalArgumentException e =
          assertThrows(
              name, IllegalArgumentException.class, () -> SM2.sm2Decrypt(s(c, "value"), d));
      assertEquals(name, "Decryption failed", e.getMessage());
    }
  }

  @Test
  public void userIdLengthLimit() throws Exception {
    String d = s(sm2, "private_key");
    String pub = s(sm2, "public_key");
    String ok = repeat('i', count(sm2, "user_id_max_bytes"));
    String tooLong = repeat('i', count(sm2, "user_id_first_invalid_bytes"));
    String signature = SM2.sm2Sign(ok, "m", d);
    assertTrue(SM2.sm2VerifySign(ok, signature, "m", pub));
    rejected("sign", () -> SM2.sm2Sign(tooLong, "m", d));
    assertFalse(SM2.sm2VerifySign(tooLong, signature, "m", pub));
    // 8192 * 8 wraps ENTL to zero, so it must also not collide with the empty ID.
    String forEmpty = SM2.sm2Sign("", "m", d);
    assertTrue(SM2.sm2VerifySign("", forEmpty, "m", pub));
    assertFalse(SM2.sm2VerifySign(tooLong, forEmpty, "m", pub));
  }

  // ---------------------------------------------------------------- SM3

  private static String zerosDigest(long mebibytes) {
    byte[] chunk = new byte[1 << 20];
    SM3 sm3 = new SM3();
    for (long i = 0; i < mebibytes; i++) {
      sm3.update(chunk, 0, chunk.length);
    }
    return ConvertUtil.byteToHex(sm3.finish().getHashBytes());
  }

  @Test
  public void sm3LengthBeyond512Mib() {
    assertEquals(s(sm3, "zeros_512_mib"), zerosDigest(512));
    assertEquals(s(sm3, "zeros_1024_mib"), zerosDigest(1024));
  }

  // ---------------------------------------------------------------- SM4

  private static SM4 sm4() {
    return new SM4().setKey(s(sm4, "key"), s(sm4, "iv"), true);
  }

  @Test
  public void sm4ValidPadding() throws Exception {
    assertEquals(
        s(sm4, "valid_padded_ciphertext"), sm4().encrypt(s(sm4, "valid_padded_plaintext")));
    assertEquals(
        s(sm4, "valid_padded_plaintext"), sm4().decrypt(s(sm4, "valid_padded_ciphertext")));
    // Plaintext of a full block's padding: exactly one all-padding block decrypts to "".
    assertEquals("", sm4().decrypt(s(sm4, "valid_full_padding_block_ciphertext")));
    assertEquals(s(sm4, "valid_full_padding_block_ciphertext"), sm4().encrypt(""));
  }

  @Test
  public void sm4InvalidKeyAndIvLengths() {
    for (Long length : lengths("invalid_key_lengths_bytes")) {
      String key = hexOf(length.intValue());
      rejected("key " + length, () -> new SM4().setKey(key, s(sm4, "iv"), true));
      String textKey = repeat('k', length.intValue());
      rejected("text key " + length, () -> new SM4().setKey(textKey, repeat('i', 16), false));
    }
    for (Long length : lengths("invalid_iv_lengths_bytes")) {
      String iv = hexOf(length.intValue());
      rejected("iv " + length, () -> new SM4().setKey(s(sm4, "key"), iv, true));
      String textIv = repeat('i', length.intValue());
      rejected("text iv " + length, () -> new SM4().setKey(repeat('k', 16), textIv, false));
    }
  }

  @Test
  public void sm4InvalidPaddingsAndLengthsShareOneError() {
    List<String> inputs = new ArrayList<>();
    for (Map<String, Object> c : cases(sm4, "invalid_paddings")) {
      inputs.add(s(c, "value"));
    }
    for (Long length : lengths("invalid_ciphertext_lengths_bytes")) {
      inputs.add(hexOf(length.intValue()));
    }
    for (String input : inputs) {
      IllegalArgumentException e =
          assertThrows(input, IllegalArgumentException.class, () -> sm4().decrypt(input));
      assertEquals(input, "SM4 decryption failed", e.getMessage());
    }
  }
}
