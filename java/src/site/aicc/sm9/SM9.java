package site.aicc.sm9;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import site.aicc.sm2.util.ConvertUtil;
import site.aicc.sm2.util.SystemRandom;

/**
 * SM9 identity-based cryptographic algorithms (GB/T 38635): signatures, key encapsulation,
 * encryption and key exchange over the 256-bit BN curve of the standard.
 *
 * <p>Conventions, as in the SM2 API of this library: keys and points are hex strings in and
 * lower-case hex out. Keys are case-insensitive and must decode to valid values (scalars in [1, N -
 * 1]; points on the curve, coordinates below q, not the identity, G2 points of order N);
 * signatures, ciphertexts and confirmation values must be lower-case. Invalid input raises {@link
 * IllegalArgumentException}, except {@link #verify} and {@link #exchangeCheck}, which return false,
 * and the key exchange steps, which return a failed result. A failing random source raises {@link
 * IllegalStateException}. String identities and messages are UTF-8; byte[] overloads take raw
 * bytes. Every {@code hid} is a byte value 0-255.
 *
 * <p>Encodings: G1 point {@code 04 || x || y}; G2 point {@code 04 || x1 || x0 || y1 || y0};
 * signature {@code h || S}; ciphertext {@code C1 || C3 || C2} with C1 a G1 point.
 *
 * <p>Security: field arithmetic is in fixed 32-bit limbs (Montgomery form) with no value-dependent
 * branch or index. Secret scalars (master keys, r, l, t2) drive G1/G2 multiplication with complete
 * formulas and 4-bit fixed windows over fully scanned tables, and GT exponentiation the same way.
 * The MAC of decryption and the key exchange confirmations are compared in constant time.
 *
 * <p>Performance: the most recent signing and encryption master public keys are cached with their
 * pairing values e(P1, Ppub-s) and e(Ppub-e, P2); from the second use, powers of those values use
 * a fixed-base table (384 KB per cached key). P1 and P2 have lazily built fixed-base tables (96 KB
 * and 192 KB). In stream mode a 16-byte C2 derives the same key bytes as SM4 mode, so such a
 * ciphertext passes the MAC in either mode; pass the mode that was used to encrypt.
 */
public final class SM9 {
  public static final int HID_SIGN = 1;
  public static final int HID_EXCHANGE = 2;
  public static final int HID_ENCRYPT = 3;

  /** Largest key length, in bytes, of key encapsulation and key exchange. */
  public static final int MAX_KEY_BYTES = 1 << 20;

  private static final int SCALAR_HEX = 64;
  private static final int G1_HEX = 2 * G1.BYTES;
  private static final int G2_HEX = 2 * G2.BYTES;
  private static final int MAX_ATTEMPTS = 64;
  private static final int MAX_PLAINTEXT_BYTES = Integer.MAX_VALUE / 2 - 1024;

  private SM9() {}

  // ---------------------------------------------------------------- keys

  /** Generates a signing master key pair: ks and Ppub-s = [ks] P2 (G2). */
  public static SM9KeyPair genSignMasterKey() {
    int[] ks = Fn.random(SystemRandom.get());
    try {
      return new SM9KeyPair(hex(Fn.toBytes(ks)), hex(G2.encode(G2.mulGenerator(ks))));
    } finally {
      Arrays.fill(ks, 0);
    }
  }

  /** Ppub-s = [ks] P2 of a signing master private key. */
  public static String signMasterPublicKey(String masterPrivateKey) {
    int[] ks = scalar(masterPrivateKey, "Invalid master private key");
    try {
      return hex(G2.encode(G2.mulGenerator(ks)));
    } finally {
      Arrays.fill(ks, 0);
    }
  }

  /** The signing private key of a UTF-8 identity with hid {@link #HID_SIGN}. */
  public static String genSignUserKey(String masterPrivateKey, String userId) {
    return genSignUserKey(masterPrivateKey, utf8(userId), HID_SIGN);
  }

  /** ds = [ks / (H1(ID || hid) + ks)] P1 (G1). */
  public static String genSignUserKey(String masterPrivateKey, byte[] userId, int hid) {
    checkId(userId);
    checkHid(hid);
    int[] ks = scalar(masterPrivateKey, "Invalid master private key");
    try {
      return hex(G1.encode(SM9Core.signUserKey(ks, userId, hid)));
    } finally {
      Arrays.fill(ks, 0);
    }
  }

  /** Generates an encryption master key pair: ke and Ppub-e = [ke] P1 (G1). */
  public static SM9KeyPair genEncMasterKey() {
    int[] ke = Fn.random(SystemRandom.get());
    try {
      return new SM9KeyPair(hex(Fn.toBytes(ke)), hex(G1.encode(G1.mulGenerator(ke))));
    } finally {
      Arrays.fill(ke, 0);
    }
  }

  /** Ppub-e = [ke] P1 of an encryption master private key. */
  public static String encMasterPublicKey(String masterPrivateKey) {
    int[] ke = scalar(masterPrivateKey, "Invalid master private key");
    try {
      return hex(G1.encode(G1.mulGenerator(ke)));
    } finally {
      Arrays.fill(ke, 0);
    }
  }

  /** The encryption private key of a UTF-8 identity with hid {@link #HID_ENCRYPT}. */
  public static String genEncUserKey(String masterPrivateKey, String userId) {
    return genEncUserKey(masterPrivateKey, utf8(userId), HID_ENCRYPT);
  }

  /**
   * de = [ke / (H1(ID || hid) + ke)] P2 (G2). Key exchange keys are encryption keys made with hid
   * {@link #HID_EXCHANGE}.
   */
  public static String genEncUserKey(String masterPrivateKey, byte[] userId, int hid) {
    checkId(userId);
    checkHid(hid);
    int[] ke = scalar(masterPrivateKey, "Invalid master private key");
    try {
      return hex(G2.encode(SM9Core.encUserKey(ke, userId, hid)));
    } finally {
      Arrays.fill(ke, 0);
    }
  }

  // ---------------------------------------------------------------- signatures

  /** Signs the UTF-8 encoding of a message; returns h || S. */
  public static String sign(String message, String userPrivateKey, String masterPublicKey) {
    return sign(utf8(message), userPrivateKey, masterPublicKey);
  }

  /** Signs message bytes with a signing private key under Ppub-s; returns h || S. */
  public static String sign(byte[] message, String userPrivateKey, String masterPublicKey) {
    if (message == null) {
      throw new IllegalArgumentException("Message is null");
    }
    int[] ds = signKey(userPrivateKey);
    SM9Core.MasterKey master = signMaster(masterPublicKey);
    try {
      for (int i = 0; i < MAX_ATTEMPTS; i++) {
        int[] r = Fn.random(SystemRandom.get());
        byte[] sig = SM9Core.sign(message, ds, master, r);
        Arrays.fill(r, 0);
        if (sig != null) {
          return hex(sig);
        }
      }
      throw new IllegalStateException("Secure random source failed");
    } finally {
      Arrays.fill(ds, 0);
    }
  }

  /** Signs with a given r, for known-answer tests. */
  static String signWithRandom(
      byte[] message, String userPrivateKey, String masterPublicKey, String r) {
    int[] ds = signKey(userPrivateKey);
    byte[] sig = SM9Core.sign(message, ds, signMaster(masterPublicKey), scalar(r, "Invalid r"));
    if (sig == null) {
      throw new IllegalArgumentException("r gives l = 0");
    }
    return hex(sig);
  }

  /** Verifies a signature of a UTF-8 message by a UTF-8 identity with hid {@link #HID_SIGN}. */
  public static boolean verify(
      String message, String signature, String userId, String masterPublicKey) {
    if (message == null || userId == null) {
      return false;
    }
    try {
      return verify(utf8(message), signature, utf8(userId), masterPublicKey, HID_SIGN);
    } catch (IllegalArgumentException e) {
      return false;
    }
  }

  /** Verifies h || S; every invalid input of any kind gives false. */
  public static boolean verify(
      byte[] message, String signature, byte[] userId, String masterPublicKey, int hid) {
    if (message == null
        || signature == null
        || userId == null
        || masterPublicKey == null
        || signature.length() != 2 * SM9Core.SIGNATURE_BYTES
        || masterPublicKey.length() != G2_HEX
        || hid < 0
        || hid > 255) {
      return false;
    }
    try {
      byte[] sig = ConvertUtil.canonicalHexToByte(signature);
      SM9Core.MasterKey master = SM9Core.signMaster(ConvertUtil.hexToByte(masterPublicKey));
      return master != null && SM9Core.verify(message, sig, userId, hid, master);
    } catch (IllegalArgumentException e) {
      return false;
    }
  }

  // ---------------------------------------------------------------- encryption

  /** Encrypts the UTF-8 encoding of a text for a UTF-8 identity in stream mode, hid 3. */
  public static String encrypt(String plaintext, String userId, String masterPublicKey) {
    return encrypt(plaintext, userId, masterPublicKey, SM9CipherMode.STREAM);
  }

  /** Encrypts the UTF-8 encoding of a text for a UTF-8 identity, hid 3. */
  public static String encrypt(
      String plaintext, String userId, String masterPublicKey, SM9CipherMode mode) {
    byte[] plain = utf8(plaintext);
    try {
      return encrypt(plain, utf8(userId), masterPublicKey, HID_ENCRYPT, mode);
    } finally {
      Arrays.fill(plain, (byte) 0);
    }
  }

  /**
   * Encrypts a non-empty plaintext to an identity; returns C1 || C3 || C2. Empty plaintexts are
   * rejected, as in SM2.
   */
  public static String encrypt(
      byte[] plaintext, byte[] userId, String masterPublicKey, int hid, SM9CipherMode mode) {
    checkPlaintext(plaintext);
    checkId(userId);
    checkHid(hid);
    boolean sm4 = isSm4(mode);
    SM9Core.MasterKey master = encMaster(masterPublicKey);
    for (int i = 0; i < MAX_ATTEMPTS; i++) {
      int[] r = Fn.random(SystemRandom.get());
      byte[] c = SM9Core.encrypt(plaintext, userId, hid, master, r, sm4);
      Arrays.fill(r, 0);
      if (c != null) {
        return hex(c);
      }
    }
    throw new IllegalStateException("Secure random source failed");
  }

  /** Encrypts with a given r, for known-answer tests. */
  static String encryptWithRandom(
      byte[] plaintext,
      byte[] userId,
      String masterPublicKey,
      int hid,
      SM9CipherMode mode,
      String r) {
    checkPlaintext(plaintext);
    byte[] c =
        SM9Core.encrypt(
            plaintext,
            userId,
            hid,
            encMaster(masterPublicKey),
            scalar(r, "Invalid r"),
            isSm4(mode));
    if (c == null) {
      throw new IllegalArgumentException("r gives an all-zero key");
    }
    return hex(c);
  }

  /** Decrypts a stream-mode ciphertext for a UTF-8 identity; returns the plaintext as UTF-8. */
  public static String decrypt(String ciphertext, String userId, String userPrivateKey) {
    return decrypt(ciphertext, userId, userPrivateKey, SM9CipherMode.STREAM);
  }

  /** Decrypts for a UTF-8 identity; invalid UTF-8 in the plaintext becomes U+FFFD. */
  public static String decrypt(
      String ciphertext, String userId, String userPrivateKey, SM9CipherMode mode) {
    byte[] plain = decryptToBytes(ciphertext, utf8(userId), userPrivateKey, mode);
    try {
      return new String(plain, StandardCharsets.UTF_8);
    } finally {
      Arrays.fill(plain, (byte) 0);
    }
  }

  /**
   * Decrypts C1 || C3 || C2 with an encryption private key; the mode must be the one used to
   * encrypt. Every rejected ciphertext raises the same exception.
   */
  public static byte[] decryptToBytes(
      String ciphertext, byte[] userId, String userPrivateKey, SM9CipherMode mode) {
    checkId(userId);
    boolean sm4 = isSm4(mode);
    int[] de = encKey(userPrivateKey);
    byte[] cipher;
    try {
      cipher = ConvertUtil.canonicalHexToByte(ciphertext);
    } catch (IllegalArgumentException e) {
      throw SM9Core.failure();
    }
    return SM9Core.decrypt(cipher, userId, de, sm4);
  }

  // ---------------------------------------------------------------- key encapsulation

  /** Encapsulates a key of keyLen bytes for a UTF-8 identity, hid 3. */
  public static SM9Encapsulation encapsulate(String userId, String masterPublicKey, int keyLen) {
    return encapsulate(utf8(userId), masterPublicKey, keyLen, HID_ENCRYPT);
  }

  /** Encapsulates a key of keyLen bytes, 1 to {@link #MAX_KEY_BYTES}, for an identity. */
  public static SM9Encapsulation encapsulate(
      byte[] userId, String masterPublicKey, int keyLen, int hid) {
    checkId(userId);
    checkHid(hid);
    checkKeyLen(keyLen);
    SM9Core.MasterKey master = encMaster(masterPublicKey);
    for (int i = 0; i < MAX_ATTEMPTS; i++) {
      int[] r = Fn.random(SystemRandom.get());
      byte[][] kc = SM9Core.encapsulate(userId, hid, master, keyLen, r);
      Arrays.fill(r, 0);
      if (kc != null) {
        return encapsulation(kc);
      }
    }
    throw new IllegalStateException("Secure random source failed");
  }

  /** Encapsulates with a given r, for known-answer tests. */
  static SM9Encapsulation encapsulateWithRandom(
      byte[] userId, String masterPublicKey, int keyLen, int hid, String r) {
    checkKeyLen(keyLen);
    byte[][] kc =
        SM9Core.encapsulate(
            userId, hid, encMaster(masterPublicKey), keyLen, scalar(r, "Invalid r"));
    if (kc == null) {
      throw new IllegalArgumentException("r gives an all-zero key");
    }
    return encapsulation(kc);
  }

  private static SM9Encapsulation encapsulation(byte[][] kc) {
    String key = hex(kc[0]);
    Arrays.fill(kc[0], (byte) 0);
    return new SM9Encapsulation(key, hex(kc[1]));
  }

  /** Recovers the key of a lower-case hex encapsulation for a UTF-8 identity. */
  public static String decapsulate(
      String ciphertext, String userId, String userPrivateKey, int keyLen) {
    return decapsulate(ciphertext, utf8(userId), userPrivateKey, keyLen);
  }

  /** Recovers the key of a lower-case hex encapsulation with an encryption private key. */
  public static String decapsulate(
      String ciphertext, byte[] userId, String userPrivateKey, int keyLen) {
    checkId(userId);
    checkKeyLen(keyLen);
    int[] de = encKey(userPrivateKey);
    int[] c;
    try {
      c = G1.decode(ConvertUtil.canonicalHexToByte(ciphertext));
    } catch (IllegalArgumentException e) {
      c = null;
    }
    if (c == null) {
      throw new IllegalArgumentException("Decapsulation failed");
    }
    byte[] k = SM9Core.decapsulate(c, userId, de, keyLen);
    try {
      return hex(k);
    } finally {
      Arrays.fill(k, (byte) 0);
    }
  }

  // ---------------------------------------------------------------- key exchange

  /** First step of either side for a UTF-8 peer identity, hid 2: r (secret) and R = [r] Q_peer. */
  public static SM9KeyPair exchangeInit(String peerId, String masterPublicKey) {
    return exchangeInit(utf8(peerId), masterPublicKey, HID_EXCHANGE);
  }

  /** r (secret, keep for the next step) and R = [r] Q_peer (send to the peer). */
  public static SM9KeyPair exchangeInit(byte[] peerId, String masterPublicKey, int hid) {
    checkId(peerId);
    checkHid(hid);
    SM9Core.MasterKey master = encMaster(masterPublicKey);
    int[] r = Fn.random(SystemRandom.get());
    try {
      return new SM9KeyPair(hex(Fn.toBytes(r)), hex(SM9Core.exchangeInit(peerId, hid, master, r)));
    } finally {
      Arrays.fill(r, 0);
    }
  }

  /** exchangeInit with a given r, for known-answer tests. */
  static String exchangeInitWithRandom(byte[] peerId, String masterPublicKey, int hid, String r) {
    return hex(
        SM9Core.exchangeInit(peerId, hid, encMaster(masterPublicKey), scalar(r, "Invalid r")));
  }

  /** B's step for UTF-8 identities; see the byte[] overload. */
  public static SM9ExchangeResult exchangeRespond(
      int keyLen,
      String idA,
      String idB,
      String masterPublicKey,
      String userPrivateKeyB,
      String rB,
      String pointRB,
      String pointRA) {
    try {
      return exchangeRespond(
          keyLen, utf8(idA), utf8(idB), masterPublicKey, userPrivateKeyB, rB, pointRB, pointRA);
    } catch (IllegalArgumentException e) {
      return SM9ExchangeResult.failed(e.getMessage());
    }
  }

  /**
   * Responder B: with its key de_B, its r_B and R_B from {@link #exchangeInit} and A's R_A, gives
   * SK_B, S_B (send to A) and S_2 (keep for {@link #exchangeCheck}). Failures give an unsuccessful
   * result.
   */
  public static SM9ExchangeResult exchangeRespond(
      int keyLen,
      byte[] idA,
      byte[] idB,
      String masterPublicKey,
      String userPrivateKeyB,
      String rB,
      String pointRB,
      String pointRA) {
    int[] r = null;
    try {
      checkExchange(keyLen, idA, idB);
      SM9Core.MasterKey master = encMaster(masterPublicKey);
      int[] de = encKey(userPrivateKeyB);
      r = scalar(rB, "Key exchange failed: invalid random value");
      byte[] rbXy = exchangePoint(pointRB, "B");
      byte[] raXy = exchangePoint(pointRA, "A");
      byte[][] g = SM9Core.exchangeValues(true, master, de, r, G1.decode(prefixed(raXy)));
      byte[][] out = SM9Core.exchangeOutputs(keyLen, idA, idB, raXy, rbXy, g);
      return SM9ExchangeResult.responder(wipedHex(out[0]), hex(out[1]), hex(out[2]));
    } catch (IllegalArgumentException e) {
      return SM9ExchangeResult.failed(e.getMessage());
    } finally {
      if (r != null) {
        Arrays.fill(r, 0);
      }
    }
  }

  /** A's step for UTF-8 identities; see the byte[] overload. */
  public static SM9ExchangeResult exchangeConfirm(
      int keyLen,
      String idA,
      String idB,
      String masterPublicKey,
      String userPrivateKeyA,
      String rA,
      String pointRA,
      String pointRB,
      String sB) {
    try {
      return exchangeConfirm(
          keyLen, utf8(idA), utf8(idB), masterPublicKey, userPrivateKeyA, rA, pointRA, pointRB, sB);
    } catch (IllegalArgumentException e) {
      return SM9ExchangeResult.failed(e.getMessage());
    }
  }

  /**
   * Initiator A: with its key de_A, its r_A and R_A, B's R_B and S_B, checks S_B in constant time
   * and only then gives SK_A and S_A (send to B).
   */
  public static SM9ExchangeResult exchangeConfirm(
      int keyLen,
      byte[] idA,
      byte[] idB,
      String masterPublicKey,
      String userPrivateKeyA,
      String rA,
      String pointRA,
      String pointRB,
      String sB) {
    int[] r = null;
    try {
      checkExchange(keyLen, idA, idB);
      SM9Core.MasterKey master = encMaster(masterPublicKey);
      int[] de = encKey(userPrivateKeyA);
      r = scalar(rA, "Key exchange failed: invalid random value");
      byte[] raXy = exchangePoint(pointRA, "A");
      byte[] rbXy = exchangePoint(pointRB, "B");
      byte[] expected = confirmation(sB);
      if (expected == null) {
        throw new IllegalArgumentException("Key exchange failed: S_B does not match");
      }
      byte[][] g = SM9Core.exchangeValues(false, master, de, r, G1.decode(prefixed(rbXy)));
      byte[][] out = SM9Core.exchangeOutputs(keyLen, idA, idB, raXy, rbXy, g);
      if (!ConvertUtil.byteArrayEqual(out[1], expected)) {
        Arrays.fill(out[0], (byte) 0);
        throw new IllegalArgumentException("Key exchange failed: S_B does not match");
      }
      return SM9ExchangeResult.initiator(wipedHex(out[0]), hex(out[2]));
    } catch (IllegalArgumentException e) {
      return SM9ExchangeResult.failed(e.getMessage());
    } finally {
      if (r != null) {
        Arrays.fill(r, 0);
      }
    }
  }

  /** B's final check S_A == S_2, in constant time; any malformed value gives false. */
  public static boolean exchangeCheck(String s2, String sA) {
    byte[] a = confirmation(s2);
    byte[] b = confirmation(sA);
    return a != null && b != null && ConvertUtil.byteArrayEqual(a, b);
  }

  // ---------------------------------------------------------------- decoding

  private static byte[] confirmation(String value) {
    if (value == null || value.length() != 2 * SM9Core.HASH_BYTES) {
      return null;
    }
    try {
      return ConvertUtil.canonicalHexToByte(value);
    } catch (IllegalArgumentException e) {
      return null;
    }
  }

  /** Decodes and validates R; returns x || y. */
  private static byte[] exchangePoint(String hex, String side) {
    byte[] raw = point(hex, G1_HEX, "Key exchange failed: invalid R_" + side);
    if (G1.decode(raw) == null) {
      throw new IllegalArgumentException("Key exchange failed: invalid R_" + side);
    }
    return Arrays.copyOfRange(raw, 1, G1.BYTES);
  }

  private static byte[] prefixed(byte[] xy) {
    byte[] out = new byte[G1.BYTES];
    out[0] = 4;
    System.arraycopy(xy, 0, out, 1, xy.length);
    return out;
  }

  private static void checkExchange(int keyLen, byte[] idA, byte[] idB) {
    if (keyLen < 1 || keyLen > MAX_KEY_BYTES) {
      throw new IllegalArgumentException("Key exchange failed: invalid key length");
    }
    if (idA == null || idB == null) {
      throw new IllegalArgumentException("Key exchange failed: user ID is required");
    }
  }

  private static int[] scalar(String hex, String message) {
    if (hex == null || hex.length() != SCALAR_HEX) {
      throw new IllegalArgumentException(message);
    }
    byte[] raw;
    try {
      raw = ConvertUtil.hexToByte(hex);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException(message);
    }
    int[] k = Fn.fromBytes(raw, 0);
    Arrays.fill(raw, (byte) 0);
    if (Fn.isValidScalar(k) == 0) {
      Arrays.fill(k, 0);
      throw new IllegalArgumentException(message);
    }
    return k;
  }

  private static byte[] point(String hex, int length, String message) {
    if (hex == null || hex.length() != length) {
      throw new IllegalArgumentException(message);
    }
    try {
      return ConvertUtil.hexToByte(hex);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException(message);
    }
  }

  private static SM9Core.MasterKey signMaster(String hex) {
    SM9Core.MasterKey key = SM9Core.signMaster(point(hex, G2_HEX, "Invalid master public key"));
    if (key == null) {
      throw new IllegalArgumentException("Invalid master public key");
    }
    return key;
  }

  private static SM9Core.MasterKey encMaster(String hex) {
    SM9Core.MasterKey key = SM9Core.encMaster(point(hex, G1_HEX, "Invalid master public key"));
    if (key == null) {
      throw new IllegalArgumentException("Invalid master public key");
    }
    return key;
  }

  private static int[] signKey(String hex) {
    byte[] raw = point(hex, G1_HEX, "Invalid user private key");
    int[] ds = G1.decode(raw);
    Arrays.fill(raw, (byte) 0);
    if (ds == null) {
      throw new IllegalArgumentException("Invalid user private key");
    }
    return ds;
  }

  private static int[] encKey(String hex) {
    byte[] raw = point(hex, G2_HEX, "Invalid user private key");
    int[] de = G2.decode(raw);
    Arrays.fill(raw, (byte) 0);
    if (de == null) {
      throw new IllegalArgumentException("Invalid user private key");
    }
    return de;
  }

  private static boolean isSm4(SM9CipherMode mode) {
    if (mode == null) {
      throw new IllegalArgumentException("Cipher mode is null");
    }
    return mode == SM9CipherMode.SM4;
  }

  private static void checkId(byte[] id) {
    if (id == null) {
      throw new IllegalArgumentException("User ID is null");
    }
  }

  private static void checkHid(int hid) {
    if (hid < 0 || hid > 255) {
      throw new IllegalArgumentException("hid must be a byte value");
    }
  }

  private static void checkKeyLen(int keyLen) {
    if (keyLen < 1 || keyLen > MAX_KEY_BYTES) {
      throw new IllegalArgumentException("Invalid key length");
    }
  }

  private static void checkPlaintext(byte[] plaintext) {
    if (plaintext == null || plaintext.length == 0 || plaintext.length > MAX_PLAINTEXT_BYTES) {
      throw new IllegalArgumentException("Plaintext must be non-empty");
    }
  }

  private static byte[] utf8(String text) {
    return ConvertUtil.utf8Bytes(text);
  }

  private static String hex(byte[] b) {
    return ConvertUtil.byteToHex(b);
  }

  private static String wipedHex(byte[] b) {
    try {
      return hex(b);
    } finally {
      Arrays.fill(b, (byte) 0);
    }
  }
}
