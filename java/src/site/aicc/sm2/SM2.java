package site.aicc.sm2;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import site.aicc.sm2.ec.AbstractECPoint;
import site.aicc.sm2.ec.DoubleAndAddMultiplier;
import site.aicc.sm2.keygen.ECKeyPair;
import site.aicc.sm2.util.ConvertUtil;

/** SM2 elliptic curve public key cryptographic algorithm. */
public class SM2 {
  private static final int PRIVATE_KEY_HEX_LENGTH = 64;

  private static final String[] PARAMS =
      new String[] {
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
        "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
        "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
        "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"
      };

  private static final SM2Initializer INIT =
      new SM2Initializer(PARAMS, new DoubleAndAddMultiplier());

  protected static SM2Initializer getSM2Initializer() {
    return INIT;
  }

  /**
   * Generates a key pair whose private key is uniform in [1, n - 2].
   *
   * @throws IllegalStateException when the operating system's random source fails
   */
  public static ECKeyPair genSM2KeyPair() {
    return INIT.genKeyPair();
  }

  /**
   * Decodes a public key: the hex of exactly 0x04 || x || y, validated.
   *
   * @throws IllegalArgumentException for malformed hex or an invalid point
   */
  public static AbstractECPoint decodePoint(String publicKey) {
    return INIT.decodePoint(ConvertUtil.hexToByte(publicKey));
  }

  /**
   * Computes the public key of a private key.
   *
   * @throws IllegalArgumentException unless 1 <= privateKey <= n - 2
   */
  public static AbstractECPoint getPublicKey(BigInteger privateKey) {
    return INIT.getPublicKey(privateKey);
  }

  /**
   * Encrypts the UTF-8 encoding of content; returns the hex of C1 || C3 || C2.
   *
   * @return null for empty content
   * @throws IllegalArgumentException for an invalid key, or content that is null or not valid
   *     Unicode
   * @throws IllegalStateException when the operating system's random source fails
   */
  public static String sm2Encrypt(String content, String publicKey)
      throws IllegalArgumentException, IOException {
    byte[] plain = ConvertUtil.utf8Bytes(content);
    try {
      return SM2Cipher.encrypt(ConvertUtil.hexToByte(publicKey), plain, INIT);
    } finally {
      Arrays.fill(plain, (byte) 0);
    }
  }

  /**
   * Decrypts the hex of C1 || C3 || C2 with a private key of exactly 64 hex digits. The result is
   * decoded as UTF-8, where bytes that are not valid UTF-8 become U+FFFD.
   *
   * @throws IllegalArgumentException for an invalid key or any rejected ciphertext
   */
  public static String sm2Decrypt(String content, String privateKey)
      throws IllegalArgumentException, IOException {
    byte[] key = decodePrivateKey(privateKey);
    try {
      byte[] cipher;
      try {
        cipher = ConvertUtil.hexToByte(content);
      } catch (IllegalArgumentException e) {
        throw new IllegalArgumentException("Decryption failed");
      }
      byte[] plain = SM2Cipher.decrypt(key, cipher, INIT);
      try {
        return new String(plain, StandardCharsets.UTF_8);
      } finally {
        Arrays.fill(plain, (byte) 0);
      }
    } finally {
      Arrays.fill(key, (byte) 0);
    }
  }

  /**
   * Signs the UTF-8 encoding of content; returns r, 'h', s as 64 hex digits each.
   *
   * @throws IllegalArgumentException for an invalid key, or a user ID or content that is null, not
   *     valid Unicode, or (for the ID) 8192 bytes or longer
   * @throws IllegalStateException when the operating system's random source fails
   */
  public static String sm2Sign(String userId, String content, String privateKey)
      throws IllegalArgumentException, Exception {
    byte[] key = decodePrivateKey(privateKey);
    try {
      return SM2Cipher.sm2Sign(
          ConvertUtil.byteToHex(ConvertUtil.utf8Bytes(userId)),
          key,
          ConvertUtil.utf8Bytes(content),
          INIT);
    } finally {
      Arrays.fill(key, (byte) 0);
    }
  }

  /** Verifies a signature; every invalid input of any kind gives false. */
  public static boolean sm2VerifySign(
      String userId, String signature, String content, String publicKey) {
    try {
      return SM2Cipher.sm2SignVerify(
          ConvertUtil.byteToHex(ConvertUtil.utf8Bytes(userId)),
          ConvertUtil.hexToByte(publicKey),
          ConvertUtil.utf8Bytes(content),
          signature,
          INIT);
    } catch (IllegalArgumentException e) {
      return false;
    }
  }

  private static byte[] decodePrivateKey(String privateKey) {
    if (privateKey == null || privateKey.length() != PRIVATE_KEY_HEX_LENGTH) {
      throw new IllegalArgumentException("Invalid private key");
    }
    try {
      return ConvertUtil.hexToByte(privateKey);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("Invalid private key");
    }
  }

  public static SM2KeySwapParams getSb(
      int byteLen,
      AbstractECPoint pA,
      AbstractECPoint rA,
      AbstractECPoint pB,
      BigInteger dB,
      AbstractECPoint rB,
      BigInteger rb,
      String idA,
      String idB) {
    return SM2KeySwap.getSb(INIT, byteLen, pA, rA, pB, dB, rB, rb, idA, idB);
  }

  public static SM2KeySwapParams getSa(
      int byteLen,
      AbstractECPoint pB,
      AbstractECPoint rB,
      AbstractECPoint pA,
      BigInteger dA,
      AbstractECPoint rA,
      BigInteger ra,
      String idA,
      String idB,
      byte[] sB) {
    return SM2KeySwap.getSa(INIT, byteLen, pB, rB, pA, dA, rA, ra, idA, idB, sB);
  }

  public static boolean checkSa(
      AbstractECPoint v, byte[] zA, byte[] zB, AbstractECPoint rA, AbstractECPoint rB, byte[] sA) {
    return SM2KeySwap.checkSa(v, zA, zB, rA, rB, sA);
  }
}
