package site.aicc.sm2;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import site.aicc.sm2.ec.AbstractECPoint;
import site.aicc.sm2.ec.DoubleAndAddMultiplier;
import site.aicc.sm2.keygen.ECKeyPair;
import site.aicc.sm2.keygen.ECPublicKey;
import site.aicc.sm2.util.ConvertUtil;

/** SM2 elliptic curve public key cryptographic algorithm. */
public class SM2 {
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

  /** Generates a key pair whose private key and coordinates fit the fixed 32-byte encodings. */
  public static ECKeyPair genSM2KeyPair() {
    while (true) {
      ECKeyPair key = INIT.genKeyPairWith32ByteScalar();
      AbstractECPoint q = ((ECPublicKey) key.getPublic()).getQ();
      int pubLength =
          q.getXCoord().toBigInteger().toByteArray().length
              + q.getYCoord().toBigInteger().toByteArray().length;
      if (pubLength == 64) {
        return key;
      }
    }
  }

  public static AbstractECPoint decodePoint(String publicKey) {
    return INIT.decodePoint(ConvertUtil.hexToByte(publicKey));
  }

  public static AbstractECPoint getPublicKey(BigInteger privateKey) {
    return INIT.getPublicKey(privateKey);
  }

  public static String sm2Encrypt(String content, String publicKey)
      throws IllegalArgumentException, IOException {
    return SM2Cipher.encrypt(
        ConvertUtil.hexToByte(publicKey), content.getBytes(StandardCharsets.UTF_8), INIT);
  }

  public static String sm2Decrypt(String content, String privateKey)
      throws IllegalArgumentException, IOException {
    byte[] decrypt =
        SM2Cipher.decrypt(ConvertUtil.hexToByte(privateKey), ConvertUtil.hexToByte(content), INIT);
    return new String(decrypt, StandardCharsets.UTF_8);
  }

  public static String sm2Sign(String userId, String content, String privateKey)
      throws IllegalArgumentException, Exception {
    return SM2Cipher.sm2Sign(
        ConvertUtil.byteToHex(userId.getBytes(StandardCharsets.UTF_8)),
        ConvertUtil.hexToByte(privateKey),
        content.getBytes(StandardCharsets.UTF_8),
        INIT);
  }

  public static boolean sm2VerifySign(
      String userId, String signature, String content, String publicKey) {
    return SM2Cipher.sm2SignVerify(
        ConvertUtil.byteToHex(userId.getBytes(StandardCharsets.UTF_8)),
        ConvertUtil.hexToByte(publicKey),
        content.getBytes(StandardCharsets.UTF_8),
        signature,
        INIT);
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
