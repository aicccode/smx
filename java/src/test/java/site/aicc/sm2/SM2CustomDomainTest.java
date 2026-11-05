package site.aicc.sm2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import org.junit.Test;
import site.aicc.sm2.ec.AbstractECMultiplier;
import site.aicc.sm2.ec.AbstractECPoint;
import site.aicc.sm2.ec.DoubleAndAddMultiplier;
import site.aicc.sm2.ec.WNAFMultiplier;
import site.aicc.sm2.keygen.ECKeyPair;
import site.aicc.sm2.util.ConvertUtil;

/** The public initializer takes any parameters, which must stay on the generic route. */
public class SM2CustomDomainTest {
  private static final String[] P256 = {
    "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
    "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
    "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
    "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
  };

  private static String[] sm2WithOtherGenerator() {
    SM2Initializer standard = SM2.getSM2Initializer();
    AbstractECPoint twice = standard.getG().twice();
    return new String[] {
      "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
      "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
      "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
      "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
      twice.getXCoord().toBigInteger().toString(16),
      twice.getYCoord().toBigInteger().toString(16)
    };
  }

  private static void roundTrips(SM2Initializer init) throws Exception {
    byte[] message = "generic route".getBytes(StandardCharsets.UTF_8);
    String id = ConvertUtil.byteToHex("id".getBytes(StandardCharsets.UTF_8));
    for (int i = 0; i < 4; i++) {
      ECKeyPair pair = init.genKeyPair();
      byte[] pub = pair.getPointPubKey().getEncoded();
      byte[] priv = ConvertUtil.bigIntegerTo32Bytes(pair.getBIPriKey());
      String signature = SM2Cipher.sm2Sign(id, priv, message, init);
      assertTrue(SM2Cipher.sm2SignVerify(id, pub, message, signature, init));
      assertFalse(SM2Cipher.sm2SignVerify(id, pub, new byte[3], signature, init));
      String cipher = SM2Cipher.encrypt(pub, message, init);
      assertEquals(
          new String(message, StandardCharsets.UTF_8),
          new String(
              SM2Cipher.decrypt(priv, ConvertUtil.hexToByte(cipher), init),
              StandardCharsets.UTF_8));
    }
    ECKeyPair a = init.genKeyPair();
    ECKeyPair ra = init.genKeyPair();
    ECKeyPair b = init.genKeyPair();
    ECKeyPair rb = init.genKeyPair();
    SM2KeySwapParams sideB =
        SM2KeySwap.getSb(
            init,
            24,
            a.getPointPubKey(),
            ra.getPointPubKey(),
            b.getPointPubKey(),
            b.getBIPriKey(),
            rb.getPointPubKey(),
            rb.getBIPriKey(),
            "a",
            "b");
    assertTrue(sideB.getMessage(), sideB.isSuccess());
    SM2KeySwapParams sideA =
        SM2KeySwap.getSa(
            init,
            24,
            b.getPointPubKey(),
            rb.getPointPubKey(),
            a.getPointPubKey(),
            a.getBIPriKey(),
            ra.getPointPubKey(),
            ra.getBIPriKey(),
            "a",
            "b",
            ConvertUtil.hexToByte(sideB.getSb()));
    assertTrue(sideA.getMessage(), sideA.isSuccess());
    assertEquals(sideB.getKb(), sideA.getKa());
  }

  @Test
  public void otherCurvesAndGeneratorsUseTheGenericRoute() throws Exception {
    for (AbstractECMultiplier m :
        new AbstractECMultiplier[] {new DoubleAndAddMultiplier(), new WNAFMultiplier()}) {
      SM2Initializer p256 = new SM2Initializer(P256, m);
      assertFalse(p256.isStandardDomain());
      roundTrips(p256);
      SM2Initializer shifted = new SM2Initializer(sm2WithOtherGenerator(), m);
      assertFalse(shifted.isStandardDomain());
      roundTrips(shifted);
    }
  }

  @Test
  public void standardParametersAreRecognizedWithAnyMultiplier() throws Exception {
    String[] standard = {
      "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
      "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
      "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
      "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
      "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
      "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"
    };
    SM2Initializer wnaf = new SM2Initializer(standard, new WNAFMultiplier());
    assertTrue(wnaf.isStandardDomain());
    roundTrips(wnaf);
  }
}
