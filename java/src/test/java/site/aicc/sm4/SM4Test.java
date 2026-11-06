package site.aicc.sm4;

import org.junit.Assert;
import org.junit.Test;

public class SM4Test {

  @Test
  public void testEncryptDecryptRoundTrip() throws Exception {
    SM4 sm4 = new SM4();
    sm4.setKey("this is the key!", "this is the iv!!", false);
    String plaintext = "国密SM4对称加密算法";
    String cipherHex = sm4.encrypt(plaintext);
    String decrypted = sm4.decrypt(cipherHex);
    Assert.assertEquals(plaintext, decrypted);
  }

  /** Decryption takes four blocks at a time with a one-block tail: cover every split. */
  @Test
  public void roundTripsEveryLengthAcrossTheFourBlockBatches() throws Exception {
    SM4 sm4 =
        new SM4()
            .setKey("0123456789abcdeffedcba9876543210", "000102030405060708090a0b0c0d0e0f", true);
    StringBuilder text = new StringBuilder();
    for (int length = 0; length <= 160; length++) {
      String plain = text.toString();
      Assert.assertEquals(plain, sm4.decrypt(sm4.encrypt(plain)));
      text.append((char) ('a' + length % 26));
    }
  }
}
