package site.aicc.sm4;

import java.nio.charset.StandardCharsets;
import org.junit.Assert;
import org.junit.Test;

public class SM4Test {

    @Test
    public void testEncryptDecryptRoundTrip() throws Exception {
        SM4 sm4 = new SM4();
        sm4.setKey("this is the key", "this is the iv", false);
        String plaintext = "国密SM4对称加密算法";
        String cipherHex = sm4.encrypt(plaintext);
        String decrypted = sm4.decrypt(cipherHex);
        Assert.assertEquals(plaintext, decrypted);
    }
}
