package site.aicc.sm2;

import java.math.BigInteger;

import site.aicc.sm2.ec.AbstractECPoint;
import site.aicc.sm2.keygen.ECKeyPair;
import site.aicc.sm2.util.ConvertUtil;
import org.junit.Test;
import org.junit.Assert;

public class SM2Test {
    @Test
    public  void testSM2KeyPair() throws IllegalArgumentException, Exception {
        ECKeyPair kp = SM2.genSM2KeyPair();
        String puk = kp.getHexPubKey();
        String prk = kp.getHexPriKey();
        System.out.println("PUK->" + puk);
        System.out.println("PRK->" + prk);

        String userId = "ALICE123@YAHOO.COM";
        String message = "encryption standard";
        String en = SM2.sm2Encrypt(message, puk);
        System.out.println("EN ->" + en);
        String de = SM2.sm2Decrypt(en, prk);
        System.out.println("DE ->" + de);
        Assert.assertEquals(message, de);
        String sign = SM2.sm2Sign(userId, message, prk);
        System.out.println("SN->" + sign);
        System.out.println("SIG->" + SM2.sm2VerifySign(userId, sign, message, puk));
        Assert.assertTrue(SM2.sm2VerifySign(userId, sign, message, puk));
    }

    @Test
    public  void testSM2KeyChange() {
        String IDa = "ALICE123@YAHOO.COM";
        BigInteger dA = new BigInteger("6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE", 16);
        AbstractECPoint pA = SM2.getSM2Initializer().getG().multiply(dA);
        BigInteger ra = new BigInteger("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563", 16);
        AbstractECPoint Ra = SM2.getSM2Initializer().getG().multiply(ra);

        String IDb = "BILL456@YAHOO.COM";
        BigInteger dB = new BigInteger("5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53", 16);
        AbstractECPoint pB = SM2.getSM2Initializer().getG().multiply(dB);
        BigInteger rb = new BigInteger("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80", 16);
        AbstractECPoint Rb = SM2.getSM2Initializer().getG().multiply(rb);

        SM2KeySwapParams resultB = SM2.getSb(16, pA, Ra, pB, dB, Rb, rb, IDa, IDb);
        if (!resultB.isSuccess()) {
            System.out.println(resultB.getMessage());
            return;
        }
        System.out.println("B key->" + resultB.getKb());

        SM2KeySwapParams resultA = SM2.getSa(16, pB, Rb, pA, dA, Ra, ra, IDa, IDb, ConvertUtil.hexToByte(resultB.getSb()));
        if (!resultA.isSuccess()) {
            System.out.println(resultA.getMessage());
            return;
        }
        System.out.println("A key->" + resultA.getKa());

        boolean check = SM2.checkSa(resultB.getV(), resultB.getZa(), resultB.getZb(), Ra, Rb, ConvertUtil.hexToByte(resultA.getSa()));
        System.out.println(check ? "Key exchange success" : "Key exchange failed");
        Assert.assertTrue(check);
        Assert.assertEquals(resultA.getKa(), resultB.getKb());
    }
}
