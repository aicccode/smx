package site.aicc.sm2;

import java.math.BigInteger;

import site.aicc.sm2.ec.AbstractECPoint;
import site.aicc.sm2.keygen.ECKeyPair;
import site.aicc.sm2.util.ConvertUtil;

//@formatter:off
/**
* <ul>
*     <li>
*       <h3>类功能概述：</h3>
*       <p>本类用于(For) : SM2 密钥对生成、加密、解密、密钥交换测试</p>
*     </li>
*     <li>
*       <h4> 使用示例(Example)：</h4>
*       <p></p>
*       <p></p>
*     </li>
*     <li>
*       <h3>版本历史</h3>
*       <ul>
*           <li>Version : 1.00</li>
*           <li>Date : 2020-10-06 | 下午11:24:57</li>
*          
*           <li>History : 新建类.</li>
*       </ul>
*     </li>
*     
*     
* </ul>
*/
//@formatter:on
public class TestSM2 {
    public static void main(String[] args) throws IllegalArgumentException, Exception {
        // 随机密钥对生成
        ECKeyPair kp = SM2.genSM2KeyPair();
        String puk = kp.getHexPubKey();
        String prk = kp.getHexPriKey();
        // 国密签名测试密钥
        // @formatter:off
        // String puk = "040ae4c7798aa0f119471bee11825be46202bb79e2a5844495e97c04ff4df2548a7c0240f88f1cd4e16352a73c17b7f16f07353e53a176d684a9fe0c6bb798e857";
        // String prk = "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263";
        // 国密加解密测试密钥
        // String puk = "04435b39cca8f3b508c1488afc67be491a0f7ba07e581a0e4849a5cf70628a7e0a75ddba78f15feecb4c7895e2c1cdf5fe01debb2cdbadf45399ccf77bba076a42";
        // String prk = "1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0";
        // @formatter:on
        System.out.println("PUK->" + puk);
        System.out.println("PRK->" + prk);
        
        
        String userId = "ALICE123@YAHOO.COM";
        // 签名测试消息
        // String message = "message digest";
        // 解密测试消息
        String message = "encryption standard";
        //加密测试
        String en = SM2.sm2Encrypt(message, puk);
        System.out.println("EN ->" + en);
        //解密测试
        System.out.println("DE ->" + SM2.sm2Decrypt(en, prk));
        //签名测试
        String sign = SM2.sm2Sign(userId, message, prk);
        System.out.println("SN->" + sign);
        //签名验证测试
        System.out.println("SIG->" + SM2.sm2VerifySign(userId, sign, message, puk));
        // 密钥交换协议测试
        testSM2KeyChange();
    }

    private static void testSM2KeyChange() {
        // 一、B向A发起协商请求

        // 二、A生成随机密钥对
        String IDa = "ALICE123@YAHOO.COM";
        // A证书密钥对
        BigInteger dA = new BigInteger("6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE", 16);
        AbstractECPoint pA = SM2.getSM2Initializer().getG().multiply(dA);
        // A随机密钥对（国密测试，实际使用中随机生成）
        BigInteger ra = new BigInteger("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563", 16);
        AbstractECPoint Ra = SM2.getSM2Initializer().getG().multiply(ra);

        // 三、A将自己的(ID、证书公钥pA、随机公钥Ra)发送给B

        // 四、B生成随机密钥对
        String IDb = "BILL456@YAHOO.COM";
        // B证书密钥对
        BigInteger dB = new BigInteger("5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53", 16);
        AbstractECPoint pB = SM2.getSM2Initializer().getG().multiply(dB);
        // B随机密钥对（国密测试，实际只用中随机生成）
        BigInteger rb = new BigInteger("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80", 16);
        AbstractECPoint Rb = SM2.getSM2Initializer().getG().multiply(rb);

        // 五、B侧计算，获得协商密钥Kb，验证结果Sb
        SM2KeySwapParams resultB = SM2.getSb(16, pA, Ra, pB, dB, Rb, rb, IDa, IDb);
        if (!resultB.isSuccess()) {
            System.out.println(resultB.getMessage());
            return;
        }
        System.out.println("通过协商，B获得密钥->" + resultB.getKb());
        // 六、B将(计算得到的Sb,以及证书公钥pB、随机公钥Rb)发送给A

        // 七、A侧计算，获得协商密钥Ka，验证结果Sa
        SM2KeySwapParams resultA = SM2.getSa(16, pB, Rb, pA, dA, Ra, ra, IDa, IDb, ConvertUtil.hexToByte(resultB.getSb()));
        if (!resultA.isSuccess()) {
            System.out.println(resultA.getMessage());
            return;
        }
        System.out.println("通过协商，A获得密钥->" + resultA.getKa());
        // 八、A将计算得到的Sa发送给B

        // 九、B侧检查Sa
        boolean check = SM2.checkSa(resultB.getV(), resultB.getZa(), resultB.getZb(), Ra, Rb, ConvertUtil.hexToByte(resultA.getSa()));
        System.out.println(check ? "密钥协商成功！" : "密钥协商失败！");
    }
}
