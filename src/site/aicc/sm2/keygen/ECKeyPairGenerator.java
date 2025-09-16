package site.aicc.sm2.keygen;

import java.math.BigInteger;
import java.security.SecureRandom;

import site.aicc.sm2.ec.AbstractECCurve;
import site.aicc.sm2.ec.AbstractECMultiplier;
import site.aicc.sm2.ec.AbstractECPoint;

//@formatter:off
/**
* <ul>
*     <li>
*       <h3>类功能概述：</h3>
*       <p>本类用于(For) : SM2 密钥对生成工具</p>
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
*           <li>Date : 2020-09-28 | 下午10:28:00</li>
*          
*           <li>History : 新建类.</li>
*       </ul>
*     </li>
*     
*     
* </ul>
*/
//@formatter:on
public class ECKeyPairGenerator {
    /**
     * 随机产生符合安全要求的密钥对
     * 
     * @param param      椭圆曲线相关参数
     * @param multiplier 倍点计算器
     * @return
     */
    public ECKeyPair getECKeyPair(AbstractECMultiplier multiplier, AbstractECCurve curve, AbstractECPoint g, BigInteger n, SecureRandom random) {
        if (random == null) {
            random = new SecureRandom();
        }
        int minWidth = n.bitLength() >>> 2;
        BigInteger d;
        do {
            d = new BigInteger(n.bitLength(), random);
        } while (d.compareTo(BigInteger.valueOf(2)) < 0 || (d.compareTo(n) >= 0) || getWidth(d) < minWidth);
        AbstractECPoint Q = multiplier.multiply(g, d);
        return new ECKeyPair(new ECPublicKey(Q), new ECPrivateKey(d));
    }

    private static int getWidth(BigInteger k) {
        return k.signum() == 0 ? 0 : k.shiftLeft(1).add(k).xor(k).bitCount();
    }
}
