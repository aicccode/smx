package site.aicc.sm2.keygen;

import java.math.BigInteger;

import site.aicc.sm2.ec.AbstractECPoint;
import site.aicc.sm2.util.ConvertUtil;
//@formatter:off
/**
* <ul>
*     <li>
*       <h3>类功能概述：</h3>
*       <p>本类用于(For) : SM2 密钥对</p>
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
*           <li>Date : 2020-09-26 | 下午08:20:40</li>
*          
*           <li>History : 新建类.</li>
*       </ul>
*     </li>
*     
*     
* </ul>
*/
//@formatter:on
public class ECKeyPair {
    private ECKey publicKey;
    private ECKey privateKey;

    public ECKeyPair(ECKey publicKey, ECKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public ECKey getPublic() {
        return publicKey;
    }

    public ECKey getPrivate() {
        return privateKey;
    }

    public String getHexPubKey() {
        ECPublicKey ecpub = (ECPublicKey) publicKey;
        AbstractECPoint publicKey = ecpub.getQ();
        return ConvertUtil.byteToHex(publicKey.getEncoded());
    }

    public String getHexPriKey() {
        ECPrivateKey ecpriv = (ECPrivateKey) privateKey;
        BigInteger privateKey = ecpriv.getD();
        return ConvertUtil.byteToHex(privateKey.toByteArray());
    }

    public AbstractECPoint getPointPubKey() {
        ECPublicKey ecpub = (ECPublicKey) publicKey;
        return ecpub.getQ();
    }
    public BigInteger getBIPriKey(){
        ECPrivateKey ecpriv = (ECPrivateKey) privateKey;
        return ecpriv.getD();
    }
}
