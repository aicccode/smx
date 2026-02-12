package site.aicc.sm2.keygen;

import java.math.BigInteger;

import site.aicc.sm2.ec.AbstractECPoint;
import site.aicc.sm2.util.ConvertUtil;

/** SM2 key pair (public + private). */
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
