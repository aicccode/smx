package site.aicc.sm2.keygen;

import java.math.BigInteger;
import site.aicc.sm2.ec.AbstractECPoint;
import site.aicc.sm2.util.ConvertUtil;

/** SM2 key pair (public + private). */
public class ECKeyPair {
  private final ECKey publicKey;
  private final ECKey privateKey;

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
    return ConvertUtil.byteToHex(getPointPubKey().getEncoded());
  }

  public String getHexPriKey() {
    return ConvertUtil.byteToHex(getBIPriKey().toByteArray());
  }

  public AbstractECPoint getPointPubKey() {
    return ((ECPublicKey) publicKey).getQ();
  }

  public BigInteger getBIPriKey() {
    return ((ECPrivateKey) privateKey).getD();
  }
}
