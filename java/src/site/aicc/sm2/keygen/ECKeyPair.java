package site.aicc.sm2.keygen;

import java.math.BigInteger;
import site.aicc.sm2.ec.AbstractECPoint;
import site.aicc.sm2.util.ConvertUtil;

/** SM2 key pair (public + private). */
public class ECKeyPair {
  private final ECKey publicKey;
  private final ECKey privateKey;

  /**
   * Pairs an {@link ECPublicKey} with an {@link ECPrivateKey}.
   *
   * @throws IllegalArgumentException for a null key or a key of the wrong kind
   */
  public ECKeyPair(ECKey publicKey, ECKey privateKey) {
    if (!(publicKey instanceof ECPublicKey) || !(privateKey instanceof ECPrivateKey)) {
      throw new IllegalArgumentException("Expected a public key and a private key");
    }
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

  /** The private key as exactly 64 hex digits. Handle with care: this String cannot be erased. */
  public String getHexPriKey() {
    return ConvertUtil.byteToHex(ConvertUtil.bigIntegerTo32Bytes(getBIPriKey()));
  }

  public AbstractECPoint getPointPubKey() {
    return ((ECPublicKey) publicKey).getQ();
  }

  public BigInteger getBIPriKey() {
    return ((ECPrivateKey) privateKey).getD();
  }
}
