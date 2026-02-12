package site.aicc.sm2.keygen;

import java.math.BigInteger;

/** SM2 private key. */
public class ECPrivateKey extends ECKey {

    private BigInteger d;

    public ECPrivateKey(BigInteger d) {
        super(true);
        this.d = d;
    }

    public BigInteger getD() {
        return d;
    }
}
