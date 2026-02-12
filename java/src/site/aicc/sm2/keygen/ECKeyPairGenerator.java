package site.aicc.sm2.keygen;

import java.math.BigInteger;
import java.security.SecureRandom;

import site.aicc.sm2.ec.AbstractECCurve;
import site.aicc.sm2.ec.AbstractECMultiplier;
import site.aicc.sm2.ec.AbstractECPoint;

/** SM2 key pair generator. */
public class ECKeyPairGenerator {

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
