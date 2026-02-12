package site.aicc.sm2;

import java.math.BigInteger;
import java.security.SecureRandom;

import site.aicc.sm2.keygen.ECKeyPair;
import site.aicc.sm2.keygen.ECKeyPairGenerator;
import site.aicc.sm2.ec.AbstractECCurve;
import site.aicc.sm2.ec.AbstractECMultiplier;
import site.aicc.sm2.ec.AbstractECPoint;
import site.aicc.sm2.ec.FpCurve;
import site.aicc.sm2.util.ConvertUtil;
import site.aicc.sm3.SM3;

/** SM2 initializer: sets up the elliptic curve and key pair generator from parameters. */
public class SM2Initializer {
    private final BigInteger p;
    private final BigInteger a;
    private final BigInteger b;
    private final BigInteger n;
    private final int w;
    private final BigInteger gx;
    private final BigInteger gy;
    private final AbstractECCurve curve;
    private final AbstractECPoint g;

    private final AbstractECMultiplier multiplier;

    public BigInteger getN() {
        return n;
    }

    public AbstractECPoint getG() {
        return g;
    }

    public int getW() {
        return w;
    }

    private final ECKeyPairGenerator keyPairGenerator;

    public SM2Initializer(String[] params, AbstractECMultiplier multiplier) {
        this.multiplier = multiplier;
        this.p = new BigInteger(params[0], 16);
        this.a = new BigInteger(params[1], 16);
        this.b = new BigInteger(params[2], 16);
        this.n = new BigInteger(params[3], 16);
        this.w = Double.valueOf(Math.ceil(this.n.bitLength() / 2.0)).intValue() - 1;
        this.gx = new BigInteger(params[4], 16);
        this.gy = new BigInteger(params[5], 16);
        this.curve = new FpCurve(this.multiplier, this.p, this.a, this.b);
        this.g = this.curve.createPoint(this.gx, this.gy);
        this.keyPairGenerator = new ECKeyPairGenerator();
    }

    public ECKeyPair genKeyPair() {
        return this.keyPairGenerator.getECKeyPair(this.multiplier,this.curve, this.g, this.n, new SecureRandom());
    }

    public AbstractECPoint decodePoint(byte[] point) {
        return this.curve.decodePoint(point);
    }

    public AbstractECPoint getPublicKey(BigInteger privateKey) {
        return this.g.multiply(privateKey);
    }

    public void validatePoint(BigInteger x, BigInteger y) {
        this.curve.validatePoint(x, y);
    }

    public byte[] userSM3Z(byte[] userId, AbstractECPoint pA) {
        SM3 sm3 = new SM3();
        int len = userId.length * 8;
        sm3.update((byte) (len >> 8 & 0xFF));
        sm3.update((byte) (len & 0xFF));
        sm3.update(userId, 0, userId.length);
        byte[] p = ConvertUtil.bigIntegerTo32Bytes(a);
        sm3.update(p, 0, p.length);
        p = ConvertUtil.bigIntegerTo32Bytes(b);
        sm3.update(p, 0, p.length);
        p = ConvertUtil.bigIntegerTo32Bytes(gx);
        sm3.update(p, 0, p.length);
        p = ConvertUtil.bigIntegerTo32Bytes(gy) ;
        sm3.update(p, 0, p.length);
        p = ConvertUtil.bigIntegerTo32Bytes(pA.getXCoord().toBigInteger());
        sm3.update(p, 0, p.length);
        p = ConvertUtil.bigIntegerTo32Bytes(pA.getYCoord().toBigInteger());
        sm3.update(p, 0, p.length);
        sm3.finish();
        return sm3.getHashBytes();
    }

}
