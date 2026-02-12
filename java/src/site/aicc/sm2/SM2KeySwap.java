package site.aicc.sm2;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import site.aicc.sm2.ec.AbstractECPoint;
import site.aicc.sm2.util.ConvertUtil;
import site.aicc.sm3.SM3;

/** SM2 key exchange protocol implementation. */
public class SM2KeySwap {

    protected static SM2KeySwapParams getSb(SM2Initializer init, int byteLen, AbstractECPoint pA, AbstractECPoint Ra, AbstractECPoint pB, BigInteger dB, AbstractECPoint Rb, BigInteger rb, String IDa, String IDb) {
        SM2KeySwapParams result = new SM2KeySwapParams();
        try {
            BigInteger x2_ = calcX(init.getW(), Rb.getXCoord().toBigInteger());
            BigInteger tb = calcT(init.getN(), rb, dB, x2_);
            try {
                init.validatePoint(Ra.getXCoord().toBigInteger(), Ra.getYCoord().toBigInteger());
            } catch (Exception e) {
                throw new IllegalArgumentException("Key exchange failed: A's random public key is not on the curve.");
            }
            BigInteger x1_ = calcX(init.getW(), Ra.getXCoord().toBigInteger());
            AbstractECPoint V = calcPoint(tb, x1_, pA, Ra);
            if (V.isInfinity()) {
                throw new IllegalArgumentException("Key exchange failed: V is at infinity.");
            }
            byte[] Za = init.userSM3Z(IDa.getBytes(StandardCharsets.UTF_8), pA);
            byte[] Zb = init.userSM3Z(IDb.getBytes(StandardCharsets.UTF_8), pB);
            byte[] Kb = SM2KdfUtil.kdf(byteLen, V, Za, Zb);
            byte[] Sb = createS((byte) 0x02, V, Za, Zb, Ra, Rb);
            result.setSb(ConvertUtil.byteToHex(Sb));
            result.setKb(ConvertUtil.byteToHex(Kb));
            result.setV(V);
            result.setZa(Za);
            result.setZb(Zb);
            result.setSuccess(true);
        } catch (Exception e) {
            result.setMessage(e.getMessage());
            result.setSuccess(false);
        }
        return result;
    }

    protected static SM2KeySwapParams getSa(SM2Initializer init, int byteLen, AbstractECPoint pB, AbstractECPoint Rb, AbstractECPoint pA, BigInteger dA, AbstractECPoint Ra, BigInteger ra, String IDa, String IDb, byte[] Sb) {
        SM2KeySwapParams result = new SM2KeySwapParams();
        try {
            BigInteger x1_ = calcX(init.getW(), Ra.getXCoord().toBigInteger());
            BigInteger ta = calcT(init.getN(), ra, dA, x1_);
            try {
                init.validatePoint(Rb.getXCoord().toBigInteger(), Rb.getYCoord().toBigInteger());
            } catch (Exception e) {
                throw new IllegalArgumentException("Key exchange failed: B's random public key is not on the curve.");
            }
            BigInteger x2_ = calcX(init.getW(), Rb.getXCoord().toBigInteger());
            AbstractECPoint U = calcPoint(ta, x2_, pB, Rb);
            if (U.isInfinity()) {
                throw new IllegalArgumentException("Key exchange failed: U is at infinity.");
            }

            byte[] Za = init.userSM3Z(IDa.getBytes(StandardCharsets.UTF_8), pA);
            byte[] Zb = init.userSM3Z(IDb.getBytes(StandardCharsets.UTF_8), pB);
            byte[] Ka = SM2KdfUtil.kdf(byteLen, U, Za, Zb);
            byte[] S1 = createS((byte) 0x02, U, Za, Zb, Ra, Rb);
            if (!ConvertUtil.byteArrayEqual(Sb, S1)) {
                throw new IllegalArgumentException("Key exchange failed: B's verification value does not match.");
            }
            byte[] Sa = createS((byte) 0x03, U, Za, Zb, Ra, Rb);
            result.setSa(ConvertUtil.byteToHex(Sa));
            result.setKa(ConvertUtil.byteToHex(Ka));
            result.setSuccess(true);
        } catch (Exception e) {
            result.setSuccess(false);
            result.setMessage(e.getMessage());
        }
        return result;
    }

    protected static boolean checkSa(AbstractECPoint V, byte[] Za, byte[] Zb, AbstractECPoint Ra, AbstractECPoint Rb, byte[] Sa) {
        byte[] S2 = createS((byte) 0x03, V, Za, Zb, Ra, Rb);
        return ConvertUtil.byteArrayEqual(Sa, S2);
    }

    private static byte[] createS(byte tag, AbstractECPoint vu, byte[] Za, byte[] Zb, AbstractECPoint Ra, AbstractECPoint Rb) {
        SM3 sm3 = new SM3();
        byte[] bXvu = ConvertUtil.bigIntegerTo32Bytes(vu.getXCoord().toBigInteger());
        sm3.update(bXvu, 0, bXvu.length);
        sm3.update(Za, 0, Za.length);
        sm3.update(Zb, 0, Zb.length);
        byte[] bRax = ConvertUtil.bigIntegerTo32Bytes(Ra.getXCoord().toBigInteger());
        byte[] bRay = ConvertUtil.bigIntegerTo32Bytes(Ra.getYCoord().toBigInteger());
        byte[] bRbx = ConvertUtil.bigIntegerTo32Bytes(Rb.getXCoord().toBigInteger());
        byte[] bRby = ConvertUtil.bigIntegerTo32Bytes(Rb.getYCoord().toBigInteger());
        sm3.update(bRax, 0, bRax.length);
        sm3.update(bRay, 0, bRay.length);
        sm3.update(bRbx, 0, bRbx.length);
        sm3.update(bRby, 0, bRby.length);
        byte[] h1 = sm3.finish().getHashBytes();
        SM3 hash = new SM3();
        hash.update(tag);
        byte[] bYvu = ConvertUtil.bigIntegerTo32Bytes(vu.getYCoord().toBigInteger());
        hash.update(bYvu, 0, bYvu.length);
        hash.update(h1, 0, h1.length);
        return hash.finish().getHashBytes();
    }

    private static BigInteger calcX(int w, BigInteger x2) {
        BigInteger _2PowW = BigInteger.valueOf(2).pow(w);
        _2PowW = _2PowW.add(x2.and(_2PowW.subtract(BigInteger.valueOf(1))));
        return ConvertUtil.fromUnsignedByteArray(ConvertUtil.bigIntegerTo32Bytes(_2PowW), 0, 32);
    }

    private static BigInteger calcT(BigInteger n, BigInteger rb, BigInteger db, BigInteger x2_) {
        return db.add(x2_.multiply(rb)).mod(n);
    }

    private static AbstractECPoint calcPoint(BigInteger t, BigInteger x, AbstractECPoint pA, AbstractECPoint rA) {
        return pA.add(rA.multiply(x)).multiply(t);
    }
}
