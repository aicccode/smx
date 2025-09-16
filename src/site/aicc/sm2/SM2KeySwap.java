package site.aicc.sm2;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import site.aicc.sm2.ec.AbstractECPoint;
import site.aicc.sm2.util.ConvertUtil;
import site.aicc.sm3.SM3;

//@formatter:off
/**
* <ul>
*     <li>
*       <h3>类功能概述：</h3>
*       <p>本类用于(For) : SM2密钥交换协议算法</p>
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
*           <li>Date : 2020-10-04 | 下午11:27:16</li>
*          
*           <li>History : 新建类.</li>
*       </ul>
*     </li>
*     
*     
* </ul>
*/
//@formatter:on
public class SM2KeySwap {
    /**
     * B用户密钥交换工具
     * @param init
     * @param byteLen
     * @param pA
     * @param Ra
     * @param pB
     * @param dB
     * @param Rb
     * @param rb
     * @param IDa
     * @param IDb
     * @return
     */
    protected static SM2KeySwapParams getSb(SM2Initializer init, int byteLen, AbstractECPoint pA, AbstractECPoint Ra, AbstractECPoint pB, BigInteger dB, AbstractECPoint Rb, BigInteger rb, String IDa, String IDb) {
        SM2KeySwapParams result = new SM2KeySwapParams();
        try {
            BigInteger x2_ = calcX(init.getW(), Rb.getXCoord().toBigInteger());
            BigInteger tb = calcT(init.getN(), rb, dB, x2_);
            try {
                init.validatePoint(Ra.getXCoord().toBigInteger(), Ra.getYCoord().toBigInteger());
            } catch (Exception e) {
                throw new IllegalArgumentException("协商失败，A用户随机公钥不是椭圆曲线倍点。");
            }
            BigInteger x1_ = calcX(init.getW(), Ra.getXCoord().toBigInteger());
            AbstractECPoint V = calcPoint(tb, x1_, pA, Ra);
            if (V.isInfinity()) {
                throw new IllegalArgumentException("协商失败，V点是无穷远点。");
            }
            byte[] Za = init.userSM3Z(IDa.getBytes(StandardCharsets.UTF_8), pA);
            byte[] Zb = init.userSM3Z(IDb.getBytes(StandardCharsets.UTF_8), pB);
            byte[] Kb = KDF(byteLen, V, Za, Zb);
            byte[] Sb = createS((byte) 0x02, V, Za, Zb, Ra, Rb);
            result.setSb(ConvertUtil.byteToHex(Sb));
            result.setKb(ConvertUtil.byteToHex(Kb));
            // 返回中间结果
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

    /**
     * A用户密钥交换工具
     * @param init
     * @param byteLen
     * @param pB
     * @param Rb
     * @param pA
     * @param dA
     * @param Ra
     * @param ra
     * @param IDa
     * @param IDb
     * @param Sb
     * @return
     */
    protected static SM2KeySwapParams getSa(SM2Initializer init, int byteLen, AbstractECPoint pB, AbstractECPoint Rb, AbstractECPoint pA, BigInteger dA, AbstractECPoint Ra, BigInteger ra, String IDa, String IDb, byte[] Sb) {
        SM2KeySwapParams result = new SM2KeySwapParams();
        try {
            BigInteger x1_ = calcX(init.getW(), Ra.getXCoord().toBigInteger());
            BigInteger ta = calcT(init.getN(), ra, dA, x1_);
            try {
                init.validatePoint(Rb.getXCoord().toBigInteger(), Rb.getYCoord().toBigInteger());
            } catch (Exception e) {
                throw new IllegalArgumentException("协商失败，B用户随机公钥不是椭圆曲线倍点。");
            }
            BigInteger x2_ = calcX(init.getW(), Rb.getXCoord().toBigInteger());
            AbstractECPoint U = calcPoint(ta, x2_, pB, Rb);
            if (U.isInfinity()) {
                throw new IllegalArgumentException("协商失败，U点是无穷远点。");
            }

            byte[] Za = init.userSM3Z(IDa.getBytes(StandardCharsets.UTF_8), pA);
            byte[] Zb = init.userSM3Z(IDb.getBytes(StandardCharsets.UTF_8), pB);
            byte[] Ka = KDF(byteLen, U, Za, Zb);
            byte[] S1 = createS((byte) 0x02, U, Za, Zb, Ra, Rb);
            if (!ConvertUtil.byteArrayEqual(Sb, S1)) {
                throw new IllegalArgumentException("协商失败，B用户验证值与A侧计算值不相等。");
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
    /**
     * B用户密钥协商验证
     * @param V
     * @param Za
     * @param Zb
     * @param Ra
     * @param Rb
     * @param Sa
     * @return
     */
    protected static boolean checkSa(AbstractECPoint V, byte[] Za, byte[] Zb, AbstractECPoint Ra, AbstractECPoint Rb, byte[] Sa) {
        byte[] S2 = createS((byte) 0x03, V, Za, Zb, Ra, Rb);
        if (!ConvertUtil.byteArrayEqual(Sa, S2)) {
            return false;
        }
        return true;
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

    // 密钥派生函数KDF
    private static byte[] KDF(int keylen, AbstractECPoint vu, byte[] Za, byte[] Zb) {
        byte[] result = new byte[keylen];
        int ct = 0x00000001;
        for (int i = 0; i < (keylen + 31) / 32; i++) {
            SM3 sm3 = new SM3();
            byte p2x[] = vu.getXCoord().getEncoded();
            sm3.update(p2x, 0, p2x.length);
            byte p2y[] = vu.getYCoord().getEncoded();
            sm3.update(p2y, 0, p2y.length);
            sm3.update(Za, 0, Za.length);
            sm3.update(Zb, 0, Zb.length);
            byte[] ctBytes = new byte[4];
            ConvertUtil.intToBigEndian(ct, ctBytes, 0);
            sm3.update(ctBytes, 0, 4);
            sm3.finish();
            // 最后一段
            if (i == ((keylen + 31) / 32 - 1) && (keylen % 32) != 0) {
                System.arraycopy(sm3.getHashBytes(), 0, result, 32 * ct - 32, keylen % 32);
            } else {
                System.arraycopy(sm3.getHashBytes(), 0, result, 32 * ct - 32, 32);
            }
            ct++;
        }
        return result;
    }
}
