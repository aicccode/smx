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

//@formatter:off
/**
* <ul>
*     <li>
*       <h3>类功能概述：</h3>
*       <p>本类用于(For) : SM2初始化类，根据输入的方程参数、倍点运算器等初始化SM2算法基础</p>
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
*           <li>Date : 2020-09-26 | 下午07:15:12</li>
*          
*           <li>History : 新建类.</li>
*       </ul>
*     </li>
*     
*     
* </ul>
*/
//@formatter:on
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

    /**
     * SM2初始化构造器
     * 
     * @param params     初始化参数[p,a,b,n,gx,gy]
     * @param multiplier 倍点运算器 ${link DoubleAndAddMultiplier} | ${link WNAFMultiplier}
     */
    public SM2Initializer(String[] params, AbstractECMultiplier multiplier) {
        this.multiplier = multiplier;
        this.p = new BigInteger(params[0], 16);
        this.a = new BigInteger(params[1], 16);
        this.b = new BigInteger(params[2], 16);
        this.n = new BigInteger(params[3], 16);
        // 密钥交换协议使用 w=[[log2(n)]/2]-1
        this.w = Double.valueOf(Math.ceil(this.n.bitLength() / 2.0)).intValue() - 1;
        this.gx = new BigInteger(params[4], 16);
        this.gy = new BigInteger(params[5], 16);
        this.curve = new FpCurve(this.multiplier, this.p, this.a, this.b);
        this.g = this.curve.createPoint(this.gx, this.gy);
        this.keyPairGenerator = new ECKeyPairGenerator();
    }

    /**
     * 随机密钥对生成
     * 
     * @return
     */
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

    /**
     * 签名或密钥交换协议中用到的Z
     * 
     * @param userId 用户标识
     * @param pA     用户公钥
     * @return
     */
    public byte[] userSM3Z(byte[] userId, AbstractECPoint pA) {
        SM3 sm3 = new SM3();
        // 取ID的后两个字节
        int len = userId.length * 8;
        sm3.update((byte) (len >> 8 & 0xFF));
        sm3.update((byte) (len & 0xFF));
        // ID
        sm3.update(userId, 0, userId.length);
        byte[] p = ConvertUtil.bigIntegerTo32Bytes(a);
        // a
        sm3.update(p, 0, p.length);
        p = ConvertUtil.bigIntegerTo32Bytes(b);
        // b
        sm3.update(p, 0, p.length);
        p = ConvertUtil.bigIntegerTo32Bytes(gx);
        // gx
        sm3.update(p, 0, p.length);
        p = ConvertUtil.bigIntegerTo32Bytes(gy) ;
        // gy
        sm3.update(p, 0, p.length);
        p = ConvertUtil.bigIntegerTo32Bytes(pA.getXCoord().toBigInteger());
        // pAx
        sm3.update(p, 0, p.length);
        p = ConvertUtil.bigIntegerTo32Bytes(pA.getYCoord().toBigInteger());
        // pAy
        sm3.update(p, 0, p.length);
        sm3.finish();
        return sm3.getHashBytes();
    }
    
}
