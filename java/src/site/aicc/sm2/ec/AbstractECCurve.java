package site.aicc.sm2.ec;

import java.math.BigInteger;

import site.aicc.sm2.util.ConvertUtil;
//@formatter:off
/**
* <ul>
*     <li>
*       <h3>类功能概述：</h3>
*       <p>本类用于(For) : 椭圆曲线</p>
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
*           <li>Date : 2020-09-26 | 下午10:36:01</li>
*          
*           <li>History : 新建类.</li>
*       </ul>
*     </li>
*     
*     
* </ul>
*/
//@formatter:on
public abstract class AbstractECCurve {
    protected AbstractECElement a, b;
    protected BigInteger order, cofactor;
    protected AbstractECMultiplier multiplier = null;

    public abstract int getFieldSize();

    public abstract AbstractECElement fromBigInteger(BigInteger x);

    public AbstractECPoint validatePoint(BigInteger x, BigInteger y) {
        AbstractECPoint p = createPoint(x, y);
        if (!p.isValid()) {
            throw new IllegalArgumentException("点不在曲线上!");
        }
        return p;
    }

    public AbstractECPoint createPoint(BigInteger x, BigInteger y) {
        return createRawPoint(fromBigInteger(x), fromBigInteger(y));
    }

    protected abstract AbstractECPoint createRawPoint(AbstractECElement x, AbstractECElement y);

    public abstract AbstractECPoint getInfinity();

    public AbstractECElement getA() {
        return a;
    }

    public AbstractECElement getB() {
        return b;
    }

    public BigInteger getOrder() {
        return order;
    }

    public BigInteger getCofactor() {
        return cofactor;
    }

    public abstract AbstractECMultiplier getMultiplier();

    public AbstractECPoint decodePoint(byte[] encoded) {
        AbstractECPoint p = null;
        int expectedLength = (getFieldSize() + 7) / 8;
        // 非压缩
        if (encoded.length != (2 * expectedLength + 1)) {
            throw new IllegalArgumentException("点编码长度错误!");
        }
        BigInteger X = ConvertUtil.fromUnsignedByteArray(encoded, 1, expectedLength);
        BigInteger Y = ConvertUtil.fromUnsignedByteArray(encoded, 1 + expectedLength, expectedLength);
        p = validatePoint(X, Y);
        if (p.isInfinity()) {
            throw new IllegalArgumentException("该点是无穷远点!");
        }
        return p;
    }

    protected void checkPoints(AbstractECPoint[] points, int off, int len) {
        if (points == null) {
            throw new IllegalArgumentException("点不能为 null!");
        }
        if (off < 0 || len < 0 || (off > (points.length - len))) {
            throw new IllegalArgumentException("该点超出范围!");
        }
        for (int i = 0; i < len; ++i) {
            AbstractECPoint point = points[off + i];
            if (null != point && this != point.getCurve()) {
                throw new IllegalArgumentException("点不在曲线上或者不为null!");
            }
        }
    }

    public boolean equals(Object obj) {
        return this == obj || (obj instanceof AbstractECCurve && equals((AbstractECCurve) obj));
    }

}
