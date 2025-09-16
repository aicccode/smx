package site.aicc.sm2.ec;

import java.math.BigInteger;

import site.aicc.sm2.util.ConvertUtil;
//@formatter:off
/**
* <ul>
*     <li>
*       <h3>类功能概述：</h3>
*       <p>本类用于(For) : double-and-add method</p>
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
*           <li>Date : 2020-09-28 | 下午11:36:12</li>
*          
*           <li>History : 新建类.</li>
*       </ul>
*     </li>
*     
*     
* </ul>
*/
//@formatter:on
public class DoubleAndAddMultiplier extends AbstractECMultiplier {

    protected AbstractECPoint multiplyPositive(AbstractECPoint p, BigInteger k) {
        AbstractECCurve c = p.getCurve();
        int size = getCombSize(c);
        if (k.bitLength() > size) {
            throw new IllegalStateException("倍点不合法");
        }
        DoubleAndAddPreCalcInfo info = preCalc(p);
        int width = info.getWidth();
        int d = (size + width - 1) / width;
        AbstractECPoint Q = c.getInfinity();
        int l = d * width;
        int[] K = ConvertUtil.fromBigInteger(l, k);
        for (int i = 0; i < d; ++i) {
            int idx = 0;
            for (int j = l - 1 - i; j >= 0; j -= d) {
                idx <<= 1;
                idx |= ConvertUtil.getBit(K, j);
            }
            AbstractECPoint add = info.getPreComp()[idx];
            Q = Q.twicePlus(add);
        }
        return Q.add(info.getOffset());
    }

    private static int getCombSize(AbstractECCurve c) {
        BigInteger order = c.getOrder();
        return order == null ? c.getFieldSize() : order.bitLength();
    }

    private static DoubleAndAddPreCalcInfo preCalc(AbstractECPoint p) {
        AbstractECCurve curve = p.getCurve();
        int bits = getCombSize(curve);
        int minWidth = bits > 256 ? 6 : 5;
        int n = 1 << minWidth;
        DoubleAndAddPreCalcInfo preCompInfo = new DoubleAndAddPreCalcInfo();
        int d = (bits + minWidth - 1) / minWidth;
        AbstractECPoint[] pow2Table = new AbstractECPoint[minWidth + 1];
        pow2Table[0] = p;
        for (int i = 1; i < minWidth; ++i) {
            pow2Table[i] = pow2Table[i - 1].timesPow2(d);
        }
        pow2Table[minWidth] = pow2Table[0].subtract(pow2Table[1]);
        curve.checkPoints(pow2Table, 0, pow2Table.length);
        AbstractECPoint[] preComp = new AbstractECPoint[n];
        preComp[0] = pow2Table[0];
        for (int bit = minWidth - 1; bit >= 0; --bit) {
            AbstractECPoint pow2 = pow2Table[bit];
            int step = 1 << bit;
            for (int i = step; i < n; i += (step << 1)) {
                preComp[i] = preComp[i - step].add(pow2);
            }
        }
        curve.checkPoints(preComp, 0, preComp.length);
        preCompInfo.setOffset(pow2Table[minWidth]);
        preCompInfo.setPreComp(preComp);
        preCompInfo.setWidth(minWidth);
        return preCompInfo;
    }
}
