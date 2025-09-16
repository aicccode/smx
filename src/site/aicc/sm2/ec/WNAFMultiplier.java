package site.aicc.sm2.ec;

import java.math.BigInteger;
//@formatter:off
/**
* <ul>
*     <li>
*       <h3>类功能概述：</h3>
*       <p>本类用于(For) : w-ary non-adjacent form (wNAF) method</p>
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
*           <li>Date : 2020-09-28 | 下午11:16:25</li>
*          
*           <li>History : 新建类.</li>
*       </ul>
*     </li>
*     
*     
* </ul>
*/
//@formatter:on
public class WNAFMultiplier extends AbstractECMultiplier {
    // 通过移位操作计算存储需要的位数
    private static int getBitLen(int size) {
        if (size == 0)
            return 0;
        if (size == 2)
            return 2;
        int order = 0;
        do {
            size >>= 1;
            order++;
        } while (size > 0);
        return order;
    }

    protected AbstractECPoint multiplyPositive(AbstractECPoint p, BigInteger k) {
        int width = Math.max(2, Math.min(16, getWindowSize(k.bitLength())));
        WNAFPreCalcInfo wnafPreCompInfo = preCalc(p, width);
        AbstractECPoint[] preComp = wnafPreCompInfo.getPreComp();
        AbstractECPoint[] preCompNeg = wnafPreCompInfo.getPreCompNeg();
        int[] wnaf = generateCompactWindow(width, k);
        AbstractECPoint Q = p.getCurve().getInfinity();
        int i = wnaf.length;
        if (i > 1) {
            int wi = wnaf[--i];
            int digit = wi >> 16, zeroes = wi & 0xFFFF;
            int n = Math.abs(digit);
            AbstractECPoint[] table = digit < 0 ? preCompNeg : preComp;
            if ((n << 2) < (1 << width)) {
                int highest = getBitLen(n);
                int scale = width - highest;
                int lowBits = n ^ (1 << (highest - 1));
                int i1 = ((1 << (width - 1)) - 1);
                int i2 = (lowBits << scale) + 1;
                Q = table[i1 >>> 1].add(table[i2 >>> 1]);
                zeroes -= scale;
            } else {
                Q = table[n >>> 1];
            }

            Q = Q.timesPow2(zeroes);
        }
        while (i > 0) {
            int wi = wnaf[--i];
            int digit = wi >> 16, zeroes = wi & 0xFFFF;
            int n = Math.abs(digit);
            AbstractECPoint[] table = digit < 0 ? preCompNeg : preComp;
            AbstractECPoint r = table[n >>> 1];
            Q = Q.twicePlus(r);
            Q = Q.timesPow2(zeroes);
        }

        return Q;
    }

    private static WNAFPreCalcInfo preCalc(AbstractECPoint p, int width) {
        AbstractECCurve curve = p.getCurve();
        WNAFPreCalcInfo preCompInfo = getPreCompInfo((WNAFPreCalcInfo) p.getPreCalcInfo());
        int iniPreCompLen = 0, reqPreCompLen = 1 << Math.max(0, width - 2);
        AbstractECPoint[] preComp = preCompInfo.getPreComp();
        if (preComp == null) {
            preComp = new AbstractECPoint[0];
        } else {
            iniPreCompLen = preComp.length;
        }
        if (iniPreCompLen < reqPreCompLen) {
            preComp = resizeTable(preComp, reqPreCompLen);
            if (reqPreCompLen == 1) {
                preComp[0] = p;
            } else {
                int curPreCompLen = iniPreCompLen;
                if (curPreCompLen == 0) {
                    preComp[0] = p;
                    curPreCompLen = 1;
                }
                if (reqPreCompLen == 2) {
                    preComp[1] = p.threeTimes();
                } else {
                    AbstractECPoint twiceP = preCompInfo.getTwice(), last = preComp[curPreCompLen - 1];
                    if (twiceP == null) {
                        twiceP = preComp[0].twice();
                        preCompInfo.setTwice(twiceP);
                    }
                    while (curPreCompLen < reqPreCompLen) {
                        preComp[curPreCompLen++] = last = last.add(twiceP);
                    }
                }
                curve.checkPoints(preComp, iniPreCompLen, reqPreCompLen - iniPreCompLen);
            }
        }

        preCompInfo.setPreComp(preComp);
        AbstractECPoint[] preCompNeg = preCompInfo.getPreCompNeg();
        int pos;
        if (preCompNeg == null) {
            pos = 0;
            preCompNeg = new AbstractECPoint[reqPreCompLen];
        } else {
            pos = preCompNeg.length;
            if (pos < reqPreCompLen) {
                preCompNeg = resizeTable(preCompNeg, reqPreCompLen);
            }
        }
        while (pos < reqPreCompLen) {
            preCompNeg[pos] = preComp[pos].negate();
            ++pos;
        }
        preCompInfo.setPreCompNeg(preCompNeg);
        p.setPreCalcInfo(preCompInfo);
        return preCompInfo;
    }

    private static int[] generateCompactWindow(int width, BigInteger k) {
        if (width == 2) {
            return generateCompact(k);
        }
        if (width < 2 || width > 16) {
            throw new IllegalArgumentException("'width' 范围必须是 [2, 16]");
        }
        if ((k.bitLength() >>> 16) != 0) {
            throw new IllegalArgumentException("'k' 的位数必须小于 2^16");
        }
        if (k.signum() == 0) {
            return new int[0];
        }
        int[] wnaf = new int[k.bitLength() / width + 1];
        int pow2 = 1 << width;
        int mask = pow2 - 1;
        int sign = pow2 >>> 1;
        boolean carry = false;
        int length = 0, pos = 0;
        while (pos <= k.bitLength()) {
            if (k.testBit(pos) == carry) {
                ++pos;
                continue;
            }
            k = k.shiftRight(pos);
            int digit = k.intValue() & mask;
            if (carry) {
                ++digit;
            }
            carry = (digit & sign) != 0;
            if (carry) {
                digit -= pow2;
            }
            int zeroes = length > 0 ? pos - 1 : pos;
            wnaf[length++] = (digit << 16) | zeroes;
            pos = width;
        }
        if (wnaf.length > length) {
            wnaf = trim(wnaf, length);
        }
        return wnaf;
    }

    private static int[] generateCompact(BigInteger k) {
        if ((k.bitLength() >>> 16) != 0) {
            throw new IllegalArgumentException("'k'的位数必须小于 2^16");
        }
        if (k.signum() == 0) {
            return new int[0];
        }
        BigInteger _3k = k.shiftLeft(1).add(k);
        int bits = _3k.bitLength();
        int[] naf = new int[bits >> 1];
        BigInteger diff = _3k.xor(k);
        int highBit = bits - 1, length = 0, zeroes = 0;
        for (int i = 1; i < highBit; ++i) {
            if (!diff.testBit(i)) {
                ++zeroes;
                continue;
            }
            int digit = k.testBit(i) ? -1 : 1;
            naf[length++] = (digit << 16) | zeroes;
            zeroes = 1;
            ++i;
        }
        naf[length++] = (1 << 16) | zeroes;
        if (naf.length > length) {
            naf = trim(naf, length);
        }
        return naf;
    }

    private static int[] trim(int[] a, int length) {
        int[] result = new int[length];
        System.arraycopy(a, 0, result, 0, result.length);
        return result;
    }

    private static int getWindowSize(int bits) {
        int[] windowSizeCutoffs = new int[] { 13, 41, 121, 337, 897, 2305 };
        int w = 0;
        for (; w < windowSizeCutoffs.length; ++w) {
            if (bits < windowSizeCutoffs[w]) {
                break;
            }
        }
        return w + 2;
    }

    private static WNAFPreCalcInfo getPreCompInfo(WNAFPreCalcInfo preCompInfo) {
        return preCompInfo == null ? new WNAFPreCalcInfo() : preCompInfo;
    }

    private static AbstractECPoint[] resizeTable(AbstractECPoint[] a, int length) {
        AbstractECPoint[] result = new AbstractECPoint[length];
        System.arraycopy(a, 0, result, 0, a.length);
        return result;
    }
}
