package site.aicc.sm2.ec;

import java.math.BigInteger;

import site.aicc.sm2.util.ConvertUtil;

//@formatter:off
/**
* <ul>
*     <li>
*       <h3>类功能概述：</h3>
*       <p>本类用于(For) : 素数域元素</p>
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
*           <li>Date : 2020-09-27 | 下午09:45:30</li>
*           <li>Author : yaojunWang.</li>
*           <li>History : 新建类.</li>
*       </ul>
*     </li>
*     <li>@Copyright Copyright © 2020, yaojunWang, All rights reserved. </li>
*     <li>@Author yaojunWang.</li>
* </ul>
*/
//@formatter:on
public class FpElement extends AbstractECElement {

    BigInteger q, r, v;

    static BigInteger calculateResidue(BigInteger p) {
        int bitLength = p.bitLength();
        if (bitLength >= 96) {
            BigInteger firstWord = p.shiftRight(bitLength - 64);
            if (firstWord.longValue() == -1L) {
                return BigInteger.valueOf(1).shiftLeft(bitLength).subtract(p);
            }
        }
        return null;
    }

    FpElement(BigInteger q, BigInteger r, BigInteger v) {
        if (v == null || v.signum() < 0 || v.compareTo(q) >= 0) {
            throw new IllegalArgumentException("v 不在Fp域");
        }

        this.q = q;
        this.r = r;
        this.v = v;
    }

    public BigInteger toBigInteger() {
        return v;
    }

    public int getFieldSize() {
        return q.bitLength();
    }

    public AbstractECElement add(AbstractECElement b) {
        return new FpElement(q, r, modAdd(v, b.toBigInteger()));
    }

    public AbstractECElement subtract(AbstractECElement b) {
        return new FpElement(q, r, modSubtract(v, b.toBigInteger()));
    }

    public AbstractECElement multiply(AbstractECElement b) {
        return new FpElement(q, r, modMult(v, b.toBigInteger()));
    }

    public AbstractECElement divide(AbstractECElement b) {
        return new FpElement(q, r, modMult(v, modInverse(b.toBigInteger())));
    }

    public AbstractECElement negate() {
        return v.signum() == 0 ? this : new FpElement(q, r, q.subtract(v));
    }

    public AbstractECElement square() {
        return new FpElement(q, r, modMult(v, v));
    }

    public AbstractECElement invert() {
        return new FpElement(q, r, modInverse(v));
    }

    private BigInteger modAdd(BigInteger x1, BigInteger x2) {
        BigInteger x3 = x1.add(x2);
        if (x3.compareTo(q) >= 0) {
            x3 = x3.subtract(q);
        }
        return x3;
    }

    private BigInteger modInverse(BigInteger x) {
        int bits = getFieldSize();
        int len = (bits + 31) >> 5;
        int[] p = ConvertUtil.fromBigInteger(bits, q);
        int[] n = ConvertUtil.fromBigInteger(bits, x);
        int[] z = new int[len];
        invert(p, n, z);
        return ConvertUtil.toBigInteger(len, z);
    }

    private BigInteger modMult(BigInteger x1, BigInteger x2) {
        return modReduce(x1.multiply(x2));
    }

    private BigInteger modReduce(BigInteger x) {
        if (r != null) {
            boolean negative = x.signum() < 0;
            if (negative) {
                x = x.abs();
            }
            int qLen = q.bitLength();
            boolean rIsOne = r.equals(BigInteger.valueOf(1));
            while (x.bitLength() > (qLen + 1)) {
                BigInteger u = x.shiftRight(qLen);
                BigInteger v = x.subtract(u.shiftLeft(qLen));
                if (!rIsOne) {
                    u = u.multiply(r);
                }
                x = u.add(v);
            }
            while (x.compareTo(q) >= 0) {
                x = x.subtract(q);
            }
            if (negative && x.signum() != 0) {
                x = q.subtract(x);
            }
        } else {
            x = x.mod(q);
        }
        return x;
    }

    private BigInteger modSubtract(BigInteger x1, BigInteger x2) {
        BigInteger x3 = x1.subtract(x2);
        if (x3.signum() < 0) {
            x3 = x3.add(q);
        }
        return x3;
    }

    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if (!(other instanceof FpElement)) {
            return false;
        }
        FpElement o = (FpElement) other;
        return q.equals(o.q) && v.equals(o.v);
    }
    
    private static final long M = 0xFFFFFFFFL;
    private static void invert(int[] p, int[] x, int[] z) {
        int len = p.length;
        if (isZero(len, x)) {
            throw new IllegalArgumentException("'x' 不能为零");
        }
        if (isOne(len, x)) {
            System.arraycopy(x, 0, z, 0, len);
            return;
        }
        int[] u = copy(len, x);
        int[] a =  new int[len];
        a[0] = 1;
        int ac = 0;
        if ((u[0] & 1) == 0) {
            ac = inversionStep(p, u, len, a, ac);
        }
        if (isOne(len, u)) {
            inversionResult(p, ac, a, z);
            return;
        }
        int[] v = copy(len, p);
        int[] b =  new int[len];
        int bc = 0;
        int uvLen = len;
        for (;;) {
            while (u[uvLen - 1] == 0 && v[uvLen - 1] == 0) {
                --uvLen;
            }
            if (gte(uvLen, u, v)) {
                subFrom(uvLen, v, u);
                ac += subFrom(len, b, a) - bc;
                ac = inversionStep(p, u, uvLen, a, ac);
                if (isOne(uvLen, u)) {
                    inversionResult(p, ac, a, z);
                    return;
                }
            } else {
                subFrom(uvLen, u, v);
                bc += subFrom(len, a, b) - ac;
                bc = inversionStep(p, v, uvLen, b, bc);
                if (isOne(uvLen, v)) {
                    inversionResult(p, bc, b, z);
                    return;
                }
            }
        }
    }
    private static void inversionResult(int[] p, int ac, int[] a, int[] z) {
        if (ac < 0) {
            add(p.length, a, p, z);
        } else {
            System.arraycopy(a, 0, z, 0, p.length);
        }
    }

    private static int inversionStep(int[] p, int[] u, int uLen, int[] x, int xc) {
        int len = p.length;
        int count = 0;
        while (u[0] == 0) {
            shiftDownWord(uLen, u, 0);
            count += 32;
        }
        int zeroes = getTrailingZeroes(u[0]);
        if (zeroes > 0) {
            shiftDownBits(uLen, u, zeroes, 0);
            count += zeroes;
        }
        for (int i = 0; i < count; ++i) {
            if ((x[0] & 1) != 0) {
                if (xc < 0) {
                    xc += addTo(len, p, x);
                } else {
                    xc += subFrom(len, p, x);
                }
            }
            shiftDownBit(len, x, xc);
        }
        return xc;
    }
    private static int getTrailingZeroes(int x) {
        int count = 0;
        while ((x & 1) == 0) {
            x >>>= 1;
            ++count;
        }
        return count;
    }
    private static int add(int len, int[] x, int[] y, int[] z) {
        long c = 0;
        for (int i = 0; i < len; ++i) {
            c += (x[i] & M) + (y[i] & M);
            z[i] = (int) c;
            c >>>= 32;
        }
        return (int) c;
    }

    private static int addTo(int len, int[] x, int[] z) {
        long c = 0;
        for (int i = 0; i < len; ++i) {
            c += (x[i] & M) + (z[i] & M);
            z[i] = (int) c;
            c >>>= 32;
        }
        return (int) c;
    }

    private static int[] copy(int len, int[] x) {
        int[] z = new int[len];
        System.arraycopy(x, 0, z, 0, len);
        return z;
    }

    private static boolean gte(int len, int[] x, int[] y) {
        for (int i = len - 1; i >= 0; --i) {
            int x_i = x[i] ^ Integer.MIN_VALUE;
            int y_i = y[i] ^ Integer.MIN_VALUE;
            if (x_i < y_i)
                return false;
            if (x_i > y_i)
                return true;
        }
        return true;
    }

    private static boolean isOne(int len, int[] x) {
        if (x[0] != 1) {
            return false;
        }
        for (int i = 1; i < len; ++i) {
            if (x[i] != 0) {
                return false;
            }
        }
        return true;
    }

    private static boolean isZero(int len, int[] x) {
        for (int i = 0; i < len; ++i) {
            if (x[i] != 0) {
                return false;
            }
        }
        return true;
    }

    private static int shiftDownBit(int len, int[] z, int c) {
        int i = len;
        while (--i >= 0) {
            int next = z[i];
            z[i] = (next >>> 1) | (c << 31);
            c = next;
        }
        return c << 31;
    }

    private static int shiftDownBits(int len, int[] z, int bits, int c) {
        int i = len;
        while (--i >= 0) {
            int next = z[i];
            z[i] = (next >>> bits) | (c << -bits);
            c = next;
        }
        return c << -bits;
    }

    private static int shiftDownWord(int len, int[] z, int c) {
        int i = len;
        while (--i >= 0) {
            int next = z[i];
            z[i] = c;
            c = next;
        }
        return c;
    }

    private static int subFrom(int len, int[] x, int[] z) {
        long c = 0;
        for (int i = 0; i < len; ++i) {
            c += (z[i] & M) - (x[i] & M);
            z[i] = (int) c;
            c >>= 32;
        }
        return (int) c;
    }

}
