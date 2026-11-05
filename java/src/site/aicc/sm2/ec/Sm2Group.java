package site.aicc.sm2.ec;

import java.math.BigInteger;

/**
 * Point arithmetic on the SM2 curve y^2 = x^3 - 3x + b in Jacobian coordinates.
 *
 * <p>Secret scalars go through {@link #mulGenerator} and {@link #mulVariable}: signed fixed-window
 * methods with a fixed sequence of field operations and full-table scans under masks. Only {@link
 * #wnafGeneratorPlusPoint} and {@link #wnafAdd} are variable time; they are for public scalars (the
 * verification equation and the public half of the key exchange).
 *
 * <p>The exceptional case of the addition formulas (adding a point to itself) is detected under a
 * mask and handled in a branch. It is unreachable in the generator method, and in the variable-base
 * method it needs a scalar within a few units of n, so the branch reveals nothing about a random
 * secret.
 */
final class Sm2Group {
  static final BigInteger B_BIG =
      new BigInteger("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16);
  static final BigInteger GX_BIG =
      new BigInteger("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16);
  static final BigInteger GY_BIG =
      new BigInteger("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16);

  private static final int[] B = Sm2Field.fromBigInteger(B_BIG);
  private static final int[] GX = Sm2Field.fromBigInteger(GX_BIG);
  private static final int[] GY = Sm2Field.fromBigInteger(GY_BIG);
  private static final int[] ONE = {1, 0, 0, 0, 0, 0, 0, 0};
  private static final Sm2ModInverse INVERSE =
      new Sm2ModInverse(Sm2Field.fromBigInteger(Sm2Field.P_BIG));

  /** Bits per signed window of the generator table. */
  private static final int COMB_BITS = 6;

  private static final int COMB_ENTRIES = 1 << (COMB_BITS - 1);
  private static final int COMB_WINDOWS = (256 + COMB_BITS) / COMB_BITS;

  /** Bits per signed window of the variable-base method: 52 windows over a 16-entry table. */
  private static final int VAR_BITS = 5;

  private static final int VAR_ENTRIES = 1 << (VAR_BITS - 1);
  private static final int VAR_WINDOWS = (256 + VAR_BITS) / VAR_BITS;

  /** wNAF widths for verification: a static table for G, a small per-call table for the key. */
  private static final int WNAF_G_BITS = 8;

  private static final int WNAF_P_BITS = 5;

  private Sm2Group() {}

  /** A mutable Jacobian point; Z = 0 is the point at infinity. */
  static final class Point {
    int[] x = new int[8];
    int[] y = new int[8];
    int[] z = new int[8];

    void setAffine(int[] ax, int[] ay) {
      System.arraycopy(ax, 0, x, 0, 8);
      System.arraycopy(ay, 0, y, 0, 8);
      System.arraycopy(ONE, 0, z, 0, 8);
    }

    void set(Point p) {
      System.arraycopy(p.x, 0, x, 0, 8);
      System.arraycopy(p.y, 0, y, 0, 8);
      System.arraycopy(p.z, 0, z, 0, 8);
    }

    boolean isInfinity() {
      return Sm2Field.isZero(z) != 0;
    }
  }

  /**
   * Scratch registers; one instance per scalar multiplication keeps the formulas allocation free.
   */
  static final class Work {
    final int[] t0 = new int[8];
    final int[] t1 = new int[8];
    final int[] t2 = new int[8];
    final int[] t3 = new int[8];
    final int[] t4 = new int[8];
    final int[] t5 = new int[8];
    final int[] t6 = new int[8];
    final int[] t7 = new int[8];
    Point out = new Point();
  }

  // ---------------------------------------------------------------- formulas

  /** Doubles q in place (dbl-2001-b, 3M + 5S using a = -3). Infinity stays infinity. */
  static void dbl(Point q, Work w) {
    int[] x = q.x;
    int[] y = q.y;
    int[] z = q.z;
    int[] delta = w.t0;
    int[] gamma = w.t1;
    int[] beta = w.t2;
    int[] alpha = w.t3;
    int[] tmp = w.t4;
    Sm2Field.sqr(delta, z);
    Sm2Field.sqr(gamma, y);
    Sm2Field.mul(beta, x, gamma);
    Sm2Field.sub(alpha, x, delta);
    Sm2Field.add(tmp, x, delta);
    Sm2Field.mul(alpha, alpha, tmp);
    Sm2Field.add(tmp, alpha, alpha);
    Sm2Field.add(alpha, tmp, alpha);
    // Z3 = (Y + Z)^2 - gamma - delta
    Sm2Field.add(z, y, z);
    Sm2Field.sqr(z, z);
    Sm2Field.sub(z, z, gamma);
    Sm2Field.sub(z, z, delta);
    // X3 = alpha^2 - 8 beta
    Sm2Field.add(beta, beta, beta);
    Sm2Field.add(beta, beta, beta);
    Sm2Field.add(tmp, beta, beta);
    Sm2Field.sqr(x, alpha);
    Sm2Field.sub(x, x, tmp);
    // Y3 = alpha (4 beta - X3) - 8 gamma^2
    Sm2Field.sub(beta, beta, x);
    Sm2Field.mul(y, alpha, beta);
    Sm2Field.sqr(gamma, gamma);
    Sm2Field.add(gamma, gamma, gamma);
    Sm2Field.add(gamma, gamma, gamma);
    Sm2Field.add(gamma, gamma, gamma);
    Sm2Field.sub(y, y, gamma);
  }

  /**
   * Computes q + (px, py, 1) into w.out without looking at exceptional cases (8M + 3S). Leaves H in
   * w.t4 and R in w.t5.
   */
  private static void addAffineRaw(Point q, int[] px, int[] py, Work w) {
    int[] zz = w.t0;
    int[] u2 = w.t1;
    int[] s2 = w.t2;
    int[] hh = w.t3;
    int[] h = w.t4;
    int[] r = w.t5;
    int[] hhh = w.t6;
    int[] v = w.t7;
    Point o = w.out;
    Sm2Field.sqr(zz, q.z);
    Sm2Field.mul(u2, px, zz);
    Sm2Field.mul(s2, q.z, zz);
    Sm2Field.mul(s2, py, s2);
    Sm2Field.sub(h, u2, q.x);
    Sm2Field.sub(r, s2, q.y);
    Sm2Field.sqr(hh, h);
    Sm2Field.mul(hhh, h, hh);
    Sm2Field.mul(v, q.x, hh);
    Sm2Field.sqr(o.x, r);
    Sm2Field.sub(o.x, o.x, hhh);
    Sm2Field.sub(o.x, o.x, v);
    Sm2Field.sub(o.x, o.x, v);
    Sm2Field.sub(v, v, o.x);
    Sm2Field.mul(o.y, r, v);
    Sm2Field.mul(hhh, q.y, hhh);
    Sm2Field.sub(o.y, o.y, hhh);
    Sm2Field.mul(o.z, q.z, h);
  }

  /** Computes q + p into w.out without looking at exceptional cases; H in w.t4, R in w.t5. */
  private static void addRaw(Point q, Point p, Work w) {
    int[] z1z1 = w.t0;
    int[] z2z2 = w.t1;
    int[] u1 = w.t2;
    int[] s1 = w.t3;
    int[] h = w.t4;
    int[] r = w.t5;
    int[] hh = w.t6;
    int[] hhh = w.t7;
    Point o = w.out;
    Sm2Field.sqr(z1z1, q.z);
    Sm2Field.sqr(z2z2, p.z);
    Sm2Field.mul(u1, q.x, z2z2);
    Sm2Field.mul(h, p.x, z1z1);
    Sm2Field.sub(h, h, u1);
    Sm2Field.mul(s1, p.z, z2z2);
    Sm2Field.mul(s1, q.y, s1);
    Sm2Field.mul(r, q.z, z1z1);
    Sm2Field.mul(r, p.y, r);
    Sm2Field.sub(r, r, s1);
    Sm2Field.sqr(hh, h);
    Sm2Field.mul(hhh, h, hh);
    Sm2Field.mul(u1, u1, hh);
    Sm2Field.sqr(o.x, r);
    Sm2Field.sub(o.x, o.x, hhh);
    Sm2Field.sub(o.x, o.x, u1);
    Sm2Field.sub(o.x, o.x, u1);
    Sm2Field.sub(u1, u1, o.x);
    Sm2Field.mul(o.y, r, u1);
    Sm2Field.mul(s1, s1, hhh);
    Sm2Field.sub(o.y, o.y, s1);
    Sm2Field.mul(o.z, q.z, p.z);
    Sm2Field.mul(o.z, o.z, h);
  }

  /** Moves w.out into q by exchanging arrays, which avoids copying. */
  private static void take(Point q, Work w) {
    Point o = w.out;
    int[] t = q.x;
    q.x = o.x;
    o.x = t;
    t = q.y;
    q.y = o.y;
    o.y = t;
    t = q.z;
    q.z = o.z;
    o.z = t;
  }

  /** Masked q += (px, py) where pInf marks a zero digit. */
  static void addAffineMasked(Point q, int[] px, int[] py, int pInf, Work w) {
    int qInf = Sm2Field.isZero(q.z);
    addAffineRaw(q, px, py, w);
    if ((Sm2Field.isZero(w.t4) & Sm2Field.isZero(w.t5) & ~qInf & ~pInf) != 0) {
      dbl(q, w);
      return;
    }
    Point o = w.out;
    Sm2Field.select(o.x, px, qInf);
    Sm2Field.select(o.y, py, qInf);
    Sm2Field.select(o.z, ONE, qInf);
    Sm2Field.select(o.x, q.x, pInf);
    Sm2Field.select(o.y, q.y, pInf);
    Sm2Field.select(o.z, q.z, pInf);
    take(q, w);
  }

  /** Masked q += p where pInf marks a zero digit. */
  static void addMasked(Point q, Point p, int pInf, Work w) {
    int qInf = Sm2Field.isZero(q.z);
    addRaw(q, p, w);
    if ((Sm2Field.isZero(w.t4) & Sm2Field.isZero(w.t5) & ~qInf & ~pInf) != 0) {
      dbl(q, w);
      return;
    }
    Point o = w.out;
    Sm2Field.select(o.x, p.x, qInf);
    Sm2Field.select(o.y, p.y, qInf);
    Sm2Field.select(o.z, p.z, qInf);
    Sm2Field.select(o.x, q.x, pInf);
    Sm2Field.select(o.y, q.y, pInf);
    Sm2Field.select(o.z, q.z, pInf);
    take(q, w);
  }

  /** Variable-time q += (px, py). */
  static void addAffineVt(Point q, int[] px, int[] py, Work w) {
    if (q.isInfinity()) {
      q.setAffine(px, py);
      return;
    }
    addAffineRaw(q, px, py, w);
    if (Sm2Field.isZero(w.t4) != 0 && Sm2Field.isZero(w.t5) != 0) {
      dbl(q, w);
      return;
    }
    take(q, w);
  }

  /** Variable-time q += p. */
  static void addVt(Point q, Point p, Work w) {
    if (p.isInfinity()) {
      return;
    }
    if (q.isInfinity()) {
      q.set(p);
      return;
    }
    addRaw(q, p, w);
    if (Sm2Field.isZero(w.t4) != 0 && Sm2Field.isZero(w.t5) != 0) {
      dbl(q, w);
      return;
    }
    take(q, w);
  }

  /** Checks the curve equation y^2 = x^3 - 3x + b. */
  static boolean isOnCurve(int[] x, int[] y) {
    int[] lhs = new int[8];
    int[] rhs = new int[8];
    int[] t = new int[8];
    Sm2Field.sqr(lhs, y);
    Sm2Field.sqr(rhs, x);
    Sm2Field.add(t, x, x);
    Sm2Field.add(t, t, x);
    Sm2Field.mul(rhs, rhs, x);
    Sm2Field.sub(rhs, rhs, t);
    Sm2Field.add(rhs, rhs, B);
    return Sm2Field.isEqual(lhs, rhs) != 0;
  }

  /** Sets {@code r = a^-1 mod p}, or 0 when a is 0. */
  static void invert(int[] r, int[] a) {
    INVERSE.invert(r, a);
  }

  /** Writes the affine coordinates of a finite q. */
  static void toAffine(Point q, int[] ax, int[] ay) {
    int[] zi = new int[8];
    int[] zi2 = new int[8];
    invert(zi, q.z);
    Sm2Field.sqr(zi2, zi);
    Sm2Field.mul(ax, q.x, zi2);
    Sm2Field.mul(zi2, zi2, zi);
    Sm2Field.mul(ay, q.y, zi2);
  }

  // ---------------------------------------------------------------- recoding

  private static int bitsAt(int[] k, int start, int width) {
    int limb = start >>> 5;
    long lo = limb < 8 ? k[limb] & 0xFFFFFFFFL : 0;
    long hi = limb + 1 < 8 ? k[limb + 1] & 0xFFFFFFFFL : 0;
    return (int) (((lo | (hi << 32)) >>> (start & 31)) & ((1L << width) - 1));
  }

  /**
   * Booth recoding of window {@code index}: returns {@code (|digit| << 1) | negative}. Computed
   * without branches on the scalar.
   */
  private static int boothDigit(int[] k, int index, int bits) {
    int pos = index * bits;
    int raw = pos == 0 ? (bitsAt(k, 0, bits) << 1) : bitsAt(k, pos - 1, bits + 1);
    int negative = -(raw >>> bits);
    int folded = ((1 << (bits + 1)) - raw - 1) & negative | raw & ~negative;
    int magnitude = (folded >>> 1) + (folded & 1);
    return (magnitude << 1) | (negative & 1);
  }

  // ---------------------------------------------------------------- generator tables

  /** Lazily built: flat [window][|digit| - 1][x, y] table of k * 64^window * G, 88 KB. */
  private static final class CombTable {
    static final int[] TABLE = build();

    private static int[] build() {
      int[] table = new int[COMB_WINDOWS * COMB_ENTRIES * 16];
      Work w = new Work();
      Point[] row = new Point[COMB_ENTRIES];
      for (int i = 0; i < COMB_ENTRIES; i++) {
        row[i] = new Point();
      }
      int[] bx = GX.clone();
      int[] by = GY.clone();
      Point next = new Point();
      for (int window = 0; window < COMB_WINDOWS; window++) {
        row[0].setAffine(bx, by);
        for (int i = 1; i < COMB_ENTRIES; i++) {
          row[i].set(row[i - 1]);
          addAffineVt(row[i], bx, by, w);
        }
        normalizeInto(row, table, window * COMB_ENTRIES * 16);
        // base * 2^COMB_BITS = (top entry = base * 2^(COMB_BITS - 1)) doubled once.
        int top = window * COMB_ENTRIES * 16 + (COMB_ENTRIES - 1) * 16;
        next.setAffine(copy(table, top), copy(table, top + 8));
        dbl(next, w);
        toAffine(next, bx, by);
      }
      return table;
    }
  }

  /** Lazily built: odd multiples 1, 3, ..., 255 of G in affine form for wNAF verification. */
  private static final class WnafTable {
    static final int[] TABLE = build();

    private static int[] build() {
      int entries = 1 << (WNAF_G_BITS - 1);
      Point[] row = new Point[entries];
      Work w = new Work();
      Point twice = new Point();
      twice.setAffine(GX, GY);
      dbl(twice, w);
      row[0] = new Point();
      row[0].setAffine(GX, GY);
      for (int i = 1; i < entries; i++) {
        row[i] = new Point();
        row[i].set(row[i - 1]);
        addVt(row[i], twice, w);
      }
      int[] table = new int[entries * 16];
      normalizeInto(row, table, 0);
      return table;
    }
  }

  private static int[] copy(int[] table, int off) {
    int[] r = new int[8];
    System.arraycopy(table, off, r, 0, 8);
    return r;
  }

  /** Batch inversion (Montgomery's trick) of the Z coordinates of finite points. */
  private static void normalizeInto(Point[] points, int[] out, int off) {
    int n = points.length;
    int[][] prefix = new int[n][8];
    System.arraycopy(points[0].z, 0, prefix[0], 0, 8);
    for (int i = 1; i < n; i++) {
      Sm2Field.mul(prefix[i], prefix[i - 1], points[i].z);
    }
    int[] inv = new int[8];
    invert(inv, prefix[n - 1]);
    int[] zi = new int[8];
    int[] zi2 = new int[8];
    int[] v = new int[8];
    for (int i = n - 1; i >= 0; i--) {
      if (i > 0) {
        Sm2Field.mul(zi, inv, prefix[i - 1]);
        Sm2Field.mul(inv, inv, points[i].z);
      } else {
        System.arraycopy(inv, 0, zi, 0, 8);
      }
      Sm2Field.sqr(zi2, zi);
      Sm2Field.mul(v, points[i].x, zi2);
      System.arraycopy(v, 0, out, off + i * 16, 8);
      Sm2Field.mul(zi2, zi2, zi);
      Sm2Field.mul(v, points[i].y, zi2);
      System.arraycopy(v, 0, out, off + i * 16 + 8, 8);
    }
  }

  // ---------------------------------------------------------------- scalar multiplication

  /** Constant-flow k * G for {@code 0 <= k < n}: one mixed addition per window, no doublings. */
  static Point mulGenerator(int[] k) {
    int[] table = CombTable.TABLE;
    Work w = new Work();
    Point q = new Point();
    int[] px = new int[8];
    int[] py = new int[8];
    for (int window = 0; window < COMB_WINDOWS; window++) {
      int coded = boothDigit(k, window, COMB_BITS);
      int magnitude = coded >>> 1;
      int base = window * COMB_ENTRIES * 16;
      scanAffine(table, base, COMB_ENTRIES, magnitude, px, py);
      Sm2Field.condNeg(py, py, -(coded & 1));
      addAffineMasked(q, px, py, (magnitude - 1) >> 31, w);
    }
    return q;
  }

  /** Reads entry {@code magnitude - 1} by touching every entry; all zero when magnitude is 0. */
  private static void scanAffine(
      int[] table, int base, int entries, int magnitude, int[] px, int[] py) {
    int x0 = 0;
    int x1 = 0;
    int x2 = 0;
    int x3 = 0;
    int x4 = 0;
    int x5 = 0;
    int x6 = 0;
    int x7 = 0;
    int y0 = 0;
    int y1 = 0;
    int y2 = 0;
    int y3 = 0;
    int y4 = 0;
    int y5 = 0;
    int y6 = 0;
    int y7 = 0;
    for (int e = 0, o = base; e < entries; e++, o += 16) {
      int m = (((e + 1) ^ magnitude) - 1) >> 31;
      x0 |= table[o] & m;
      x1 |= table[o + 1] & m;
      x2 |= table[o + 2] & m;
      x3 |= table[o + 3] & m;
      x4 |= table[o + 4] & m;
      x5 |= table[o + 5] & m;
      x6 |= table[o + 6] & m;
      x7 |= table[o + 7] & m;
      y0 |= table[o + 8] & m;
      y1 |= table[o + 9] & m;
      y2 |= table[o + 10] & m;
      y3 |= table[o + 11] & m;
      y4 |= table[o + 12] & m;
      y5 |= table[o + 13] & m;
      y6 |= table[o + 14] & m;
      y7 |= table[o + 15] & m;
    }
    px[0] = x0;
    px[1] = x1;
    px[2] = x2;
    px[3] = x3;
    px[4] = x4;
    px[5] = x5;
    px[6] = x6;
    px[7] = x7;
    py[0] = y0;
    py[1] = y1;
    py[2] = y2;
    py[3] = y3;
    py[4] = y4;
    py[5] = y5;
    py[6] = y6;
    py[7] = y7;
  }

  /** Constant-flow k * base for {@code 0 <= k < n} and a finite base. */
  static Point mulVariable(Point base, int[] k) {
    Work w = new Work();
    int[] table = new int[VAR_ENTRIES * 24];
    Point[] multiples = new Point[VAR_ENTRIES + 1];
    multiples[1] = base;
    for (int j = 2; j <= VAR_ENTRIES; j++) {
      Point m = new Point();
      if ((j & 1) == 0) {
        m.set(multiples[j >> 1]);
        dbl(m, w);
      } else {
        addRaw(multiples[j - 1], base, w);
        take(m, w);
      }
      multiples[j] = m;
    }
    for (int j = 1; j <= VAR_ENTRIES; j++) {
      int o = (j - 1) * 24;
      System.arraycopy(multiples[j].x, 0, table, o, 8);
      System.arraycopy(multiples[j].y, 0, table, o + 8, 8);
      System.arraycopy(multiples[j].z, 0, table, o + 16, 8);
    }
    Point q = new Point();
    Point p = new Point();
    for (int window = VAR_WINDOWS - 1; window >= 0; window--) {
      if (window != VAR_WINDOWS - 1) {
        for (int i = 0; i < VAR_BITS; i++) {
          dbl(q, w);
        }
      }
      int coded = boothDigit(k, window, VAR_BITS);
      int magnitude = coded >>> 1;
      scanJacobian(table, magnitude, p);
      Sm2Field.condNeg(p.y, p.y, -(coded & 1));
      addMasked(q, p, (magnitude - 1) >> 31, w);
    }
    return q;
  }

  private static void scanJacobian(int[] table, int magnitude, Point p) {
    int[] x = p.x;
    int[] y = p.y;
    int[] z = p.z;
    for (int i = 0; i < 8; i++) {
      x[i] = 0;
      y[i] = 0;
      z[i] = 0;
    }
    for (int e = 0, o = 0; e < VAR_ENTRIES; e++, o += 24) {
      int m = (((e + 1) ^ magnitude) - 1) >> 31;
      for (int i = 0; i < 8; i++) {
        x[i] |= table[o + i] & m;
        y[i] |= table[o + 8 + i] & m;
        z[i] |= table[o + 16 + i] & m;
      }
    }
  }

  /** Width-w NAF of a public scalar below 2^256, one signed digit per bit position. */
  static byte[] wnaf(int[] k, int bits) {
    byte[] digits = new byte[258];
    int carry = 0;
    int pos = 0;
    while (pos <= 256) {
      int bit = pos < 256 ? (k[pos >>> 5] >>> (pos & 31)) & 1 : 0;
      if (bit == carry) {
        pos++;
        continue;
      }
      int word = bitsAt(k, pos, bits) + carry;
      carry = (word >>> (bits - 1)) & 1;
      digits[pos] = (byte) (word - (carry << bits));
      pos += bits;
    }
    return digits;
  }

  /** Variable-time s * G + t * (px, py) for public scalars below 2^256. */
  static Point wnafGeneratorPlusPoint(int[] s, int[] t, int[] px, int[] py) {
    int[] gTable = WnafTable.TABLE;
    byte[] sDigits = wnaf(s, WNAF_G_BITS);
    byte[] tDigits = wnaf(t, WNAF_P_BITS);
    Work w = new Work();
    Point[] odd = oddMultiples(px, py, w);
    Point q = new Point();
    Point neg = new Point();
    int[] gx = new int[8];
    int[] gy = new int[8];
    boolean started = false;
    for (int i = 257; i >= 0; i--) {
      if (started) {
        dbl(q, w);
      }
      int ds = sDigits[i];
      if (ds != 0) {
        int o = ((Math.abs(ds) - 1) >> 1) * 16;
        System.arraycopy(gTable, o, gx, 0, 8);
        System.arraycopy(gTable, o + 8, gy, 0, 8);
        if (ds < 0) {
          Sm2Field.neg(gy, gy);
        }
        addAffineVt(q, gx, gy, w);
        started = true;
      }
      int dt = tDigits[i];
      if (dt != 0) {
        Point entry = odd[(Math.abs(dt) - 1) >> 1];
        if (dt < 0) {
          neg.set(entry);
          Sm2Field.neg(neg.y, neg.y);
          entry = neg;
        }
        addVt(q, entry, w);
        started = true;
      }
    }
    return q;
  }

  /** Variable-time q + k * (px, py) for a public k below 2^256; q is updated in place. */
  static void wnafAdd(Point q, int[] k, int[] px, int[] py) {
    byte[] digits = wnaf(k, WNAF_P_BITS);
    Work w = new Work();
    Point[] odd = oddMultiples(px, py, w);
    Point sum = new Point();
    Point neg = new Point();
    boolean started = false;
    for (int i = 257; i >= 0; i--) {
      if (started) {
        dbl(sum, w);
      }
      int d = digits[i];
      if (d != 0) {
        Point entry = odd[(Math.abs(d) - 1) >> 1];
        if (d < 0) {
          neg.set(entry);
          Sm2Field.neg(neg.y, neg.y);
          entry = neg;
        }
        addVt(sum, entry, w);
        started = true;
      }
    }
    addVt(sum, q, w);
    q.set(sum);
  }

  private static Point[] oddMultiples(int[] px, int[] py, Work w) {
    Point[] odd = new Point[1 << (WNAF_P_BITS - 1)];
    odd[0] = new Point();
    odd[0].setAffine(px, py);
    Point twice = new Point();
    twice.set(odd[0]);
    dbl(twice, w);
    for (int i = 1; i < odd.length; i++) {
      odd[i] = new Point();
      odd[i].set(odd[i - 1]);
      addVt(odd[i], twice, w);
    }
    return odd;
  }

  static boolean isGenerator(int[] x, int[] y) {
    return (Sm2Field.isEqual(x, GX) & Sm2Field.isEqual(y, GY)) != 0;
  }
}
