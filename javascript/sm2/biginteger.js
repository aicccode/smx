export class BigInteger {
  constructor(a, b, c) {
    this.dbits = null;
    this.canary = 0xdeadbeefcafe;
    this.j_lm = ((this.canary & 0xffffff) == 0xefcafe);

    this.lowprimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997];
    this.lplim = (1 << 26) / this.lowprimes[this.lowprimes.length - 1];

    this.inBrowser = typeof navigator !== 'undefined';
    if (this.inBrowser && this.j_lm && (navigator.appName == 'Microsoft Internet Explorer')) {
      this.am = this.am2;
      this.dbits = 30;
    } else if (this.inBrowser && this.j_lm && (navigator.appName != 'Netscape')) {
      this.am = this.am1;
      this.dbits = 26;
    } else {
      this.am = this.am3;
      this.dbits = 28;
    }


    this.DB = this.dbits;
    this.DM = ((1 << this.dbits) - 1);
    this.DV = (1 << this.dbits);

    this.BI_FP = 52;
    this.FV = Math.pow(2, this.BI_FP);
    this.F1 = this.BI_FP - this.dbits;
    this.F2 = 2 * this.dbits - this.BI_FP;
    this.BI_RM = '0123456789abcdefghijklmnopqrstuvwxyz';
    this.BI_RC = [];
    this.rr = null;
    this.vv = null;
    this.rr = '0'.charCodeAt(0);
    for (this.vv = 0; this.vv <= 9; ++this.vv) this.BI_RC[this.rr++] = this.vv;
    this.rr = 'a'.charCodeAt(0);
    for (this.vv = 10; this.vv < 36; ++this.vv) this.BI_RC[this.rr++] = this.vv;
    this.rr = 'A'.charCodeAt(0);
    for (this.vv = 10; this.vv < 36; ++this.vv) this.BI_RC[this.rr++] = this.vv;


    this.copyTo = this.bnpCopyTo;
    this.fromInt = this.bnpFromInt;
    this.fromString = this.bnpFromString;
    this.clamp = this.bnpClamp;
    this.dlShiftTo = this.bnpDLShiftTo;
    this.drShiftTo = this.bnpDRShiftTo;
    this.lShiftTo = this.bnpLShiftTo;
    this.rShiftTo = this.bnpRShiftTo;
    this.subTo = this.bnpSubTo;
    this.multiplyTo = this.bnpMultiplyTo;
    this.squareTo = this.bnpSquareTo;
    this.divRemTo = this.bnpDivRemTo;
    this.invDigit = this.bnpInvDigit;
    this.isEven = this.bnpIsEven;
    this.exp = this.bnpExp;

    // public
    this.toString = this.bnToString;
    this.negate = this.bnNegate;
    this.abs = this.bnAbs;
    this.compareTo = this.bnCompareTo;
    this.bitLength = this.bnBitLength;
    this.mod = this.bnMod;
    this.modPowInt = this.bnModPowInt;


    // protected
    this.chunkSize = this.bnpChunkSize;
    this.toRadix = this.bnpToRadix;
    this.fromRadix = this.bnpFromRadix;
    this.fromNumber = this.bnpFromNumber;
    this.bitwiseTo = this.bnpBitwiseTo;
    this.changeBit = this.bnpChangeBit;
    this.addTo = this.bnpAddTo;
    this.dMultiply = this.bnpDMultiply;
    this.dAddOffset = this.bnpDAddOffset;
    this.multiplyLowerTo = this.bnpMultiplyLowerTo;
    this.multiplyUpperTo = this.bnpMultiplyUpperTo;
    this.modInt = this.bnpModInt;
    this.millerRabin = this.bnpMillerRabin;

    // public
    this.clone = this.bnClone;
    this.intValue = this.bnIntValue;
    this.byteValue = this.bnByteValue;
    this.shortValue = this.bnShortValue;
    this.signum = this.bnSigNum;
    this.toByteArray = this.bnToByteArray;
    this.equals = this.bnEquals;
    this.min = this.bnMin;
    this.max = this.bnMax;
    this.and = this.bnAnd;
    this.or = this.bnOr;
    this.xor = this.bnXor;
    this.andNot = this.bnAndNot;
    this.not = this.bnNot;
    this.shiftLeft = this.bnShiftLeft;
    this.shiftRight = this.bnShiftRight;
    this.getLowestSetBit = this.bnGetLowestSetBit;
    this.bitCount = this.bnBitCount;
    this.testBit = this.bnTestBit;
    this.setBit = this.bnSetBit;
    this.clearBit = this.bnClearBit;
    this.flipBit = this.bnFlipBit;
    this.add = this.bnAdd;
    this.subtract = this.bnSubtract;
    this.multiply = this.bnMultiply;
    this.divide = this.bnDivide;
    this.remainder = this.bnRemainder;
    this.divideAndRemainder = this.bnDivideAndRemainder;
    this.modPow = this.bnModPow;
    this.modInverse = this.bnModInverse;
    this.pow = this.bnPow;
    this.gcd = this.bnGCD;
    this.isProbablePrime = this.bnIsProbablePrime;
    this.square = this.bnSquare;
    this.Barrett = Barrett

    // =========================
    if (a != null) {
      if (typeof a == 'number') this.fromNumber(a, b, c);
      else if (b == null && typeof a != 'string') this.fromString(a, 256);
      else this.fromString(a, b);
    }
  }

  nbi() { return new BigInteger(null); }

  ONE() {
    return this.nbv(1)
  }
  ZERO() {
    return this.nbv(0)
  }

  am1(i, x, w, j, c, n) {
    while (--n >= 0) {
      const v = x * this[i++] + w[j] + c;
      c = Math.floor(v / 0x4000000);
      w[j++] = v & 0x3ffffff;
    }
    return c;
  }

  am2(i, x, w, j, c, n) {
    const xl = x & 0x7fff; const xh = x >> 15;
    while (--n >= 0) {
      let l = this[i] & 0x7fff;
      const h = this[i++] >> 15;
      const m = xh * l + h * xl;
      l = xl * l + ((m & 0x7fff) << 15) + w[j] + (c & 0x3fffffff);
      c = (l >>> 30) + (m >>> 15) + xh * h + (c >>> 30);
      w[j++] = l & 0x3fffffff;
    }
    return c;
  }
  am3(i, x, w, j, c, n) {
    const xl = x & 0x3fff; const xh = x >> 14;
    while (--n >= 0) {
      let l = this[i] & 0x3fff;
      const h = this[i++] >> 14;
      const m = xh * l + h * xl;
      l = xl * l + ((m & 0x3fff) << 14) + w[j] + c;
      c = (l >> 28) + (m >> 14) + xh * h;
      w[j++] = l & 0xfffffff;
    }
    return c;
  }


  int2char(n) { return this.BI_RM.charAt(n); }

  intAt(s, i) {
    const c = this.BI_RC[s.charCodeAt(i)];
    return (c == null) ? -1 : c;
  }
  bnpCopyTo(r) {
    for (let i = this.t - 1; i >= 0; --i) r[i] = this[i];
    r.t = this.t;
    r.s = this.s;
  }
  bnpFromInt(x) {
    this.t = 1;
    this.s = (x < 0) ? -1 : 0;
    if (x > 0) this[0] = x;
    else if (x < -1) this[0] = x + this.DV;
    else this.t = 0;
  }

  nbv(i) { const r = this.nbi(); r.fromInt(i); return r; }

  bnpFromString(s, b) {
    let k;
    if (b == 16) k = 4;
    else if (b == 8) k = 3;
    else if (b == 256) k = 8; // byte array
    else if (b == 2) k = 1;
    else if (b == 32) k = 5;
    else if (b == 4) k = 2;
    else { this.fromRadix(s, b); return; }
    this.t = 0;
    this.s = 0;
    let i = s.length; let mi = false; let sh = 0;
    while (--i >= 0) {
      const x = (k == 8) ? s[i] & 0xff : this.intAt(s, i);
      if (x < 0) {
        if (s.charAt(i) == '-') mi = true;
        continue;
      }
      mi = false;
      if (sh == 0) { this[this.t++] = x; } else if (sh + k > this.DB) {
        this[this.t - 1] |= (x & ((1 << (this.DB - sh)) - 1)) << sh;
        this[this.t++] = (x >> (this.DB - sh));
      } else { this[this.t - 1] |= x << sh; }
      sh += k;
      if (sh >= this.DB) sh -= this.DB;
    }
    if (k == 8 && (s[0] & 0x80) != 0) {
      this.s = -1;
      if (sh > 0) this[this.t - 1] |= ((1 << (this.DB - sh)) - 1) << sh;
    }
    this.clamp();
    if (mi) this.ZERO().subTo(this, this);
  }

  bnpClamp() {
    const c = this.s & this.DM;
    while (this.t > 0 && this[this.t - 1] == c) --this.t;
  }

  bnToString(b) {
    if (this.s < 0) return '-' + this.negate().toString(b);
    let k;
    if (b == 16) k = 4;
    else if (b == 8) k = 3;
    else if (b == 2) k = 1;
    else if (b == 32) k = 5;
    else if (b == 4) k = 2;
    else return this.toRadix(b);
    const km = (1 << k) - 1; let d; let m = false; let r = ''; let i = this.t;
    let p = this.DB - (i * this.DB) % k;
    if (i-- > 0) {
      if (p < this.DB && (d = this[i] >> p) > 0) { m = true; r = this.int2char(d); }
      while (i >= 0) {
        if (p < k) {
          d = (this[i] & ((1 << p) - 1)) << (k - p);
          d |= this[--i] >> (p += this.DB - k);
        } else {
          d = (this[i] >> (p -= k)) & km;
          if (p <= 0) { p += this.DB; --i; }
        }
        if (d > 0) m = true;
        if (m) r += this.int2char(d);
      }
    }
    return m ? r : '0';
  }

  bnNegate() { const r = this.nbi(); this.ZERO().subTo(this, r); return r; }

  bnAbs() { return (this.s < 0) ? this.negate() : this; }

  bnCompareTo(a) {
    let r = this.s - a.s;
    if (r != 0) return r;
    let i = this.t;
    r = i - a.t;
    if (r != 0) return (this.s < 0) ? -r : r;
    while (--i >= 0) if ((r = this[i] - a[i]) != 0) return r;
    return 0;
  }

  nbits(x) {
    let r = 1; let t;
    if ((t = x >>> 16) != 0) { x = t; r += 16; }
    if ((t = x >> 8) != 0) { x = t; r += 8; }
    if ((t = x >> 4) != 0) { x = t; r += 4; }
    if ((t = x >> 2) != 0) { x = t; r += 2; }
    if ((t = x >> 1) != 0) { x = t; r += 1; }
    return r;
  }

  bnBitLength() {
    if (this.t <= 0) return 0;
    return this.DB * (this.t - 1) + this.nbits(this[this.t - 1] ^ (this.s & this.DM));
  }

  bnpDLShiftTo(n, r) {
    let i;
    for (i = this.t - 1; i >= 0; --i) r[i + n] = this[i];
    for (i = n - 1; i >= 0; --i) r[i] = 0;
    r.t = this.t + n;
    r.s = this.s;
  }

  bnpDRShiftTo(n, r) {
    for (let i = n; i < this.t; ++i) r[i - n] = this[i];
    r.t = Math.max(this.t - n, 0);
    r.s = this.s;
  }

  bnpLShiftTo(n, r) {
    const bs = n % this.DB;
    const cbs = this.DB - bs;
    const bm = (1 << cbs) - 1;
    const ds = Math.floor(n / this.DB); let c = (this.s << bs) & this.DM; let i;
    for (i = this.t - 1; i >= 0; --i) {
      r[i + ds + 1] = (this[i] >> cbs) | c;
      c = (this[i] & bm) << bs;
    }
    for (i = ds - 1; i >= 0; --i) r[i] = 0;
    r[ds] = c;
    r.t = this.t + ds + 1;
    r.s = this.s;
    r.clamp();
  }

  bnpRShiftTo(n, r) {
    r.s = this.s;
    const ds = Math.floor(n / this.DB);
    if (ds >= this.t) { r.t = 0; return; }
    const bs = n % this.DB;
    const cbs = this.DB - bs;
    const bm = (1 << bs) - 1;
    r[0] = this[ds] >> bs;
    for (let i = ds + 1; i < this.t; ++i) {
      r[i - ds - 1] |= (this[i] & bm) << cbs;
      r[i - ds] = this[i] >> bs;
    }
    if (bs > 0) r[this.t - ds - 1] |= (this.s & bm) << cbs;
    r.t = this.t - ds;
    r.clamp();
  }

  bnpSubTo(a, r) {
    let i = 0; let c = 0; const m = Math.min(a.t, this.t);
    while (i < m) {
      c += this[i] - a[i];
      r[i++] = c & this.DM;
      c >>= this.DB;
    }
    if (a.t < this.t) {
      c -= a.s;
      while (i < this.t) {
        c += this[i];
        r[i++] = c & this.DM;
        c >>= this.DB;
      }
      c += this.s;
    } else {
      c += this.s;
      while (i < a.t) {
        c -= a[i];
        r[i++] = c & this.DM;
        c >>= this.DB;
      }
      c -= a.s;
    }
    r.s = (c < 0) ? -1 : 0;
    if (c < -1) r[i++] = this.DV + c;
    else if (c > 0) r[i++] = c;
    r.t = i;
    r.clamp();
  }

  bnpMultiplyTo(a, r) {
    const x = this.abs(); const y = a.abs();
    let i = x.t;
    r.t = i + y.t;
    while (--i >= 0) r[i] = 0;
    for (i = 0; i < y.t; ++i) r[i + x.t] = x.am(0, y[i], r, i, 0, x.t);
    r.s = 0;
    r.clamp();
    if (this.s != a.s) this.ZERO().subTo(r, r);
  }

  bnpSquareTo(r) {
    const x = this.abs();
    let i = r.t = 2 * x.t;
    while (--i >= 0) r[i] = 0;
    for (i = 0; i < x.t - 1; ++i) {
      const c = x.am(i, x[i], r, 2 * i, 0, 1);
      if ((r[i + x.t] += x.am(i + 1, 2 * x[i], r, 2 * i + 1, c, x.t - i - 1)) >= x.DV) {
        r[i + x.t] -= x.DV;
        r[i + x.t + 1] = 1;
      }
    }
    if (r.t > 0) r[r.t - 1] += x.am(i, x[i], r, 2 * i, 0, 1);
    r.s = 0;
    r.clamp();
  }
  bnpDivRemTo(m, q, r) {
    const pm = m.abs();
    if (pm.t <= 0) return;
    const pt = this.abs();
    if (pt.t < pm.t) {
      if (q != null) q.fromInt(0);
      if (r != null) this.copyTo(r);
      return;
    }
    if (r == null) r = this.nbi();
    const y = this.nbi(); const ts = this.s; const ms = m.s;
    const nsh = this.DB - this.nbits(pm[pm.t - 1]); // normalize modulus
    if (nsh > 0) { pm.lShiftTo(nsh, y); pt.lShiftTo(nsh, r); } else { pm.copyTo(y); pt.copyTo(r); }
    const ys = y.t;
    const y0 = y[ys - 1];
    if (y0 == 0) return;
    const yt = y0 * (1 << this.F1) + ((ys > 1) ? y[ys - 2] >> this.F2 : 0);
    const d1 = this.FV / yt; const d2 = (1 << this.F1) / yt; const e = 1 << this.F2;
    let i = r.t; let j = i - ys; const t = (q == null) ? this.nbi() : q;
    y.dlShiftTo(j, t);
    if (r.compareTo(t) >= 0) {
      r[r.t++] = 1;
      r.subTo(t, r);
    }
    this.nbv(1).dlShiftTo(ys, t);
    t.subTo(y, y); // "negative" y so we can replace sub with am later
    while (y.t < ys) y[y.t++] = 0;
    while (--j >= 0) {
      // Estimate quotient digit
      let qd = (r[--i] == y0) ? this.DM : Math.floor(r[i] * d1 + (r[i - 1] + e) * d2);
      if ((r[i] += y.am(0, qd, r, j, 0, ys)) < qd) { // Try it out
        y.dlShiftTo(j, t);
        r.subTo(t, r);
        while (r[i] < --qd) r.subTo(t, r);
      }
    }
    if (q != null) {
      r.drShiftTo(ys, q);
      if (ts != ms) this.ZERO().subTo(q, q);
    }
    r.t = ys;
    r.clamp();
    if (nsh > 0) r.rShiftTo(nsh, r); // Denormalize remainder
    if (ts < 0) this.ZERO().subTo(r, r);
  }

  bnMod(a) {
    const r = this.nbi();
    this.abs().divRemTo(a, null, r);
    if (this.s < 0 && r.compareTo(this.ZERO()) > 0) a.subTo(r, r);
    return r;
  }
  bnpInvDigit() {
    if (this.t < 1) return 0;
    const x = this[0];
    if ((x & 1) == 0) return 0;
    let y = x & 3; // y == 1/x mod 2^2
    y = (y * (2 - (x & 0xf) * y)) & 0xf; // y == 1/x mod 2^4
    y = (y * (2 - (x & 0xff) * y)) & 0xff; // y == 1/x mod 2^8
    y = (y * (2 - (((x & 0xffff) * y) & 0xffff))) & 0xffff; // y == 1/x mod 2^16
    y = (y * (2 - x * y % this.DV)) % this.DV; // y == 1/x mod 2^dbits
    return (y > 0) ? this.DV - y : -y;
  }
  bnpIsEven() { return ((this.t > 0) ? (this[0] & 1) : this.s) == 0; }

  bnpExp(e, z) {
    if (e > 0xffffffff || e < 1) return this.ONE();
    let r = this.nbi(); let r2 = this.nbi(); const g = z.convert(this); let i = this.nbits(e) - 1;
    g.copyTo(r);
    while (--i >= 0) {
      z.sqrTo(r, r2);
      if ((e & (1 << i)) > 0) z.mulTo(r2, g, r);
      else { const t = r; r = r2; r2 = t; }
    }
    return z.revert(r);
  }

  bnModPowInt(e, m) {
    let z;
    if (e < 256 || m.isEven()) z = new Classic(m); else z = new Montgomery(m);
    return this.exp(e, z);
  }

  // (public)
  bnClone() { const r = this.nbi(); this.copyTo(r); return r; }

  // (public) return value as integer
  bnIntValue() {
    if (this.s < 0) {
      if (this.t == 1) return this[0] - this.DV;
      else if (this.t == 0) return -1;
    } else if (this.t == 1) return this[0];
    else if (this.t == 0) return 0;
    // assumes 16 < DB < 32
    return ((this[1] & ((1 << (32 - this.DB)) - 1)) << this.DB) | this[0];
  }

  // (public) return value as byte
  bnByteValue() { return (this.t == 0) ? this.s : (this[0] << 24) >> 24; }

  // (public) return value as short (assumes DB>=16)
  bnShortValue() { return (this.t == 0) ? this.s : (this[0] << 16) >> 16; }

  // (protected) return x s.t. r^x < DV
  bnpChunkSize(r) { return Math.floor(Math.LN2 * this.DB / Math.log(r)); }

  // (public) 0 if this == 0, 1 if this > 0
  bnSigNum() {
    if (this.s < 0) return -1;
    else if (this.t <= 0 || (this.t == 1 && this[0] <= 0)) return 0;
    else return 1;
  }

  // (protected) convert to radix string
  bnpToRadix(b) {
    if (b == null) b = 10;
    if (this.signum() == 0 || b < 2 || b > 36) return '0';
    const cs = this.chunkSize(b);
    const a = Math.pow(b, cs);
    const d = this.nbv(a); const y = this.nbi(); const z = this.nbi(); let r = '';
    this.divRemTo(d, y, z);
    while (y.signum() > 0) {
      r = (a + z.intValue()).toString(b).substr(1) + r;
      y.divRemTo(d, y, z);
    }
    return z.intValue().toString(b) + r;
  }

  // (protected) convert from radix string
  bnpFromRadix(s, b) {
    this.fromInt(0);
    if (b == null) b = 10;
    const cs = this.chunkSize(b);
    const d = Math.pow(b, cs); let mi = false; let j = 0; let w = 0;
    for (let i = 0; i < s.length; ++i) {
      const x = this.intAt(s, i);
      if (x < 0) {
        if (s.charAt(i) == '-' && this.signum() == 0) mi = true;
        continue;
      }
      w = b * w + x;
      if (++j >= cs) {
        this.dMultiply(d);
        this.dAddOffset(w, 0);
        j = 0;
        w = 0;
      }
    }
    if (j > 0) {
      this.dMultiply(Math.pow(b, j));
      this.dAddOffset(w, 0);
    }
    if (mi) this.ZERO().subTo(this, this);
  }

  bnpFromNumber(a, b, c) {
    if (typeof b == 'number') {
      // new BigInteger(int,int,RNG)
      if (a < 2) this.fromInt(1);
      else {
        this.fromNumber(a, c);
        if (!this.testBit(a - 1)) { this.bitwiseTo(this.ONE().shiftLeft(a - 1), this.op_or, this); }
        if (this.isEven()) this.dAddOffset(1, 0); // force odd
        while (!this.isProbablePrime(b)) {
          this.dAddOffset(2, 0);
          if (this.bitLength() > a) this.subTo(this.ONE().shiftLeft(a - 1), this);
        }
      }
    } else {
      // new BigInteger(int,RNG)
      const x = []; const t = a & 7;
      x.length = (a >> 3) + 1;
      b.nextBytes(x);
      if (t > 0) x[0] &= ((1 << t) - 1); else x[0] = 0;
      this.fromString(x, 256);
    }
  }

  // (public) convert to bigendian byte array
  bnToByteArray() {
    let i = this.t; const r = [];
    r[0] = this.s;
    let p = this.DB - (i * this.DB) % 8; let d; let k = 0;
    if (i-- > 0) {
      if (p < this.DB && (d = this[i] >> p) != (this.s & this.DM) >> p) { r[k++] = d | (this.s << (this.DB - p)); }
      while (i >= 0) {
        if (p < 8) {
          d = (this[i] & ((1 << p) - 1)) << (8 - p);
          d |= this[--i] >> (p += this.DB - 8);
        } else {
          d = (this[i] >> (p -= 8)) & 0xff;
          if (p <= 0) { p += this.DB; --i; }
        }
        if ((d & 0x80) != 0) d |= -256;
        if (k == 0 && (this.s & 0x80) != (d & 0x80)) ++k;
        if (k > 0 || d != this.s) r[k++] = d;
      }
    }
    return r;
  }

  bnEquals(a) { return (this.compareTo(a) == 0); }
  bnMin(a) { return (this.compareTo(a) < 0) ? this : a; }
  bnMax(a) { return (this.compareTo(a) > 0) ? this : a; }

  // (protected) r = this op a (bitwise)
  bnpBitwiseTo(a, op, r) {
    let i; let f; const m = Math.min(a.t, this.t);
    for (i = 0; i < m; ++i) r[i] = op(this[i], a[i]);
    if (a.t < this.t) {
      f = a.s & this.DM;
      for (i = m; i < this.t; ++i) r[i] = op(this[i], f);
      r.t = this.t;
    } else {
      f = this.s & this.DM;
      for (i = m; i < a.t; ++i) r[i] = op(f, a[i]);
      r.t = a.t;
    }
    r.s = op(this.s, a.s);
    r.clamp();
  }

  // (public) this & a
  op_and(x, y) { return x & y; }
  bnAnd(a) { const r = this.nbi(); this.bitwiseTo(a, this.op_and, r); return r; }

  // (public) this | a
  op_or(x, y) { return x | y; }
  bnOr(a) { const r = this.nbi(); this.bitwiseTo(a, this.op_or, r); return r; }

  // (public) this ^ a
  op_xor(x, y) { return x ^ y; }
  bnXor(a) { const r = this.nbi(); this.bitwiseTo(a, this.op_xor, r); return r; }

  // (public) this & ~a
  op_andnot(x, y) { return x & ~y; }
  bnAndNot(a) { const r = this.nbi(); this.bitwiseTo(a, this.op_andnot, r); return r; }

  // (public) ~this
  bnNot() {
    const r = this.nbi();
    for (let i = 0; i < this.t; ++i) r[i] = this.DM & ~this[i];
    r.t = this.t;
    r.s = ~this.s;
    return r;
  }

  // (public) this << n
  bnShiftLeft(n) {
    const r = this.nbi();
    if (n < 0) this.rShiftTo(-n, r); else this.lShiftTo(n, r);
    return r;
  }

  // (public) this >> n
  bnShiftRight(n) {
    const r = this.nbi();
    if (n < 0) this.lShiftTo(-n, r); else this.rShiftTo(n, r);
    return r;
  }

  // return index of lowest 1-bit in x, x < 2^31
  lbit(x) {
    if (x == 0) return -1;
    let r = 0;
    if ((x & 0xffff) == 0) { x >>= 16; r += 16; }
    if ((x & 0xff) == 0) { x >>= 8; r += 8; }
    if ((x & 0xf) == 0) { x >>= 4; r += 4; }
    if ((x & 3) == 0) { x >>= 2; r += 2; }
    if ((x & 1) == 0) ++r;
    return r;
  }

  // (public) returns index of lowest 1-bit (or -1 if none)
  bnGetLowestSetBit() {
    for (let i = 0; i < this.t; ++i) { if (this[i] != 0) return i * this.DB + this.lbit(this[i]); }
    if (this.s < 0) return this.t * this.DB;
    return -1;
  }

  // return number of 1 bits in x
  cbit(x) {
    let r = 0;
    while (x != 0) { x &= x - 1; ++r; }
    return r;
  }

  // (public) return number of set bits
  bnBitCount() {
    let r = 0; const x = this.s & this.DM;
    for (let i = 0; i < this.t; ++i) r += this.cbit(this[i] ^ x);
    return r;
  }

  // (public) true iff nth bit is set
  bnTestBit(n) {
    const j = Math.floor(n / this.DB);
    if (j >= this.t) return (this.s != 0);
    return ((this[j] & (1 << (n % this.DB))) != 0);
  }

  // (protected) this op (1<<n)
  bnpChangeBit(n, op) {
    const r = this.ONE().shiftLeft(n);
    this.bitwiseTo(r, op, r);
    return r;
  }

  // (public) this | (1<<n)
  bnSetBit(n) { return this.changeBit(n, this.op_or); }

  // (public) this & ~(1<<n)
  bnClearBit(n) { return this.changeBit(n, this.op_andnot); }

  // (public) this ^ (1<<n)
  bnFlipBit(n) { return this.changeBit(n, this.op_xor); }

  // (protected) r = this + a
  bnpAddTo(a, r) {
    let i = 0; let c = 0; const m = Math.min(a.t, this.t);
    while (i < m) {
      c += this[i] + a[i];
      r[i++] = c & this.DM;
      c >>= this.DB;
    }
    if (a.t < this.t) {
      c += a.s;
      while (i < this.t) {
        c += this[i];
        r[i++] = c & this.DM;
        c >>= this.DB;
      }
      c += this.s;
    } else {
      c += this.s;
      while (i < a.t) {
        c += a[i];
        r[i++] = c & this.DM;
        c >>= this.DB;
      }
      c += a.s;
    }
    r.s = (c < 0) ? -1 : 0;
    if (c > 0) r[i++] = c;
    else if (c < -1) r[i++] = this.DV + c;
    r.t = i;
    r.clamp();
  }

  // (public) this + a
  bnAdd(a) { const r = this.nbi(); this.addTo(a, r); return r; }

  // (public) this - a
  bnSubtract(a) { const r = this.nbi(); this.subTo(a, r); return r; }

  // (public) this * a
  bnMultiply(a) { const r = this.nbi(); this.multiplyTo(a, r); return r; }

  // (public) this^2
  bnSquare() { const r = this.nbi(); this.squareTo(r); return r; }

  // (public) this / a
  bnDivide(a) { const r = this.nbi(); this.divRemTo(a, r, null); return r; }

  // (public) this % a
  bnRemainder(a) { const r = this.nbi(); this.divRemTo(a, null, r); return r; }

  // (public) [this/a,this%a]
  bnDivideAndRemainder(a) {
    const q = this.nbi(); const r = this.nbi();
    this.divRemTo(a, q, r);
    return [q, r];
  }

  // (protected) this *= n, this >= 0, 1 < n < DV
  bnpDMultiply(n) {
    this[this.t] = this.am(0, n - 1, this, 0, 0, this.t);
    ++this.t;
    this.clamp();
  }

  // (protected) this += n << w words, this >= 0
  bnpDAddOffset(n, w) {
    if (n == 0) return;
    while (this.t <= w) this[this.t++] = 0;
    this[w] += n;
    while (this[w] >= this.DV) {
      this[w] -= this.DV;
      if (++w >= this.t) this[this.t++] = 0;
      ++this[w];
    }
  }


  // (public) this^e
  bnPow(e) { return this.exp(e, new NullExp()); }

  // (protected) r = lower n words of "this * a", a.t <= n
  // "this" should be the larger one if appropriate.
  bnpMultiplyLowerTo(a, n, r) {
    let i = Math.min(this.t + a.t, n);
    r.s = 0; // assumes a,this >= 0
    r.t = i;
    while (i > 0) r[--i] = 0;
    let j;
    for (j = r.t - this.t; i < j; ++i) r[i + this.t] = this.am(0, a[i], r, i, 0, this.t);
    for (j = Math.min(a.t, n); i < j; ++i) this.am(0, a[i], r, i, 0, n - i);
    r.clamp();
  }

  // (protected) r = "this * a" without lower n words, n > 0
  // "this" should be the larger one if appropriate.
  bnpMultiplyUpperTo(a, n, r) {
    --n;
    let i = r.t = this.t + a.t - n;
    r.s = 0; // assumes a,this >= 0
    while (--i >= 0) r[i] = 0;
    for (i = Math.max(n - this.t, 0); i < a.t; ++i) { r[this.t + i - n] = this.am(n - i, a[i], r, 0, 0, this.t + i - n); }
    r.clamp();
    r.drShiftTo(1, r);
  }


  // (public) this^e % m (HAC 14.85)
  bnModPow(e, m) {
    let i = e.bitLength(); let k; let r = this.nbv(1); let z;
    if (i <= 0) return r;
    else if (i < 18) k = 1;
    else if (i < 48) k = 3;
    else if (i < 144) k = 4;
    else if (i < 768) k = 5;
    else k = 6;
    if (i < 8) { z = new Classic(m); } else if (m.isEven()) { z = new Barrett(m); } else { z = new Montgomery(m); }

    // precomputation
    const g = []; let n = 3; const k1 = k - 1; const km = (1 << k) - 1;
    g[1] = z.convert(this);
    if (k > 1) {
      const g2 = this.nbi();
      z.sqrTo(g[1], g2);
      while (n <= km) {
        g[n] = this.nbi();
        z.mulTo(g2, g[n - 2], g[n]);
        n += 2;
      }
    }

    let j = e.t - 1; let w; let is1 = true; let r2 = this.nbi(); let t;
    i = this.nbits(e[j]) - 1;
    while (j >= 0) {
      if (i >= k1) w = (e[j] >> (i - k1)) & km;
      else {
        w = (e[j] & ((1 << (i + 1)) - 1)) << (k1 - i);
        if (j > 0) w |= e[j - 1] >> (this.DB + i - k1);
      }

      n = k;
      while ((w & 1) == 0) { w >>= 1; --n; }
      if ((i -= n) < 0) { i += this.DB; --j; }
      if (is1) { // ret == 1, don't bother squaring or multiplying it
        g[w].copyTo(r);
        is1 = false;
      } else {
        while (n > 1) { z.sqrTo(r, r2); z.sqrTo(r2, r); n -= 2; }
        if (n > 0) z.sqrTo(r, r2); else { t = r; r = r2; r2 = t; }
        z.mulTo(r2, g[w], r);
      }

      while (j >= 0 && (e[j] & (1 << i)) == 0) {
        z.sqrTo(r, r2); t = r; r = r2; r2 = t;
        if (--i < 0) { i = this.DB - 1; --j; }
      }
    }
    return z.revert(r);
  }

  // (public) gcd(this,a) (HAC 14.54)
  bnGCD(a) {
    let x = (this.s < 0) ? this.negate() : this.clone();
    let y = (a.s < 0) ? a.negate() : a.clone();
    if (x.compareTo(y) < 0) { const t = x; x = y; y = t; }
    let i = x.getLowestSetBit(); let g = y.getLowestSetBit();
    if (g < 0) return x;
    if (i < g) g = i;
    if (g > 0) {
      x.rShiftTo(g, x);
      y.rShiftTo(g, y);
    }
    while (x.signum() > 0) {
      if ((i = x.getLowestSetBit()) > 0) x.rShiftTo(i, x);
      if ((i = y.getLowestSetBit()) > 0) y.rShiftTo(i, y);
      if (x.compareTo(y) >= 0) {
        x.subTo(y, x);
        x.rShiftTo(1, x);
      } else {
        y.subTo(x, y);
        y.rShiftTo(1, y);
      }
    }
    if (g > 0) y.lShiftTo(g, y);
    return y;
  }

  // (protected) this % n, n < 2^26
  bnpModInt(n) {
    if (n <= 0) return 0;
    const d = this.DV % n; let r = (this.s < 0) ? n - 1 : 0;
    if (this.t > 0) {
      if (d == 0) r = this[0] % n;
      else for (let i = this.t - 1; i >= 0; --i) r = (d * r + this[i]) % n;
    }
    return r;
  }

  // (public) 1/this % m (HAC 14.61)
  bnModInverse(m) {
    const ac = m.isEven();
    if ((this.isEven() && ac) || m.signum() == 0) return this.ZERO();
    const u = m.clone(); const v = this.clone();
    const a = this.nbv(1); const b = this.nbv(0); const c = this.nbv(0); const d = this.nbv(1);
    while (u.signum() != 0) {
      while (u.isEven()) {
        u.rShiftTo(1, u);
        if (ac) {
          if (!a.isEven() || !b.isEven()) { a.addTo(this, a); b.subTo(m, b); }
          a.rShiftTo(1, a);
        } else if (!b.isEven()) b.subTo(m, b);
        b.rShiftTo(1, b);
      }
      while (v.isEven()) {
        v.rShiftTo(1, v);
        if (ac) {
          if (!c.isEven() || !d.isEven()) { c.addTo(this, c); d.subTo(m, d); }
          c.rShiftTo(1, c);
        } else if (!d.isEven()) d.subTo(m, d);
        d.rShiftTo(1, d);
      }
      if (u.compareTo(v) >= 0) {
        u.subTo(v, u);
        if (ac) a.subTo(c, a);
        b.subTo(d, b);
      } else {
        v.subTo(u, v);
        if (ac) c.subTo(a, c);
        d.subTo(b, d);
      }
    }
    if (v.compareTo(this.ONE()) != 0) return this.ZERO();
    if (d.compareTo(m) >= 0) return d.subtract(m);
    if (d.signum() < 0) d.addTo(m, d); else return d;
    if (d.signum() < 0) return d.add(m); else return d;
  }


  // (public) test primality with certainty >= 1-.5^t
  bnIsProbablePrime(t) {
    let i; const x = this.abs();
    if (x.t == 1 && x[0] <= this.lowprimes[this.lowprimes.length - 1]) {
      for (i = 0; i < this.lowprimes.length; ++i) { if (x[0] == this.lowprimes[i]) return true; }
      return false;
    }
    if (x.isEven()) return false;
    i = 1;
    while (i < this.lowprimes.length) {
      let m = this.lowprimes[i]; let j = i + 1;
      while (j < this.lowprimes.length && m < this.lplim) m *= this.lowprimes[j++];
      m = x.modInt(m);
      while (i < j) if (m % this.lowprimes[i++] == 0) return false;
    }
    return x.millerRabin(t);
  }

  // (protected) true if probably prime (HAC 4.24, Miller-Rabin)
  bnpMillerRabin(t) {
    const n1 = this.subtract(this.ONE());
    const k = n1.getLowestSetBit();
    if (k <= 0) return false;
    const r = n1.shiftRight(k);
    t = (t + 1) >> 1;
    if (t > this.lowprimes.length) t = this.lowprimes.length;
    const a = this.nbi();
    for (let i = 0; i < t; ++i) {
      // Pick bases at random, instead of starting at 2
      a.fromInt(this.lowprimes[Math.floor(Math.random() * this.lowprimes.length)]);
      let y = a.modPow(r, this);
      if (y.compareTo(this.ONE()) != 0 && y.compareTo(n1) != 0) {
        let j = 1;
        while (j++ < k && y.compareTo(n1) != 0) {
          y = y.modPowInt(2, this);
          if (y.compareTo(this.ONE()) == 0) return false;
        }
        if (y.compareTo(n1) != 0) return false;
      }
    }
    return true;
  }
}

// ==================================================

class Arcfour {
  constructor() {
    this.i = 0;
    this.j = 0;
    this.S = [];
    this.init = this.ARC4init;
    this.next = this.ARC4next;
  }
  // Initialize arcfour context from key, an array of ints, each from [0..255]
  ARC4init(key) {
    let i, j, t;
    for (i = 0; i < 256; ++i) { this.S[i] = i; }
    j = 0;
    for (i = 0; i < 256; ++i) {
      j = (j + this.S[i] + key[i % key.length]) & 255;
      t = this.S[i];
      this.S[i] = this.S[j];
      this.S[j] = t;
    }
    this.i = 0;
    this.j = 0;
  }

  ARC4next() {
    this.i = (this.i + 1) & 255;
    this.j = (this.j + this.S[this.i]) & 255;
    const t = this.S[this.i];
    this.S[this.i] = this.S[this.j];
    this.S[this.j] = t;
    return this.S[(t + this.S[this.i]) & 255];
  }
}


export class SecureRandom {
  constructor() {
    this.nextBytes = this.rng_get_bytes;
    this.rng_state = null;
    this.rng_pool = null;
    this.rng_pptr = null;
    // Initialize the pool with junk if needed.
    if (this.rng_pool == null) {
      this.rng_pool = [];
      this.rng_pptr = 0;
      let t;
      if (typeof window !== 'undefined' && window.crypto) {
        if (window.crypto.getRandomValues) {
          // Use webcrypto if available
          const ua = new Uint8Array(32);
          window.crypto.getRandomValues(ua);
          for (t = 0; t < 32; ++t) { this.rng_pool[this.rng_pptr++] = ua[t]; }
        } else if (navigator.appName == 'Netscape' && navigator.appVersion < '5') {
          // Extract entropy (256 bits) from NS4 RNG if available
          const z = window.crypto.random(32);
          for (t = 0; t < z.length; ++t) { this.rng_pool[this.rng_pptr++] = z.charCodeAt(t) & 255; }
        }
      }
      while (this.rng_pptr < this.rng_psize) {
        t = Math.floor(65536 * Math.random());
        this.rng_pool[this.rng_pptr++] = t >>> 8;
        this.rng_pool[this.rng_pptr++] = t & 255;
      }
      this.rng_pptr = 0;
      this.rng_seed_time();
    }
  }
  // Mix in a 32-bit integer into the pool
  rng_seed_int(x) {
    this.rng_pool[this.rng_pptr++] ^= x & 255;
    this.rng_pool[this.rng_pptr++] ^= (x >> 8) & 255;
    this.rng_pool[this.rng_pptr++] ^= (x >> 16) & 255;
    this.rng_pool[this.rng_pptr++] ^= (x >> 24) & 255;
    if (this.rng_pptr >= this.rng_psize) this.rng_pptr -= this.rng_psize;
  }

  // Mix in the current time (w/milliseconds) into the pool
  rng_seed_time() {
    this.rng_seed_int(new Date().getTime());
  }
  prng_newstate() {
    return new Arcfour();
  }

  rng_get_byte() {
    if (this.rng_state == null) {
      this.rng_seed_time();
      this.rng_state = this.prng_newstate();
      this.rng_state.init(this.rng_pool);
      for (this.rng_pptr = 0; this.rng_pptr < this.rng_pool.length; ++this.rng_pptr) { this.rng_pool[this.rng_pptr] = 0; }
      this.rng_pptr = 0;
    }
    return this.rng_state.next();
  }

  rng_get_bytes(ba) {
    let i;
    for (i = 0; i < ba.length; ++i) ba[i] = this.rng_get_byte();
  }
}


// A "null" reducer
class NullExp {
  constructor() {
    this.convert = this.nNop
    this.revert = this.nNop
    this.mulTo = this.nMulTo
    this.sqrTo = this.nSqrTo
  }
  nNop(x) { return x; }
  nMulTo(x, y, r) { x.multiplyTo(y, r); }
  nSqrTo(x, r) { x.squareTo(r); }
}

// Barrett modular reduction
class Barrett {
  constructor(m) {
    // setup Barrett
    this.r2 = BigInteger.nbi();
    this.q3 = BigInteger.nbi();
    this.ONE().dlShiftTo(2 * m.t, this.r2);
    this.mu = this.r2.divide(m);
    this.m = m;
    this.convert = this.barrettConvert;
    this.revert = this.barrettRevert;
    this.reduce = this.barrettReduce;
    this.mulTo = this.barrettMulTo;
    this.sqrTo = this.barrettSqrTo;
  }
  barrettConvert(x) {
    if (x.s < 0 || x.t > 2 * this.m.t) return x.mod(this.m);
    else if (x.compareTo(this.m) < 0) return x;
    else { const r = BigInteger.nbi(); x.copyTo(r); this.reduce(r); return r; }
  }

  barrettRevert(x) { return x; }

  // x = x mod m (HAC 14.42)
  barrettReduce(x) {
    x.drShiftTo(this.m.t - 1, this.r2);
    if (x.t > this.m.t + 1) { x.t = this.m.t + 1; x.clamp(); }
    this.mu.multiplyUpperTo(this.r2, this.m.t + 1, this.q3);
    this.m.multiplyLowerTo(this.q3, this.m.t + 1, this.r2);
    while (x.compareTo(this.r2) < 0) x.dAddOffset(1, this.m.t + 1);
    x.subTo(this.r2, x);
    while (x.compareTo(this.m) >= 0) x.subTo(this.m, x);
  }

  // r = x^2 mod m; x != r
  barrettSqrTo(x, r) { x.squareTo(r); this.reduce(r); }

  // r = x*y mod m; x,y != r
  barrettMulTo(x, y, r) { x.multiplyTo(y, r); this.reduce(r); }
}

class Classic {
  constructor(m) {
    this.m = m;
    this.convert = this.cConvert;
    this.revert = this.cRevert;
    this.reduce = this.cReduce;
    this.mulTo = this.cMulTo;
    this.sqrTo = this.cSqrTo;
  }
  cConvert(x) {
    if (x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
    else return x;
  }
  cRevert(x) { return x; }
  cReduce(x) { x.divRemTo(this.m, null, x); }
  cMulTo(x, y, r) { x.multiplyTo(y, r); this.reduce(r); }
  cSqrTo(x, r) { x.squareTo(r); this.reduce(r); }
}

class Montgomery {
  constructor(m) {
    this.m = m;
    this.mp = m.invDigit();
    this.mpl = this.mp & 0x7fff;
    this.mph = this.mp >> 15;
    this.um = (1 << (m.DB - 15)) - 1;
    this.mt2 = 2 * m.t;
    this.convert = this.montConvert;
    this.revert = this.montRevert;
    this.reduce = this.montReduce;
    this.mulTo = this.montMulTo;
    this.sqrTo = this.montSqrTo;
  }
  // xR mod m
  montConvert(x) {
    const r = BigInteger.nbi();
    x.abs().dlShiftTo(this.m.t, r);
    r.divRemTo(this.m, null, r);
    if (x.s < 0 && r.compareTo(this.ZERO()) > 0) this.m.subTo(r, r);
    return r;
  }

  // x/R mod m
  montRevert(x) {
    const r = BigInteger.nbi();
    x.copyTo(r);
    this.reduce(r);
    return r;
  }

  // x = x/R mod m (HAC 14.32)
  montReduce(x) {
    while (x.t <= this.mt2) { x[x.t++] = 0; }
    for (let i = 0; i < this.m.t; ++i) {
    // faster way of calculating u0 = x[i]*mp mod DV
      let j = x[i] & 0x7fff;
      const u0 = (j * this.mpl + (((j * this.mph + (x[i] >> 15) * this.mpl) & this.um) << 15)) & x.DM;
      // use am to combine the multiply-shift-add into one call
      j = i + this.m.t;
      x[j] += this.m.am(0, u0, x, i, 0, this.m.t);
      // propagate carry
      while (x[j] >= x.DV) { x[j] -= x.DV; x[++j]++; }
    }
    x.clamp();
    x.drShiftTo(this.m.t, x);
    if (x.compareTo(this.m) >= 0) x.subTo(this.m, x);
  }

  // r = "x^2/R mod m"; x != r
  montSqrTo(x, r) { x.squareTo(r); this.reduce(r); }

  // r = "xy/R mod m"; x,y != r
  montMulTo(x, y, r) { x.multiplyTo(y, r); this.reduce(r); }
}


