package site.aicc.sm9;

import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;
import site.aicc.sm2.util.ConvertUtil;
import site.aicc.sm4.SM4;

/**
 * The SM9 algorithms of GB/T 38635.2 on decoded values, with every random scalar passed in. The
 * facade {@link SM9} draws the scalars and handles encodings; tests call these directly with the
 * scalars of known-answer vectors.
 *
 * <p>Secret scalars only reach {@link G1#mul}, {@link G2#mul}, {@link Pairing#pow} and {@link Fn},
 * which all have a fixed sequence of operations and memory accesses.
 */
final class SM9Core {
  static final int SCALAR_BYTES = 32;
  static final int HASH_BYTES = 32;
  static final int SIGNATURE_BYTES = HASH_BYTES + G1.BYTES;
  static final int MAC_KEY_BYTES = 32;
  static final int SM4_KEY_BYTES = 16;
  static final int CIPHER_OVERHEAD = G1.BYTES + HASH_BYTES;

  private SM9Core() {}

  /**
   * A decoded master public key with its pairing value, cached by its encoding. From the second
   * exponentiation on, powers of the pairing value use a fixed-base table.
   */
  static final class MasterKey {
    final byte[] encoded;
    final int[] point;
    final int[] pairing;
    private final AtomicInteger uses = new AtomicInteger();
    private volatile int[] comb;

    MasterKey(byte[] encoded, int[] point, int[] pairing) {
      this.encoded = encoded;
      this.point = point;
      this.pairing = pairing;
    }

    /** pairing^k in constant time. */
    int[] pow(int[] k) {
      int[] table = comb;
      if (table == null) {
        if (uses.incrementAndGet() < 2) {
          return Pairing.pow(pairing, k);
        }
        table = Pairing.combTable(pairing);
        comb = table;
      }
      return Pairing.powComb(table, k);
    }
  }

  private static volatile MasterKey lastSignMaster;
  private static volatile MasterKey lastEncMaster;

  /** Ppub-s (G2) with g = e(P1, Ppub-s), or null when the bytes are not a G2 point. */
  static MasterKey signMaster(byte[] encoded) {
    MasterKey cached = lastSignMaster;
    if (cached != null && Arrays.equals(cached.encoded, encoded)) {
      return cached;
    }
    int[] point = G2.decode(encoded);
    if (point == null) {
      return null;
    }
    MasterKey key = new MasterKey(encoded.clone(), point, Pairing.pair(G1.P1, point));
    lastSignMaster = key;
    return key;
  }

  /** Ppub-e (G1) with e(Ppub-e, P2), or null when the bytes are not a G1 point. */
  static MasterKey encMaster(byte[] encoded) {
    MasterKey cached = lastEncMaster;
    if (cached != null && Arrays.equals(cached.encoded, encoded)) {
      return cached;
    }
    int[] point = G1.decode(encoded);
    if (point == null) {
      return null;
    }
    MasterKey key = new MasterKey(encoded.clone(), point, Pairing.pair(point, G2.P2));
    lastEncMaster = key;
    return key;
  }

  static byte[] withHid(byte[] id, int hid) {
    byte[] z = Arrays.copyOf(id, id.length + 1);
    z[id.length] = (byte) hid;
    return z;
  }

  /** t2 = ks / (H1(ID || hid) + ks) mod N; error when the denominator is 0. */
  private static int[] userScalar(int[] master, byte[] id, int hid) {
    int[] t1 = Fn.add(SM9Hash.h1(withHid(id, hid)), master);
    if (Fn.isZero(t1) != 0) {
      throw new IllegalArgumentException(
          "Cannot derive a key for this identity; regenerate the master key");
    }
    int[] t2 = Fn.mul(master, Fn.inv(t1));
    Arrays.fill(t1, 0);
    return t2;
  }

  /** ds = [ks / (H1(ID || hid) + ks)] P1. */
  static int[] signUserKey(int[] ks, byte[] id, int hid) {
    int[] t2 = userScalar(ks, id, hid);
    try {
      return G1.mulGenerator(t2);
    } finally {
      Arrays.fill(t2, 0);
    }
  }

  /** de = [ke / (H1(ID || hid) + ke)] P2. */
  static int[] encUserKey(int[] ke, byte[] id, int hid) {
    int[] t2 = userScalar(ke, id, hid);
    try {
      return G2.mulGenerator(t2);
    } finally {
      Arrays.fill(t2, 0);
    }
  }

  /** h || S, or null when l = r - h is 0 (the caller draws a new r). */
  static byte[] sign(byte[] message, int[] ds, MasterKey master, int[] r) {
    int[] w = master.pow(r);
    int[] h = SM9Hash.h2(message, Fp12.encode(w));
    Fp12.wipe(w);
    int[] l = Fn.sub(r, h);
    try {
      if (Fn.isZero(l) != 0) {
        return null;
      }
      byte[] out = new byte[SIGNATURE_BYTES];
      System.arraycopy(Fn.toBytes(h), 0, out, 0, HASH_BYTES);
      System.arraycopy(G1.encode(G1.mul(ds, l)), 0, out, HASH_BYTES, G1.BYTES);
      return out;
    } finally {
      Arrays.fill(l, 0);
    }
  }

  /** Verification on public data; every malformed input gives false. */
  static boolean verify(byte[] message, byte[] signature, byte[] id, int hid, MasterKey master) {
    if (signature.length != SIGNATURE_BYTES) {
      return false;
    }
    int[] h = Fn.fromBytes(signature, 0);
    if (Fn.isValidScalar(h) == 0) {
      return false;
    }
    int[] s = G1.decode(Arrays.copyOfRange(signature, HASH_BYTES, SIGNATURE_BYTES));
    if (s == null) {
      return false;
    }
    int[] t = master.pow(h);
    int[] p = new int[G2.L];
    G2.add(p, G2.mulGenerator(SM9Hash.h1(withHid(id, hid))), master.point);
    int[] u = Pairing.pair(s, p);
    Fp12.mul(u, u, t);
    int[] h2 = SM9Hash.h2(message, Fp12.encode(u));
    return Arrays.equals(Fn.toBytes(h2), Fn.toBytes(h));
  }

  /** Q = [H1(ID || hid)] P1 + Ppub-e, or an error when that is the identity. */
  static int[] peerPoint(byte[] id, int hid, MasterKey master) {
    int[] q = new int[G1.L];
    G1.add(q, G1.mulGenerator(SM9Hash.h1(withHid(id, hid))), master.point);
    if (G1.isInfinity(q)) {
      throw new IllegalArgumentException("Invalid master public key for this identity");
    }
    return q;
  }

  /** {K, C}, or null when K is all zero (the caller draws a new r). */
  static byte[][] encapsulate(byte[] id, int hid, MasterKey master, int klen, int[] r) {
    int[] c = G1.mul(peerPoint(id, hid, master), r);
    int[] w = master.pow(r);
    byte[] wb = Fp12.encode(w);
    Fp12.wipe(w);
    byte[] k = SM9Hash.kdf(klen, G1.xy(c), wb, id);
    Arrays.fill(wb, (byte) 0);
    if (SM9Hash.isAllZero(k, 0, k.length)) {
      return null;
    }
    return new byte[][] {k, G1.encode(c)};
  }

  /** K for a decoded C; error when it is all zero. */
  static byte[] decapsulate(int[] c, byte[] id, int[] de, int klen) {
    int[] w = Pairing.pair(c, de);
    byte[] wb = Fp12.encode(w);
    Fp12.wipe(w);
    byte[] k = SM9Hash.kdf(klen, G1.xy(c), wb, id);
    Arrays.fill(wb, (byte) 0);
    if (SM9Hash.isAllZero(k, 0, k.length)) {
      throw new IllegalArgumentException("Decapsulation failed");
    }
    return k;
  }

  /** C1 || C3 || C2, or null when K1 is all zero (the caller draws a new r). */
  static byte[] encrypt(
      byte[] message, byte[] id, int hid, MasterKey master, int[] r, boolean sm4) {
    int[] c1 = G1.mul(peerPoint(id, hid, master), r);
    int[] w = master.pow(r);
    byte[] wb = Fp12.encode(w);
    Fp12.wipe(w);
    int k1Len = sm4 ? SM4_KEY_BYTES : message.length;
    byte[] k = SM9Hash.kdf(k1Len + MAC_KEY_BYTES, G1.xy(c1), wb, id);
    Arrays.fill(wb, (byte) 0);
    try {
      if (SM9Hash.isAllZero(k, 0, k1Len)) {
        return null;
      }
      byte[] c2;
      if (sm4) {
        c2 = SM4.ecbEncrypt(Arrays.copyOf(k, SM4_KEY_BYTES), message);
      } else {
        c2 = new byte[message.length];
        for (int i = 0; i < c2.length; i++) {
          c2[i] = (byte) (message[i] ^ k[i]);
        }
      }
      byte[] c3 = SM9Hash.sm3(c2, Arrays.copyOfRange(k, k1Len, k.length));
      byte[] out = new byte[CIPHER_OVERHEAD + c2.length];
      System.arraycopy(G1.encode(c1), 0, out, 0, G1.BYTES);
      System.arraycopy(c3, 0, out, G1.BYTES, HASH_BYTES);
      System.arraycopy(c2, 0, out, CIPHER_OVERHEAD, c2.length);
      return out;
    } finally {
      Arrays.fill(k, (byte) 0);
    }
  }

  /**
   * Decrypts C1 || C3 || C2. The MAC is compared in constant time before any decryption or
   * unpadding, and every failure raises the same exception.
   */
  static byte[] decrypt(byte[] cipher, byte[] id, int[] de, boolean sm4) {
    int c2Len = cipher.length - CIPHER_OVERHEAD;
    if (c2Len < 1 || (sm4 && c2Len % 16 != 0)) {
      throw failure();
    }
    int[] c1 = G1.decode(Arrays.copyOf(cipher, G1.BYTES));
    if (c1 == null) {
      throw failure();
    }
    int[] w = Pairing.pair(c1, de);
    byte[] wb = Fp12.encode(w);
    Fp12.wipe(w);
    int k1Len = sm4 ? SM4_KEY_BYTES : c2Len;
    byte[] k = SM9Hash.kdf(k1Len + MAC_KEY_BYTES, G1.xy(c1), wb, id);
    Arrays.fill(wb, (byte) 0);
    try {
      byte[] c2 = Arrays.copyOfRange(cipher, CIPHER_OVERHEAD, cipher.length);
      byte[] mac = SM9Hash.sm3(c2, Arrays.copyOfRange(k, k1Len, k.length));
      boolean macOk =
          ConvertUtil.byteArrayEqual(mac, Arrays.copyOfRange(cipher, G1.BYTES, CIPHER_OVERHEAD));
      if (!macOk | SM9Hash.isAllZero(k, 0, k1Len)) {
        throw failure();
      }
      if (sm4) {
        try {
          return SM4.ecbDecrypt(Arrays.copyOf(k, SM4_KEY_BYTES), c2);
        } catch (IllegalArgumentException e) {
          throw failure();
        }
      }
      byte[] m = new byte[c2Len];
      for (int i = 0; i < c2Len; i++) {
        m[i] = (byte) (c2[i] ^ k[i]);
      }
      return m;
    } finally {
      Arrays.fill(k, (byte) 0);
    }
  }

  static IllegalArgumentException failure() {
    return new IllegalArgumentException("Decryption failed");
  }

  /** R = [r] Q_peer for the key exchange. */
  static byte[] exchangeInit(byte[] peerId, int hid, MasterKey master, int[] r) {
    return G1.encode(G1.mul(peerPoint(peerId, hid, master), r));
  }

  /** The three GT values of one side, encoded, in the standard's order g1, g2, g3. */
  static byte[][] exchangeValues(
      boolean responder, MasterKey master, int[] de, int[] r, int[] peerR) {
    int[] paired = Pairing.pair(peerR, de);
    int[] own = master.pow(r);
    int[] shared = Pairing.pow(paired, r);
    byte[][] g =
        responder
            ? new byte[][] {Fp12.encode(paired), Fp12.encode(own), Fp12.encode(shared)}
            : new byte[][] {Fp12.encode(own), Fp12.encode(paired), Fp12.encode(shared)};
    Fp12.wipe(paired);
    Fp12.wipe(own);
    Fp12.wipe(shared);
    return g;
  }

  /** {SK, S_82, S_83} from g1, g2, g3 and the public transcript. */
  static byte[][] exchangeOutputs(
      int klen, byte[] idA, byte[] idB, byte[] raXy, byte[] rbXy, byte[][] g) {
    byte[] sk = SM9Hash.kdf(klen, idA, idB, raXy, rbXy, g[0], g[1], g[2]);
    byte[] inner = SM9Hash.sm3(g[1], g[2], idA, idB, raXy, rbXy);
    byte[] s82 = SM9Hash.sm3(new byte[] {(byte) 0x82}, g[0], inner);
    byte[] s83 = SM9Hash.sm3(new byte[] {(byte) 0x83}, g[0], inner);
    for (byte[] v : g) {
      Arrays.fill(v, (byte) 0);
    }
    return new byte[][] {sk, s82, s83};
  }
}
