using System.Security.Cryptography;
using System.Text;

namespace SMX;

public class SM2KeySwapParams
{
    public string Sa { get; set; } = "";
    public string Sb { get; set; } = "";
    public string Ka { get; set; } = "";
    public string Kb { get; set; } = "";
    public ECPoint V { get; set; }
    public byte[] Za { get; set; } = [];
    public byte[] Zb { get; set; } = [];
    public bool Success { get; set; }
    public string Message { get; set; } = "";
}

public static class SM2
{
    public static (string privateKey, string publicKey) GenKeyPair()
    {
        while (true)
        {
            var pri = RandomBigInt();
            if (pri.IsZero || pri.Compare(ECPoint.SM2_N) >= 0) continue;
            var pub = ECPoint.Generator().Multiply(pri);
            var priHex = pri.ToHex();
            var pubHex = pub.ToHexEncoded();
            if (priHex.Length == 64 && pubHex.Length == 130)
                return (priHex, pubHex);
        }
    }

    public static string Encrypt(string plaintext, string publicKey)
    {
        var message = Encoding.UTF8.GetBytes(plaintext);
        if (message.Length == 0)
            throw new ArgumentException("plaintext cannot be empty");

        var pubPoint = ECPoint.FromHexEncoded(publicKey);
        if (!pubPoint.IsOnCurve())
            throw new ArgumentException("invalid public key");

        while (true)
        {
            var k = RandomBigInt();
            if (k.IsZero || k.Compare(ECPoint.SM2_N) >= 0) continue;

            var c1 = ECPoint.Generator().Multiply(k);
            var p2 = pubPoint.Multiply(k);
            if (p2.Infinity) continue;

            var key = Kdf(message.Length, p2);
            bool allZero = true;
            foreach (var b in key)
                if (b != 0) { allZero = false; break; }
            if (allZero) continue;

            var c2 = new byte[message.Length];
            for (int i = 0; i < message.Length; i++)
                c2[i] = (byte)(message[i] ^ key[i]);

            var sm3 = new SM3();
            sm3.Update(p2.X.ToBEBytes());
            sm3.Update(message);
            sm3.Update(p2.Y.ToBEBytes());
            sm3.Finish();
            var c3 = sm3.HashBytes();

            return c1.ToHexEncoded() + HexUtils.BytesToHex(c3) + HexUtils.BytesToHex(c2);
        }
    }

    public static string Decrypt(string ciphertext, string privateKey)
    {
        if (ciphertext.Length < 130 + 64)
            throw new ArgumentException("ciphertext too short");

        var c1Hex = ciphertext[..130];
        var c3Hex = ciphertext[130..194];
        var c2Hex = ciphertext[194..];

        var c1 = ECPoint.FromHexEncoded(c1Hex);
        if (!c1.IsOnCurve())
            throw new ArgumentException("invalid C1 point");

        var c3 = HexUtils.HexToBytes(c3Hex);
        var c2 = HexUtils.HexToBytes(c2Hex);

        var d = BigInt256.FromHex(privateKey);
        var p2 = c1.Multiply(d);
        if (p2.Infinity)
            throw new InvalidOperationException("invalid decryption");

        var key = Kdf(c2.Length, p2);
        for (int i = 0; i < c2.Length; i++)
            c2[i] ^= key[i];

        var sm3 = new SM3();
        sm3.Update(p2.X.ToBEBytes());
        sm3.Update(c2);
        sm3.Update(p2.Y.ToBEBytes());
        sm3.Finish();
        var computedC3 = sm3.HashBytes();

        if (!BytesEqual(computedC3, c3))
            throw new InvalidOperationException("decryption verification failed");

        return Encoding.UTF8.GetString(c2);
    }

    public static string Sign(string userID, string message, string privateKey)
    {
        var d = BigInt256.FromHex(privateKey);
        var publicKey = ECPoint.Generator().Multiply(d);

        var z = UserSM3Z(Encoding.UTF8.GetBytes(userID), publicKey);

        var sm3 = new SM3();
        sm3.Update(z);
        sm3.Update(Encoding.UTF8.GetBytes(message));
        sm3.Finish();
        var eBytes = sm3.HashBytes();
        var e = BigInt256.FromBEBytes(eBytes);

        while (true)
        {
            var k = RandomBigInt();
            if (k.IsZero || k.Compare(ECPoint.SM2_N) >= 0) continue;

            var kp = ECPoint.Generator().Multiply(k);
            var x1 = kp.X.ToBigInt();

            var r = e.ModAdd(x1, ECPoint.SM2_N);
            if (r.IsZero) continue;

            var rk = r.Add(k, out _);
            if (rk == ECPoint.SM2_N) continue;

            var dPlus1 = d.Add(BigInt256.One, out _);
            var dPlus1Inv = dPlus1.ModInverse(ECPoint.SM2_N);
            var rd = r.ModMul(d, ECPoint.SM2_N);
            var kMinusRD = k.ModSub(rd, ECPoint.SM2_N);
            var s = kMinusRD.ModMul(dPlus1Inv, ECPoint.SM2_N);

            if (s.IsZero) continue;

            var rHex = r.ToHex();
            var sHex = s.ToHex();
            if (rHex.Length == 64 && sHex.Length == 64)
                return rHex.ToLower() + "h" + sHex.ToLower();
        }
    }

    public static bool Verify(string userID, string signature, string message, string publicKey)
    {
        var parts = signature.Split('h');
        if (parts.Length != 2) return false;

        var r = BigInt256.FromHex(parts[0]);
        var s = BigInt256.FromHex(parts[1]);

        if (r.IsZero || r.Compare(ECPoint.SM2_N) >= 0) return false;
        if (s.IsZero || s.Compare(ECPoint.SM2_N) >= 0) return false;

        var pubPoint = ECPoint.FromHexEncoded(publicKey);
        if (!pubPoint.IsOnCurve()) return false;

        var z = UserSM3Z(Encoding.UTF8.GetBytes(userID), pubPoint);

        var sm3 = new SM3();
        sm3.Update(z);
        sm3.Update(Encoding.UTF8.GetBytes(message));
        sm3.Finish();
        var eBytes = sm3.HashBytes();
        var e = BigInt256.FromBEBytes(eBytes);

        var t = r.ModAdd(s, ECPoint.SM2_N);
        if (t.IsZero) return false;

        var sg = ECPoint.Generator().Multiply(s);
        var tpa = pubPoint.Multiply(t);
        var point = sg.Add(tpa);

        if (point.Infinity) return false;

        var px = point.X.ToBigInt();
        var computedR = e.ModAdd(px, ECPoint.SM2_N);
        return r == computedR;
    }

    public static SM2KeySwapParams GetSb(int byteLen, ECPoint pA, ECPoint rA, ECPoint pB,
        BigInt256 dB, ECPoint rB, BigInt256 rb, string idA, string idB)
    {
        var result = new SM2KeySwapParams();

        var x2_ = CalcX(rB.X.ToBigInt());
        var tb = CalcT(ECPoint.SM2_N, rb, dB, x2_);

        if (!rA.IsOnCurve())
        {
            result.Message = "RA point is not on curve";
            return result;
        }

        var x1_ = CalcX(rA.X.ToBigInt());
        var v = CalcPoint(tb, x1_, pA, rA);
        if (v.Infinity)
        {
            result.Message = "V is point at infinity";
            return result;
        }

        var za = UserSM3Z(Encoding.UTF8.GetBytes(idA), pA);
        var zb = UserSM3Z(Encoding.UTF8.GetBytes(idB), pB);

        var kb = KdfKeySwap(byteLen, v, za, zb);
        var sb = CreateS(0x02, v, za, zb, rA, rB);

        result.Sb = HexUtils.BytesToHex(sb);
        result.Kb = HexUtils.BytesToHex(kb);
        result.V = v;
        result.Za = za;
        result.Zb = zb;
        result.Success = true;
        return result;
    }

    public static SM2KeySwapParams GetSa(int byteLen, ECPoint pB, ECPoint rB, ECPoint pA,
        BigInt256 dA, ECPoint rA, BigInt256 ra, string idA, string idB, byte[] sb)
    {
        var result = new SM2KeySwapParams();

        var x1_ = CalcX(rA.X.ToBigInt());
        var ta = CalcT(ECPoint.SM2_N, ra, dA, x1_);

        if (!rB.IsOnCurve())
        {
            result.Message = "RB point is not on curve";
            return result;
        }

        var x2_ = CalcX(rB.X.ToBigInt());
        var u = CalcPoint(ta, x2_, pB, rB);
        if (u.Infinity)
        {
            result.Message = "U is point at infinity";
            return result;
        }

        var za = UserSM3Z(Encoding.UTF8.GetBytes(idA), pA);
        var zb = UserSM3Z(Encoding.UTF8.GetBytes(idB), pB);

        var ka = KdfKeySwap(byteLen, u, za, zb);
        var s1 = CreateS(0x02, u, za, zb, rA, rB);

        if (!BytesEqual(s1, sb))
        {
            result.Message = "B's verification value does not match";
            return result;
        }

        var sa = CreateS(0x03, u, za, zb, rA, rB);
        result.Sa = HexUtils.BytesToHex(sa);
        result.Ka = HexUtils.BytesToHex(ka);
        result.Success = true;
        return result;
    }

    public static bool CheckSa(ECPoint v, byte[] za, byte[] zb, ECPoint rA, ECPoint rB, byte[] sa)
    {
        var s2 = CreateS(0x03, v, za, zb, rA, rB);
        return BytesEqual(s2, sa);
    }

    public static ECPoint DecodePoint(string hexStr) => ECPoint.FromHexEncoded(hexStr);

    public static ECPoint GetPublicKey(BigInt256 privateKey) => ECPoint.Generator().Multiply(privateKey);

    // --- internal helpers ---

    private static BigInt256 RandomBigInt()
    {
        var b = new byte[32];
        RandomNumberGenerator.Fill(b);
        return BigInt256.FromBEBytes(b);
    }

    private static byte[] Kdf(int keylen, ECPoint p2)
    {
        var result = new byte[keylen];
        uint ct = 1;
        int blocks = (keylen + 31) / 32;

        for (int i = 0; i < blocks; i++)
        {
            var sm3 = new SM3();
            sm3.Update(p2.X.ToBEBytes());
            sm3.Update(p2.Y.ToBEBytes());
            byte[] ctBytes = [(byte)(ct >> 24), (byte)(ct >> 16), (byte)(ct >> 8), (byte)ct];
            sm3.Update(ctBytes);
            sm3.Finish();
            var hash = sm3.HashBytes();

            int start = i * 32;
            int end = Math.Min((i + 1) * 32, keylen);
            Array.Copy(hash, 0, result, start, end - start);
            ct++;
        }
        return result;
    }

    private static byte[] KdfKeySwap(int keylen, ECPoint vu, byte[] za, byte[] zb)
    {
        var result = new byte[keylen];
        uint ct = 1;
        int blocks = (keylen + 31) / 32;

        for (int i = 0; i < blocks; i++)
        {
            var sm3 = new SM3();
            sm3.Update(vu.X.ToBEBytes());
            sm3.Update(vu.Y.ToBEBytes());
            sm3.Update(za);
            sm3.Update(zb);
            byte[] ctBytes = [(byte)(ct >> 24), (byte)(ct >> 16), (byte)(ct >> 8), (byte)ct];
            sm3.Update(ctBytes);
            sm3.Finish();
            var hash = sm3.HashBytes();

            int start = i * 32;
            int end = Math.Min((i + 1) * 32, keylen);
            Array.Copy(hash, 0, result, start, end - start);
            ct++;
        }
        return result;
    }

    private static byte[] UserSM3Z(byte[] userID, ECPoint publicKey)
    {
        var sm3 = new SM3();

        ushort entl = (ushort)(userID.Length * 8);
        sm3.UpdateByte((byte)(entl >> 8));
        sm3.UpdateByte((byte)(entl & 0xFF));

        sm3.Update(userID);

        sm3.Update(ECPoint.SM2_A.ToBEBytes());
        sm3.Update(ECPoint.SM2_B.ToBEBytes());
        sm3.Update(ECPoint.SM2_GX.ToBEBytes());
        sm3.Update(ECPoint.SM2_GY.ToBEBytes());
        sm3.Update(publicKey.X.ToBEBytes());
        sm3.Update(publicKey.Y.ToBEBytes());

        sm3.Finish();
        return sm3.HashBytes();
    }

    private static BigInt256 CalcX(BigInt256 x)
    {
        var twoPowW = BigInt256.FromHex("80000000000000000000000000000000");
        var mask = BigInt256.FromHex("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
        var xMasked = x.And(mask);
        return twoPowW.Add(xMasked, out _);
    }

    private static BigInt256 CalcT(in BigInt256 n, in BigInt256 r, in BigInt256 d, in BigInt256 x_)
    {
        var xr = x_.ModMul(r, n);
        return d.ModAdd(xr, n);
    }

    private static ECPoint CalcPoint(in BigInt256 t, in BigInt256 x_, ECPoint p, ECPoint r)
    {
        var xr = r.Multiply(x_);
        var sum = p.Add(xr);
        return sum.Multiply(t);
    }

    private static byte[] CreateS(byte tag, ECPoint vu, byte[] za, byte[] zb, ECPoint ra, ECPoint rb)
    {
        var sm3 = new SM3();
        sm3.Update(vu.X.ToBEBytes());
        sm3.Update(za);
        sm3.Update(zb);
        sm3.Update(ra.X.ToBEBytes());
        sm3.Update(ra.Y.ToBEBytes());
        sm3.Update(rb.X.ToBEBytes());
        sm3.Update(rb.Y.ToBEBytes());
        sm3.Finish();
        var h1 = sm3.HashBytes();

        var hash = new SM3();
        hash.UpdateByte(tag);
        hash.Update(vu.Y.ToBEBytes());
        hash.Update(h1);
        hash.Finish();
        return hash.HashBytes();
    }

    private static bool BytesEqual(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++)
            if (a[i] != b[i]) return false;
        return true;
    }
}
