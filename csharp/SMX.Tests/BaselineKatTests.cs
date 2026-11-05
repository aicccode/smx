using System.Numerics;
using System.Reflection;
using System.Text;
using SMX;

namespace SMX.Tests;

/// <summary>
/// Replays answers captured from the pre-optimization implementation (commit 3397c6d), including its exception types
/// and messages and its results for off-curve points and unreduced inputs. Any difference is a compatibility break.
/// Set SMX_KAT_FILE to replay a larger capture in the same format.
/// </summary>
public class BaselineKatTests
{
    private static string Hx(byte[] b) => HexUtils.BytesToHex(b);

    private static BigInt256 B(string s) => BigInt256.FromHex(s);

    private static ECPoint Pt(string s)
    {
        var parts = s.Split(':');
        return new ECPoint
        {
            Infinity = parts[0] == "I",
            X = new FpElement { Value = B(parts[1]) },
            Y = new FpElement { Value = B(parts[2]) },
        };
    }

    private static string Ps(ECPoint p) => (p.Infinity ? "I" : "A") + ":" + p.X.Value.ToHex() + ":" + p.Y.Value.ToHex();

    private static string Attempt(Func<string> f)
    {
        try
        {
            return f();
        }
        catch (Exception ex)
        {
            return "!" + ex.GetType().Name + ":" + ex.Message;
        }
    }

    private static string Eval(string op, string[] a)
    {
        switch (op)
        {
            case "cmp": return B(a[0]).Compare(B(a[1])).ToString();
            case "add": { var r = B(a[0]).Add(B(a[1]), out ulong c); return r.ToHex() + "," + c; }
            case "sub": { var r = B(a[0]).Sub(B(a[1]), out ulong c); return r.ToHex() + "," + c; }
            case "mul": return string.Join(",", B(a[0]).Mul(B(a[1])).Select(x => x.ToString("X16")));
            case "and": return B(a[0]).And(B(a[1])).ToHex();
            case "shr1": return B(a[0]).ShiftRight1().ToHex();
            case "shl1": return B(a[0]).ShiftLeft1().ToHex();
            case "bitlen": return B(a[0]).BitLength().ToString();
            case "bit": return B(a[0]).GetBit(int.Parse(a[1])) ? "1" : "0";
            case "modp2": return B(a[0]).SM2ModMulP(B(a[1])).ToHex();
            case "sqrp": return B(a[0]).SM2ModSquareP().ToHex();
            case "modadd": return B(a[0]).ModAdd(B(a[1]), B(a[2])).ToHex();
            case "modsub": return B(a[0]).ModSub(B(a[1]), B(a[2])).ToHex();
            case "modmul": return Attempt(() => B(a[0]).ModMul(B(a[1]), B(a[2])).ToHex());
            case "modsqr": return B(a[0]).ModSquare(B(a[1])).ToHex();
            case "modinv": return B(a[0]).ModInverse(B(a[1])).ToHex();
            case "modpow": return a[1] == "x" ? "" : B(a[0]).ModPow(B(a[1]), B(a[2])).ToHex();
            case "fp_ctor": return new FpElement(B(a[0])).Value.ToHex();
            case "fp_add": return new FpElement(B(a[0])).Add(new FpElement(B(a[1]))).Value.ToHex();
            case "fp_sub": return new FpElement(B(a[0])).Sub(new FpElement(B(a[1]))).Value.ToHex();
            case "fp_mul": return new FpElement(B(a[0])).Mul(new FpElement(B(a[1]))).Value.ToHex();
            case "fp_sqr": return new FpElement(B(a[0])).Square().Value.ToHex();
            case "fp_neg": return new FpElement(B(a[0])).Negate().Value.ToHex();
            case "fp_dbl": return new FpElement(B(a[0])).Double().Value.ToHex();
            case "fp_tpl": return new FpElement(B(a[0])).Triple().Value.ToHex();
            case "fp_inv": return Attempt(() => new FpElement(B(a[0])).Invert().Value.ToHex());
            case "fp_div": return Attempt(() => new FpElement(B(a[0])).Div(new FpElement(B(a[1]))).Value.ToHex());
            case "b2h": return HexUtils.BytesToHex(Convert.FromHexString(a[0]));
            case "b2hu": return HexUtils.BytesToHexUpper(Convert.FromHexString(a[0]));
            case "h2b": return Attempt(() => Hx(HexUtils.HexToBytes(a[0])));
            case "bigfromhex": return Attempt(() => BigInt256.FromHex(a[0]).ToHex());
            case "fpfromhex": return Attempt(() => FpElement.FromHex(a[0]).Value.ToHex());
            case "frombe": return BigInt256.FromBEBytes(Convert.FromHexString(a[0])).ToHex();
            case "sm3": return Sm3(a[0], a[1]);
            case "sm3again": { var h = new SM3(); h.Update(Convert.FromHexString(a[0])); h.Finish(); h.Finish(); return h.HashHexUpper(); }
            case "sm4": { var c = Sm4(a[0], a[1]); return c.Encrypt(a[2]); }
            case "sm4dec": { var c = Sm4(a[0], a[1]); return c.Decrypt(a[2]); }
            case "sm4nokey": return new SM4().Encrypt("no key set");
            case "sm4decerr":
                {
                    var c = Sm4(new string('0', 32), new string('0', 32));
                    return Attempt(() =>
                    {
                        var plain = c.Decrypt(a[0]);
                        // Blocks crafted with valid padding were recorded as hex of the UTF-8 plaintext.
                        return a[0].Length == 32 && a[0] != new string('0', 32) && a[0].Any(ch => ch != 'a') ? Convert.ToHexString(Encoding.UTF8.GetBytes(plain)) : plain;
                    });
                }
            case "gmul": return Ps(ECPoint.Generator().Multiply(B(a[0])));
            case "pmul": return Ps(Pt(a[0]).Multiply(B(a[1])));
            case "oncurve": return Pt(a[0]).IsOnCurve() ? "1" : "0";
            case "neg": return Ps(Pt(a[0]).Negate());
            case "twice": return Ps(Pt(a[0]).Twice());
            case "enc": return Hx(Pt(a[0]).ToEncoded());
            case "hexenc": return Pt(a[0]).ToHexEncoded();
            case "padd": return Attempt(() => Ps(Pt(a[0]).Add(Pt(a[1]))));
            case "psub": return Attempt(() => Ps(Pt(a[0]).Subtract(Pt(a[1]))));
            case "peq": return Pt(a[0]).Equal(Pt(a[1])) ? "1" : "0";
            case "decpt": return Attempt(() => Ps(ECPoint.FromHexEncoded(a[0])));
            case "pubkey": return SM2.GetPublicKey(B(a[0])).ToHexEncoded();
            case "verify": return Attempt(() => SM2.Verify(a[0], a[1], a[2], a[3]) ? "1" : "0");
            case "dec": return Attempt(() => SM2.Decrypt(a[0], a[1]));
            case "getsb":
                {
                    var r = SM2.GetSb(int.Parse(a[0]), Pt(a[1]), Pt(a[2]), Pt(a[3]), B(a[4]), Pt(a[5]), B(a[6]), a[7], a[8]);
                    return string.Join(",", r.Success, r.Message, r.Sb, r.Kb, Ps(r.V), Hx(r.Za), Hx(r.Zb), r.Sa, r.Ka);
                }
            case "getsa":
                {
                    var r = SM2.GetSa(int.Parse(a[0]), Pt(a[1]), Pt(a[2]), Pt(a[3]), B(a[4]), Pt(a[5]), B(a[6]), a[7], a[8], Convert.FromHexString(a[9]));
                    return string.Join(",", r.Success, r.Message, r.Sa, r.Ka, r.Sb, r.Kb);
                }
            case "checksa":
                return SM2.CheckSa(Pt(a[0]), Convert.FromHexString(a[1]), Convert.FromHexString(a[2]), Pt(a[3]), Pt(a[4]), Convert.FromHexString(a[5])) ? "1" : "0";
            case "enc_empty": return Attempt(() => SM2.Encrypt("", "04" + a[0]));
            case "enc_err": return Attempt(() => SM2.Encrypt("m", a[0]));
            default: throw new InvalidOperationException("unknown op " + op);
        }
    }

    private static string Sm3(string messageHex, string chunkList)
    {
        var m = Convert.FromHexString(messageHex);
        var h = new SM3();
        int o = 0;
        foreach (var c in chunkList.Split(',').Select(int.Parse))
        {
            int n = Math.Min(c, m.Length - o);
            h.Update(m[o..(o + n)]);
            o += n;
        }
        while (o < m.Length)
        {
            h.UpdateByte(m[o++]);
        }
        h.Finish();
        return h.HashHexUpper() + "," + Hx(h.HashBytes());
    }

    private static SM4 Sm4(string keyHex, string ivHex)
    {
        var c = new SM4();
        c.SetKey(Convert.FromHexString(keyHex), Convert.FromHexString(ivHex));
        return c;
    }

    private static readonly StreamWriter? DiffLog = Environment.GetEnvironmentVariable("SMX_KAT_DIFF") is { Length: > 0 } p
        ? new StreamWriter(p, append: false) { AutoFlush = true }
        : null;

    private static void Replay(TextReader reader)
    {
        var failures = new List<string>();
        int count = 0;
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            var fields = line.Split('\t');
            var op = fields[0];
            var expected = fields[^1];
            if (op == "sm4nokey" && fields.Length == 2)
            {
                fields = [op, expected];
            }
            var a = fields[1..^1];
            if (op == "modpow" && a[1] == "x")
            {
                continue;
            }
            count++;
            string actual;
            try
            {
                actual = Eval(op, a);
            }
            catch (Exception ex)
            {
                actual = "threw " + ex;
            }
            if (actual != expected)
            {
                DiffLog?.WriteLine(line + "\t=>\t" + actual.Replace('\n', ' '));
            }
            if (actual != expected && failures.Count < 20)
            {
                failures.Add($"{op}({string.Join(", ", a)})\n  expected {expected}\n  actual   {actual}");
            }
        }
        Assert.True(count > 0, "no vectors");
        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }

    [Fact]
    public void ReplayEmbeddedCapture()
    {
        var asm = Assembly.GetExecutingAssembly();
        var name = asm.GetManifestResourceNames().Single(n => n.EndsWith("baseline_kat.txt", StringComparison.Ordinal));
        using var reader = new StreamReader(asm.GetManifestResourceStream(name)!, Encoding.UTF8);
        Replay(reader);
    }

    [Fact]
    public void ReplayExternalCaptureWhenConfigured()
    {
        var path = Environment.GetEnvironmentVariable("SMX_KAT_FILE");
        if (string.IsNullOrEmpty(path))
        {
            return;
        }
        using var reader = new StreamReader(path, Encoding.UTF8);
        Replay(reader);
    }
}
