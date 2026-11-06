// SMX Mac benchmark: identical source for the baseline (3397c6d) and the current library; only public API is used.
// Prints "<name>\t<median_us>\t<min_us>" per operation, in the order the kit spec requires.
using System.Diagnostics;
using System.Text;
using SMX;

const string UserId = "1234567812345678";
const double WarmupSeconds = 2.0;
const int Samples = 7;
const double SampleSeconds = 0.2;

long sink = 0;

void Check(bool condition, string what)
{
    if (!condition)
    {
        Console.Error.WriteLine("correctness check failed: " + what);
        Environment.Exit(1);
    }
}

void Measure(string name, Func<long> op)
{
    var warm = Stopwatch.StartNew();
    long warmOps = 0;
    while (warm.Elapsed.TotalSeconds < WarmupSeconds)
    {
        sink += op();
        warmOps++;
    }

    // Size each sample from the warm-up rate so that it lasts at least 200 ms, then re-check the time.
    double perOp = warm.Elapsed.TotalSeconds / Math.Max(1, warmOps);
    long batch = Math.Max(1, (long)(SampleSeconds / perOp / 4));
    var results = new double[Samples];
    for (int s = 0; s < Samples; s++)
    {
        long ops = 0;
        long start = Stopwatch.GetTimestamp();
        double elapsed;
        do
        {
            for (long i = 0; i < batch; i++)
            {
                sink += op();
            }
            ops += batch;
            elapsed = Stopwatch.GetElapsedTime(start).TotalSeconds;
        }
        while (elapsed < SampleSeconds);
        results[s] = elapsed * 1e6 / ops;
    }
    Array.Sort(results);
    Console.WriteLine($"{name}\t{results[Samples / 2]:F3}\t{results[0]:F3}");
}

byte[] RandomBytes(int n)
{
    var b = new byte[n];
    new Random(n).NextBytes(b);
    return b;
}

// Printable ASCII text of exactly n bytes, since the SM4 and SM2 APIs take strings and encode them as UTF-8.
string Text(int n)
{
    var rng = new Random(n + 1);
    var sb = new StringBuilder(n);
    for (int i = 0; i < n; i++)
    {
        sb.Append((char)rng.Next(0x21, 0x7F));
    }
    return sb.ToString();
}

// --- correctness, once, outside timing ---
{
    var h = new SM3();
    h.Update(Encoding.ASCII.GetBytes("abc"));
    h.Finish();
    Check(h.HashHexUpper() == "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0", "SM3 abc");
}

// --- SM3 ---
foreach (var (label, size) in new[] { ("64B", 64), ("1KB", 1024), ("1MB", 1024 * 1024) })
{
    var data = RandomBytes(size);
    Measure($"sm3/{label}", () =>
    {
        var h = new SM3();
        h.Update(data);
        h.Finish();
        return h.HashBytes()[0];
    });
}

// --- SM4 ---
var key = RandomBytes(16);
var iv = RandomBytes(16)[..16];
iv[0] ^= 0x5A;
var keyCipher = new SM4();
keyCipher.SetKey(key, iv);
Measure("sm4/key_schedule", () =>
{
    keyCipher.SetKey(key, iv);
    return 1;
});

var cipher = new SM4();
cipher.SetKey(key, iv);
var sizes = new[] { ("16B", 16), ("1KB", 1024), ("1MB", 1024 * 1024) };
var plains = sizes.Select(s => Text(s.Item2)).ToArray();
var cipherTexts = plains.Select(p => cipher.Encrypt(p)).ToArray();
for (int i = 0; i < sizes.Length; i++)
{
    Check(cipherTexts[i].Length == (sizes[i].Item2 + 16) * 2, "SM4 ciphertext length");
    Check(cipher.Decrypt(cipherTexts[i]) == plains[i], "SM4 round trip " + sizes[i].Item1);
}
for (int i = 0; i < sizes.Length; i++)
{
    var p = plains[i];
    Measure($"sm4/cbc_encrypt/{sizes[i].Item1}", () => cipher.Encrypt(p).Length);
}
for (int i = 0; i < sizes.Length; i++)
{
    var c = cipherTexts[i];
    Measure($"sm4/cbc_decrypt/{sizes[i].Item1}", () => cipher.Decrypt(c).Length);
}

// --- SM2 ---
var (pri, pub) = SM2.GenKeyPair();
var message = Text(32);
var signature = SM2.Sign(UserId, message, pri);
Check(SM2.Verify(UserId, signature, message, pub), "SM2 verify");
Check(!SM2.Verify(UserId, signature, message + "x", pub), "SM2 verify rejects");
var plain32 = Text(32);
var sm2Cipher = SM2.Encrypt(plain32, pub);
Check(SM2.Decrypt(sm2Cipher, pri) == plain32, "SM2 round trip");

Measure("sm2/keygen", () => SM2.GenKeyPair().privateKey.Length);
Measure("sm2/sign", () => SM2.Sign(UserId, message, pri).Length);
Measure("sm2/verify", () => SM2.Verify(UserId, signature, message, pub) ? 1 : throw new InvalidOperationException("verify"));
Measure("sm2/encrypt/32B", () => SM2.Encrypt(plain32, pub).Length);
Measure("sm2/decrypt/32B", () => SM2.Decrypt(sm2Cipher, pri).Length);

// Key exchange: long-term keys are fixed; each exchange draws both ephemeral keys and runs both sides with confirmation.
const string IdA = "ALICE123@YAHOO.COM";
const string IdB = "BILL456@YAHOO.COM";
var (dAHex, pAHex) = SM2.GenKeyPair();
var (dBHex, pBHex) = SM2.GenKeyPair();
var dA = BigInt256.FromHex(dAHex);
var dB = BigInt256.FromHex(dBHex);
var pA = SM2.DecodePoint(pAHex);
var pB = SM2.DecodePoint(pBHex);

long Exchange()
{
    var (raHex, rAHex) = SM2.GenKeyPair();
    var (rbHex, rBHex) = SM2.GenKeyPair();
    var ra = BigInt256.FromHex(raHex);
    var rb = BigInt256.FromHex(rbHex);
    var rA = SM2.DecodePoint(rAHex);
    var rB = SM2.DecodePoint(rBHex);

    var b = SM2.GetSb(16, pA, rA, pB, dB, rB, rb, IdA, IdB);
    var a = SM2.GetSa(16, pB, rB, pA, dA, rA, ra, IdA, IdB, HexUtils.HexToBytes(b.Sb));
    bool ok = b.Success && a.Success && a.Ka == b.Kb && a.Ka.Length == 32
        && SM2.CheckSa(b.V, b.Za, b.Zb, rA, rB, HexUtils.HexToBytes(a.Sa));
    return ok ? 1 : throw new InvalidOperationException("key exchange");
}

Check(Exchange() == 1, "key exchange");
Measure("sm2/key_exchange", Exchange);

GC.KeepAlive(sink);
