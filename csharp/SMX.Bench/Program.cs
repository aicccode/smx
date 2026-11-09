// Dependency-free benchmark for the SMX public API.
//
//   dotnet run -c Release --project SMX.Bench [-- --rounds N --millis M --filter text]
//   taskset -c 2 dotnet SMX.Bench/bin/Release/net8.0/SMX.Bench.dll
//
// Only public API is used, so the same file also builds against an older copy of the library. Each case warms up
// until the JIT has settled, then the best of several timed rounds is reported, along with allocations per call.
using System.Diagnostics;
using System.Text;
using SMX;

int rounds = 7;
int millis = 200;
string? filter = null;
for (int i = 0; i + 1 < args.Length; i += 2)
{
    switch (args[i])
    {
        case "--rounds":
            rounds = int.Parse(args[i + 1]);
            break;
        case "--millis":
            millis = int.Parse(args[i + 1]);
            break;
        case "--filter":
            filter = args[i + 1];
            break;
        default:
            throw new ArgumentException($"unknown option {args[i]}");
    }
}

const int WarmupMillis = 2000;
long sink = 0;

void Run(string name, long bytesPerOp, Func<long> op)
{
    if (filter != null && !name.Contains(filter, StringComparison.OrdinalIgnoreCase))
    {
        return;
    }

    // Warm-up: long enough for tiered compilation to reach tier 1, even when pinned to one core with the JIT thread.
    var warm = Stopwatch.StartNew();
    while (warm.ElapsedMilliseconds < Math.Max(millis * 2, WarmupMillis))
    {
        sink += op();
    }
    Thread.Sleep(150);

    double bestNs = double.MaxValue;
    for (int round = 0; round < rounds; round++)
    {
        long ops = 0;
        var sw = Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < millis)
        {
            sink += op();
            ops++;
        }
        sw.Stop();
        bestNs = Math.Min(bestNs, sw.Elapsed.TotalNanoseconds / ops);
    }

    long before = GC.GetAllocatedBytesForCurrentThread();
    sink += op();
    long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

    string throughput = bytesPerOp > 0 ? $"{bytesPerOp * 1e9 / bestNs / (1024 * 1024),10:F1} MiB/s" : new string(' ', 16);
    Console.WriteLine($"{name,-22} {bestNs / 1000,14:F3} us/op {1e9 / bestNs,12:F0} op/s {throughput} {allocated,10} B/op");
}

byte[] Bytes(int n)
{
    var data = new byte[n];
    new Random(42).NextBytes(data);
    return data;
}

string Ascii(int n)
{
    var sb = new StringBuilder(n);
    for (int i = 0; i < n; i++)
    {
        sb.Append((char)('a' + i % 26));
    }
    return sb.ToString();
}

foreach (var (label, size) in new[] { ("64B", 64), ("1KB", 1024), ("1MB", 1024 * 1024) })
{
    var data = Bytes(size);
    Run($"SM3 {label}", size, () =>
    {
        var h = new SM3();
        h.Update(data);
        h.Finish();
        return h.HashBytes()[0];
    });
}

var key = Encoding.ASCII.GetBytes("0123456789abcdef");
var iv = Encoding.ASCII.GetBytes("fedcba9876543210");
Run("SM4 key schedule", 0, () =>
{
    var c = new SM4();
    c.SetKey(key, iv);
    return 1;
});

foreach (var (label, size) in new[] { ("16B", 16), ("1KB", 1024), ("1MB", 1024 * 1024) })
{
    var c = new SM4();
    c.SetKey(key, iv);
    var plain = Ascii(size);
    var cipher = c.Encrypt(plain);
    Run($"SM4 encrypt {label}", size, () => c.Encrypt(plain).Length);
    Run($"SM4 decrypt {label}", size, () => c.Decrypt(cipher).Length);
}

const string UserId = "ALICE123@YAHOO.COM";
const string Message = "encryption standard";
var (pri, pub) = SM2.GenKeyPair();
var signature = SM2.Sign(UserId, Message, pri);
var cipherText = SM2.Encrypt(Message, pub);

Run("SM2 keygen", 0, () => SM2.GenKeyPair().privateKey.Length);
Run("SM2 sign", 0, () => SM2.Sign(UserId, Message, pri).Length);
Run("SM2 verify", 0, () => SM2.Verify(UserId, signature, Message, pub) ? 1 : throw new InvalidOperationException());
Run("SM2 encrypt", 0, () => SM2.Encrypt(Message, pub).Length);
Run("SM2 decrypt", 0, () => SM2.Decrypt(cipherText, pri).Length);

var longMessage = Ascii(1024 * 1024);
var longCipherText = SM2.Encrypt(longMessage, pub);
Run("SM2 encrypt 1MB", 1024 * 1024, () => SM2.Encrypt(longMessage, pub).Length);
Run("SM2 decrypt 1MB", 1024 * 1024, () => SM2.Decrypt(longCipherText, pri).Length);

const string IdA = "ALICE123@YAHOO.COM";
const string IdB = "BILL456@YAHOO.COM";
var dA = BigInt256.FromHex("6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE");
var ra = BigInt256.FromHex("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563");
var dB = BigInt256.FromHex("5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53");
var rb = BigInt256.FromHex("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80");
var pA = SM2.GetPublicKey(dA);
var rA = SM2.GetPublicKey(ra);
var pB = SM2.GetPublicKey(dB);
var rB = SM2.GetPublicKey(rb);
Run("SM2 key exchange", 0, () =>
{
    // One complete exchange: B responds, A confirms, B checks. Both sides' work is included.
    var b = SM2.GetSb(16, pA, rA, pB, dB, rB, rb, IdA, IdB);
    var a = SM2.GetSa(16, pB, rB, pA, dA, rA, ra, IdA, IdB, HexUtils.HexToBytes(b.Sb));
    var ok = SM2.CheckSa(b.V, b.Za, b.Zb, rA, rB, HexUtils.HexToBytes(a.Sa));
    return ok && a.Ka == b.Kb ? 1 : throw new InvalidOperationException();
});
Run("SM2 public key", 0, () => SM2.GetPublicKey(dA).Infinity ? 0 : 1);

// SM9: the master public key caches its pairing value, so sign and encrypt pay for one GT exponentiation, not a pairing.
var (sm9SignMsk, sm9SignMpk) = SM9.GenSignMasterKey();
var (sm9EncMsk, sm9EncMpk) = SM9.GenEncMasterKey();
var sm9Ds = SM9.GenSignUserKey(sm9SignMsk, IdA);
var sm9De = SM9.GenEncUserKey(sm9EncMsk, IdB);
var sm9Message = Encoding.UTF8.GetBytes(Message);
var sm9Signature = SM9.Sign(sm9Message, sm9Ds, sm9SignMpk);
var sm9Cipher = SM9.Encrypt(sm9Message, IdB, sm9EncMpk);
var sm9CipherSm4 = SM9.Encrypt(sm9Message, IdB, sm9EncMpk, mode: SM9EncryptMode.SM4);
var (_, sm9Kem) = SM9.Encapsulate(IdB, sm9EncMpk, 32);
var sm9DeA = SM9.GenEncUserKey(sm9EncMsk, IdA, SM9.HidExchange);
var sm9DeB = SM9.GenEncUserKey(sm9EncMsk, IdB, SM9.HidExchange);
var (sm9Ra, sm9RA) = SM9.ExchangeInit(IdB, sm9EncMpk);
var (sm9Rb, sm9RB) = SM9.ExchangeInit(IdA, sm9EncMpk);

Run("SM9 sign master key", 0, () => SM9.GenSignMasterKey().masterPublicKey.Length);
Run("SM9 sign user key", 0, () => SM9.GenSignUserKey(sm9SignMsk, IdA).Length);
Run("SM9 enc user key", 0, () => SM9.GenEncUserKey(sm9EncMsk, IdB).Length);
Run("SM9 sign", 0, () => SM9.Sign(sm9Message, sm9Ds, sm9SignMpk).Length);
Run("SM9 verify", 0, () => SM9.Verify(sm9Message, sm9Signature, IdA, sm9SignMpk) ? 1 : throw new InvalidOperationException());
Run("SM9 encrypt", 0, () => SM9.Encrypt(sm9Message, IdB, sm9EncMpk).Length);
Run("SM9 decrypt", 0, () => SM9.DecryptToBytes(sm9Cipher, IdB, sm9De).Length);
Run("SM9 encrypt SM4", 0, () => SM9.Encrypt(sm9Message, IdB, sm9EncMpk, mode: SM9EncryptMode.SM4).Length);
Run("SM9 decrypt SM4", 0, () => SM9.DecryptToBytes(sm9CipherSm4, IdB, sm9De, SM9EncryptMode.SM4).Length);
Run("SM9 encapsulate", 0, () => SM9.Encapsulate(IdB, sm9EncMpk, 32).key.Length);
Run("SM9 decapsulate", 0, () => SM9.Decapsulate(sm9Kem, IdB, sm9De, 32).Length);
Run("SM9 exchange init", 0, () => SM9.ExchangeInit(IdB, sm9EncMpk).R.Length);
Run("SM9 key exchange", 0, () =>
{
    // B responds, A confirms, B checks: both sides' work after the two init steps.
    var b = SM9.ExchangeRespond(16, IdA, IdB, sm9EncMpk, sm9DeB, sm9Rb, sm9RB, sm9RA);
    var a = SM9.ExchangeConfirm(16, IdA, IdB, sm9EncMpk, sm9DeA, sm9Ra, sm9RA, sm9RB, b.Sb);
    return a.Success && SM9.ExchangeCheck(b.S2, a.Sa) && a.SharedKey == b.SharedKey ? 1 : throw new InvalidOperationException();
});

GC.KeepAlive(sink);
