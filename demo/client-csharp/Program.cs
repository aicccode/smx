using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SMX;

// Demo limitation: this talks plain HTTP, so anyone on the network can read or alter the traffic, and nothing
// authenticates the server's long-term public key. Real deployments need TLS and a way to trust the peer's key.
const string serverUrl = "http://localhost:8080";
const string ida = "csharp-client@demo.aicc";
const int MaxResponseBytes = 1024 * 1024;
const string PinnedKeyVariable = "SM2_DEMO_SERVER_PUBKEY";

// One deadline for the whole run, however slowly a server sends its bytes.
using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(60));

try
{
    return await RunDemo();
}
catch (Exception ex)
{
    // Only the exception's type: its text can quote server data.
    Console.Error.WriteLine($"Demo failed: {ex.GetType().Name}");
    return 1;
}

async Task<int> RunDemo()
{
    Console.WriteLine("=== SM2 Key Exchange Demo (C# Client) ===");
    Console.WriteLine();

    // Generate A-side certificate keypair. Private keys and session keys are never printed.
    var (daHex, paHex) = SM2.GenKeyPair();
    Console.WriteLine("Generated A certificate keypair:");
    Console.WriteLine($"  Public key (pA): {paHex}");

    // Generate A-side random keypair
    var (raHex, raPubHex) = SM2.GenKeyPair();
    Console.WriteLine("\nGenerated A random keypair:");
    Console.WriteLine($"  Public key (Ra): {raPubHex}");

    int keyLen = 16;

    using var http = new HttpClient(new HttpClientHandler { UseProxy = false, AllowAutoRedirect = false })
    {
        MaxResponseContentBufferSize = MaxResponseBytes,
        Timeout = TimeSpan.FromSeconds(30),
    };

    async Task<T> PostJson<T>(string url, object req) where T : class
    {
        var json = JsonSerializer.Serialize(req);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var response = await http.PostAsync(url, content, deadline.Token);
        response.EnsureSuccessStatusCode();
        var respJson = await response.Content.ReadAsStringAsync(deadline.Token);
        Console.WriteLine($"Response: {Printable(respJson)}");
        return JsonSerializer.Deserialize<T>(respJson) ?? throw new JsonException("empty response");
    }

    // Step 1: Key Exchange Init
    Console.WriteLine("\n--- Step 1: Key Exchange Init ---");
    var initReq = new InitRequest { IDa = ida, PA = paHex, Ra = raPubHex, KeyLen = keyLen };
    Console.WriteLine($"Request: {JsonSerializer.Serialize(initReq)}");

    InitResponse initResp;
    try
    {
        initResp = await PostJson<InitResponse>($"{serverUrl}/api/keyswap/init", initReq);
    }
    catch (HttpRequestException)
    {
        Console.Error.WriteLine("Failed to connect to server");
        Console.Error.WriteLine("Make sure the Java server is running on port 8080");
        return 1;
    }

    // Step 2: Calculate Sa and Ka
    Console.WriteLine("\n--- Step 2: Calculate Sa and Ka ---");

    // Key confirmation only proves the peer holds the private key for the pB it sent, and anyone can make a key pair. Without
    // a pinned key an impostor passes every check below.
    var pinnedKey = Environment.GetEnvironmentVariable(PinnedKeyVariable);
    if (string.IsNullOrEmpty(pinnedKey))
    {
        Console.WriteLine($"WARNING: the server is UNAUTHENTICATED. Set {PinnedKeyVariable} to its public key to pin it.");
    }
    else if (!SMX.ECPoint.FromHexEncoded(pinnedKey).Equal(SMX.ECPoint.FromHexEncoded(initResp.PB)))
    {
        Console.Error.WriteLine("Server public key does not match the pinned key");
        return 1;
    }

    var pB = SMX.ECPoint.FromHexEncoded(initResp.PB);
    var rB = SMX.ECPoint.FromHexEncoded(initResp.RB);
    var pA = SMX.ECPoint.FromHexEncoded(paHex);
    var rA = SMX.ECPoint.FromHexEncoded(raPubHex);
    var dA = BigInt256.FromHex(daHex);
    var ra = BigInt256.FromHex(raHex);
    var sbBytes = HexUtils.HexToBytes(initResp.Sb);

    var result = SM2.GetSa(keyLen, pB, rB, pA, dA, rA, ra, ida, initResp.IDb, sbBytes);
    if (!result.Success)
    {
        Console.Error.WriteLine($"getSa failed: {result.Message}");
        return 1;
    }

    Console.WriteLine($"Sa: {result.Sa}");

    // Step 3: Key Exchange Confirm
    Console.WriteLine("\n--- Step 3: Key Exchange Confirm ---");
    var confirmReq = new ConfirmRequest { SessionId = initResp.SessionId, Sa = result.Sa };
    Console.WriteLine($"Request: {JsonSerializer.Serialize(confirmReq)}");

    var confirmResp = await PostJson<ConfirmResponse>($"{serverUrl}/api/keyswap/confirm", confirmReq);

    if (!confirmResp.Success)
    {
        Console.Error.WriteLine("Key exchange confirmation failed");
        return 1;
    }

    Console.WriteLine("\nKey exchange completed successfully!");

    // Step 4: Bidirectional Crypto Test
    Console.WriteLine("\n--- Step 4: Bidirectional Crypto Test ---");

    var kaBytes = HexUtils.HexToBytes(result.Ka);
    // The protocol this demo must interoperate with fixes an all-zero IV. Safe use needs a fresh random IV per message,
    // and CBC gives no integrity by itself: do not copy this part into real code.
    var ivBytes = new byte[16];
    var sm4 = new SM4();
    sm4.SetKey(kaBytes, ivBytes);

    string clientPlaintext = "Hello from C# Client!";
    string clientCiphertext = sm4.Encrypt(clientPlaintext);
    Console.WriteLine($"Client plaintext: {clientPlaintext}");
    Console.WriteLine($"Client ciphertext: {clientCiphertext}");

    var cryptoReq = new CryptoTestRequest
    {
        SessionId = initResp.SessionId,
        ClientCiphertext = clientCiphertext,
        ClientPlaintext = clientPlaintext
    };
    Console.WriteLine($"\nRequest: {JsonSerializer.Serialize(cryptoReq)}");

    var cryptoResp = await PostJson<CryptoTestResponse>($"{serverUrl}/api/crypto/test", cryptoReq);

    // Verify server correctly decrypted client's message
    bool serverDecryptOk = cryptoResp.ClientDecryptMatch;
    Console.WriteLine(serverDecryptOk
        ? "\n[Server decrypted client message]: PASS"
        : "\n[Server decrypted client message]: FAIL");

    // Client decrypts server's message
    string serverDecrypted = sm4.Decrypt(cryptoResp.ServerCiphertext);
    bool clientDecryptOk = serverDecrypted == cryptoResp.ServerPlaintext;
    Console.WriteLine(clientDecryptOk
        ? "[Client decrypted server message]: PASS"
        : "[Client decrypted server message]: FAIL");
    Console.WriteLine($"  Server plaintext: {Printable(cryptoResp.ServerPlaintext)}");
    Console.WriteLine($"  Client decrypted: {Printable(serverDecrypted)}");

    if (serverDecryptOk && clientDecryptOk)
    {
        Console.WriteLine("\nBidirectional Crypto test PASSED!");
    }
    else
    {
        Console.Error.WriteLine("\nBidirectional Crypto test FAILED!");
        return 1;
    }

    Console.WriteLine("\n=== Demo Complete ===");
    return 0;
}

// Server text may hold terminal escape sequences or direction overrides; show none of them raw.
static string Printable(string text) => string.Concat(text.Select(c =>
    char.IsControl(c) || char.GetUnicodeCategory(c) is System.Globalization.UnicodeCategory.Format
        or System.Globalization.UnicodeCategory.LineSeparator or System.Globalization.UnicodeCategory.ParagraphSeparator
        ? '?'
        : c));

// --- DTO classes with explicit JSON property names ---

class InitRequest
{
    [JsonPropertyName("IDa")] public string IDa { get; set; } = "";
    [JsonPropertyName("pA")] public string PA { get; set; } = "";
    [JsonPropertyName("Ra")] public string Ra { get; set; } = "";
    [JsonPropertyName("keyLen")] public int KeyLen { get; set; }
}

class InitResponse
{
    [JsonPropertyName("sessionId")] public string SessionId { get; set; } = "";
    [JsonPropertyName("IDb")] public string IDb { get; set; } = "";
    [JsonPropertyName("pB")] public string PB { get; set; } = "";
    [JsonPropertyName("Rb")] public string RB { get; set; } = "";
    [JsonPropertyName("Sb")] public string Sb { get; set; } = "";
}

class ConfirmRequest
{
    [JsonPropertyName("sessionId")] public string SessionId { get; set; } = "";
    [JsonPropertyName("Sa")] public string Sa { get; set; } = "";
}

class ConfirmResponse
{
    [JsonPropertyName("success")] public bool Success { get; set; }
}

class CryptoTestRequest
{
    [JsonPropertyName("sessionId")] public string SessionId { get; set; } = "";
    [JsonPropertyName("clientCiphertext")] public string ClientCiphertext { get; set; } = "";
    [JsonPropertyName("clientPlaintext")] public string ClientPlaintext { get; set; } = "";
}

class CryptoTestResponse
{
    [JsonPropertyName("clientDecrypted")] public string ClientDecrypted { get; set; } = "";
    [JsonPropertyName("clientDecryptMatch")] public bool ClientDecryptMatch { get; set; }
    [JsonPropertyName("serverPlaintext")] public string ServerPlaintext { get; set; } = "";
    [JsonPropertyName("serverCiphertext")] public string ServerCiphertext { get; set; } = "";
}
