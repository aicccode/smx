using System.Reflection;
using System.Text.Json;

namespace SMX.Tests.SM9;

/// <summary>The shared vectors of testvectors/sm9-vectors.json, embedded in the test assembly.</summary>
internal static class Sm9Vectors
{
    private static readonly Lazy<JsonElement> Root = new(() =>
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("sm9-vectors.json")
            ?? throw new InvalidOperationException("sm9-vectors.json is not embedded");
        using var doc = JsonDocument.Parse(stream);
        return doc.RootElement.Clone();
    });

    public static JsonElement Json => Root.Value;

    public static JsonElement Standard(string name) => Json.GetProperty("standard").GetProperty(name);

    public static JsonElement Extra => Json.GetProperty("extra");

    public static string Str(this JsonElement e, string name) => e.GetProperty(name).GetString()!;

    public static int Int(this JsonElement e, string name) => e.GetProperty(name).GetInt32();

    public static byte[] Hex(this JsonElement e, string name) => Convert.FromHexString(e.Str(name));

    public static IEnumerable<object[]> Cases(string section, string kind)
    {
        var list = section == "extra" ? Extra.GetProperty(kind) : Json.GetProperty(section).GetProperty(kind);
        for (int i = 0; i < list.GetArrayLength(); i++)
        {
            yield return [i];
        }
    }
}
