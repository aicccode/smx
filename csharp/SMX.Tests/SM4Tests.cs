using SMX;
using System.Text;

namespace SMX.Tests;

public class SM4Tests
{
    private const string DerivedKey = "157224F19FD4C080";
    private const string DerivedIv = "65B06A99625C008A";

    [Fact]
    public void EncryptDecrypt()
    {
        var sm4 = new SM4();
        // SetKey no longer derives keys from other lengths. These are the values that derivation gave for the 15-byte key
        // "this is the key" and the 14-byte IV "this is the iv", so the ciphertext below stays the original KAT.
        sm4.SetKey(Encoding.ASCII.GetBytes(DerivedKey), Encoding.ASCII.GetBytes(DerivedIv));

        string plaintext = "国密SM4对称加密算法";

        string ciphertext = sm4.Encrypt(plaintext);
        Assert.Equal("09908004c24cece806ee6dc2d6a3d154907048fb96d0201a8c47f4f1e03995bc", ciphertext);

        string decrypted = sm4.Decrypt(ciphertext);
        Assert.Equal(plaintext, decrypted);
    }
}
