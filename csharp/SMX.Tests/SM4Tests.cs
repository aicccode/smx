using SMX;
using System.Text;

namespace SMX.Tests;

public class SM4Tests
{
    [Fact]
    public void EncryptDecrypt()
    {
        var sm4 = new SM4();
        sm4.SetKey(Encoding.UTF8.GetBytes("this is the key"), Encoding.UTF8.GetBytes("this is the iv"));

        string plaintext = "国密SM4对称加密算法";

        string ciphertext = sm4.Encrypt(plaintext);
        Assert.Equal("09908004c24cece806ee6dc2d6a3d154907048fb96d0201a8c47f4f1e03995bc", ciphertext);

        string decrypted = sm4.Decrypt(ciphertext);
        Assert.Equal(plaintext, decrypted);
    }
}
