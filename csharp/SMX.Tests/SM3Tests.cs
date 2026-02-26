using SMX;
using System.Text;

namespace SMX.Tests;

public class SM3Tests
{
    [Fact]
    public void SM3Abc()
    {
        var sm3 = new SM3();
        sm3.Update(Encoding.UTF8.GetBytes("abc"));
        sm3.Finish();
        Assert.Equal("66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0", sm3.HashHexUpper());
    }

    [Fact]
    public void SM3Empty()
    {
        var sm3 = new SM3();
        sm3.Update(Encoding.UTF8.GetBytes(""));
        sm3.Finish();
        Assert.Equal("1AB21D8355CFA17F8E61194831E81A8F22BEC8C728FEFB747ED035EB5082AA2B", sm3.HashHexUpper());
    }
}
