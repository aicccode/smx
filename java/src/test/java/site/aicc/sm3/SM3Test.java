package site.aicc.sm3;

import org.junit.Assert;
import org.junit.Test;

public class SM3Test {

    @Test
    public void testSm3Empty() {
        SM3 sm3 = new SM3();
        String hash = sm3.finish().getHashCode();
        // 与 JS/Rust/Swift 版本保持一致
        Assert.assertEquals("1AB21D8355CFA17F8E61194831E81A8F22BEC8C728FEFB747ED035EB5082AA2B", hash);
    }

    @Test
    public void testSm3Abc() {
        SM3 sm3 = new SM3();
        sm3.update("abc");
        String hash = sm3.finish().getHashCode();
        Assert.assertEquals("66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0", hash);
    }
}
