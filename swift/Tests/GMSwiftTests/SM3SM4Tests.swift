import XCTest

@testable import GMSwift

final class SM3SM4Tests: XCTestCase {
    func testSM3Empty() {
        let sm3 = SM3()
        _ = sm3.finalize()
        XCTAssertEqual(sm3.getHash(), "1AB21D8355CFA17F8E61194831E81A8F22BEC8C728FEFB747ED035EB5082AA2B")
    }

    func testSM3Abc() {
        let sm3 = SM3()
        _ = sm3.update("abc").finalize()
        XCTAssertEqual(sm3.getHash(), "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0")
    }

    /// 原测试使用15字节的文本密钥，由 SM3 派生出熵约64位的密钥。这条路径已被移除：
    /// 同样的文本密钥现在必须失败，而把派生结果（SM3 大写十六进制的前16个字符）显式作为16字节密钥时，密文与原来完全相同。
    func testSM4RoundTrip() {
        let rejected = Sm4Impl()
        _ = rejected.setKey(key: "this is the key", iv: "this is the iv", hex: false)
        XCTAssertEqual(rejected.encrypt(text: "x"), "")

        let derive: (String) -> String = { String(SM3().update($0).finalize().getHash().prefix(16)) }
        let sm4 = Sm4Impl()
        _ = sm4.setKey(key: derive("this is the key"), iv: derive("this is the iv"), hex: false)
        let msg = "国密SM4对称加密算法"
        let c = sm4.encrypt(text: msg)
        XCTAssertEqual(c, "09908004c24cece806ee6dc2d6a3d154907048fb96d0201a8c47f4f1e03995bc")
        let p = sm4.decrypt(text: c)
        XCTAssertEqual(p, msg)
    }
}
