import XCTest
@testable import GMSwiftTests

fileprivate extension SM2Tests {
    @available(*, deprecated, message: "Not actually deprecated. Marked as deprecated to allow inclusion of deprecated tests (which test deprecated functionality) without warnings")
    static nonisolated(unsafe) let __allTests__SM2Tests = [
        ("testBigIntAdd", testBigIntAdd),
        ("testBigIntFromHex", testBigIntFromHex),
        ("testBigIntModInverse", testBigIntModInverse),
        ("testBigIntMul", testBigIntMul),
        ("testBigIntSub", testBigIntSub),
        ("testEncryptDecrypt", testEncryptDecrypt),
        ("testEncryptDecryptChinese", testEncryptDecryptChinese),
        ("testKeyExchange", testKeyExchange),
        ("testKeyPairGeneration", testKeyPairGeneration),
        ("testPointAdd", testPointAdd),
        ("testPointMultiply", testPointMultiply),
        ("testPointOnCurve", testPointOnCurve),
        ("testPointTwice", testPointTwice),
        ("testSignVerify", testSignVerify),
        ("testSignVerifyWrongMessage", testSignVerifyWrongMessage)
    ]
}

fileprivate extension SM3SM4Tests {
    @available(*, deprecated, message: "Not actually deprecated. Marked as deprecated to allow inclusion of deprecated tests (which test deprecated functionality) without warnings")
    static nonisolated(unsafe) let __allTests__SM3SM4Tests = [
        ("testSM3Abc", testSM3Abc),
        ("testSM3Empty", testSM3Empty),
        ("testSM4RoundTrip", testSM4RoundTrip)
    ]
}
@available(*, deprecated, message: "Not actually deprecated. Marked as deprecated to allow inclusion of deprecated tests (which test deprecated functionality) without warnings")
func __GMSwiftTests__allTests() -> [XCTestCaseEntry] {
    return [
        testCase(SM2Tests.__allTests__SM2Tests),
        testCase(SM3SM4Tests.__allTests__SM3SM4Tests)
    ]
}