// 椭圆曲线点（仿射坐标，公开接口）

public final class ECPoint: Equatable {
    public var x: FpElement
    public var y: FpElement
    var infinity: Bool

    init(x: FpElement, y: FpElement) {
        self.x = x
        self.y = y
        self.infinity = false
    }

    init(infinity: Bool) {
        self.x = FpElement.zero
        self.y = FpElement.zero
        self.infinity = true
    }

    public static func infinityPoint() -> ECPoint {
        return ECPoint(infinity: true)
    }

    public static func generator() -> ECPoint {
        return ECPoint(x: FpElement(SM2Curve.gx), y: FpElement(SM2Curve.gy))
    }

    public var isInfinity: Bool { return infinity }

    /// 由32字节坐标的十六进制构造点。这些解析接口无法抛错：任何不合法的输入（长度、非十六进制、坐标 >= p、
    /// 不在曲线上）都返回无穷远点，可以用 isInfinity 判断；所有运算入口都会拒绝无穷远点。
    public static func fromHex(xHex: String, yHex: String) -> ECPoint {
        guard let xValue = BigInt256(hex: xHex), let yValue = BigInt256(hex: yHex) else {
            return ECPoint.infinityPoint()
        }
        return validated(x: xValue, y: yValue)
    }

    /// 恰好65字节，0x04 开头，坐标规范且在曲线上；否则返回无穷远点（见 fromHex）。
    public static func fromEncoded(_ data: [UInt8]) -> ECPoint {
        guard data.count == 65, data[0] == 0x04 else {
            return ECPoint.infinityPoint()
        }
        return data.withUnsafeBufferPointer { buffer -> ECPoint in
            guard let base = buffer.baseAddress else {
                return ECPoint.infinityPoint()
            }
            return validated(x: BigInt256.fromBEPointer(base + 1), y: BigInt256.fromBEPointer(base + 33))
        }
    }

    /// 恰好130个十六进制字符（大小写均可），其余同 fromEncoded。
    public static func fromHexEncoded(_ hex: String) -> ECPoint {
        guard let bytes = Hex.decodeStrict(hex) else {
            return ECPoint.infinityPoint()
        }
        return fromEncoded(bytes)
    }

    private static func validated(x xValue: BigInt256, y yValue: BigInt256) -> ECPoint {
        let point = ECPoint(x: FpElement(unchecked: xValue), y: FpElement(unchecked: yValue))
        return point.isValidPublicKey ? point : ECPoint.infinityPoint()
    }

    /// 可以作为对方公钥使用：不是无穷远点，坐标在 [0, p) 内，并且在曲线上。
    /// x、y 是公开可写的属性，所以每个入口都要重新检查，不能只依赖解析时的校验。
    var isValidPublicKey: Bool {
        return !infinity && x.value < SM2Curve.p && y.value < SM2Curve.p && isOnCurve()
    }

    public func toEncoded() -> [UInt8] {
        if infinity {
            return [0x00]
        }
        return [UInt8](unsafeUninitializedCapacity: 65) { buffer, initialized in
            buffer[0] = 0x04
            if let base = buffer.baseAddress {
                x.value.writeBE(to: base + 1)
                y.value.writeBE(to: base + 33)
            }
            initialized = 65
        }
    }

    public func toHexEncoded() -> String {
        return Hex.encode(toEncoded())
    }

    func negate() -> ECPoint {
        if infinity {
            return ECPoint.infinityPoint()
        }
        return ECPoint(x: x, y: y.negate())
    }

    // 转换为Jacobian坐标
    func toJacobian() -> JacobianPoint {
        if infinity { return JacobianPoint.infinity }
        return JacobianPoint(x: x, y: y, z: .one)
    }

    // 从Jacobian坐标转换回仿射坐标
    static func fromJacobian(_ point: JacobianPoint) -> ECPoint {
        guard let (affineX, affineY) = point.toAffine() else {
            return ECPoint.infinityPoint()
        }
        return ECPoint(x: affineX, y: affineY)
    }

    func add(_ other: ECPoint) -> ECPoint {
        if self.infinity { return other }
        if other.infinity { return self }
        return ECPoint.fromJacobian(toJacobian().addJacobian(other.toJacobian()))
    }

    func twice() -> ECPoint {
        if infinity { return self }
        return ECPoint.fromJacobian(toJacobian().twice())
    }

    func subtract(_ other: ECPoint) -> ECPoint {
        return add(other.negate())
    }

    /// [k]self，k 按秘密处理（恒定时间），点本身是公开的。
    func multiply(_ k: BigInt256) -> ECPoint {
        if infinity {
            return ECPoint.infinityPoint()
        }
        return ECPoint.fromJacobian(
            JacobianPoint.multiplyConstantTime(x: x, y: y, scalar: k, isOnCurve: isOnCurve())
        )
    }

    /// [k]self，k 必须是公开的且小于 n，点必须在曲线上（可变时间，更快）。
    func multiplyPublic(_ k: BigInt256) -> ECPoint {
        return ECPoint.fromJacobian(
            JacobianPoint.multiplyPublicPair(generatorScalar: .zero, pointScalar: k, point: toJacobian())
        )
    }

    /// [k]G，k 按秘密处理（恒定时间，使用预计算表）。
    static func multiplyGenerator(_ k: BigInt256) -> ECPoint {
        return fromJacobian(JacobianPoint.multiplyGenerator(k))
    }

    func isOnCurve() -> Bool {
        if infinity {
            return true
        }

        // y^2 = x^3 + a*x + b
        let lhs = y.square()
        let rhs = x.square().add(FpElement(unchecked: SM2Curve.a)).multiply(x).add(FpElement(unchecked: SM2Curve.b))
        return lhs == rhs
    }

    public static func == (lhs: ECPoint, rhs: ECPoint) -> Bool {
        if lhs.infinity && rhs.infinity {
            return true
        }
        if lhs.infinity || rhs.infinity {
            return false
        }
        return lhs.x == rhs.x && lhs.y == rhs.y
    }
}
