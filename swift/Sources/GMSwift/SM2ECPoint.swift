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

    public static func fromHex(xHex: String, yHex: String) -> ECPoint {
        return ECPoint(x: FpElement.fromHex(xHex), y: FpElement.fromHex(yHex))
    }

    public static func fromEncoded(_ data: [UInt8]) -> ECPoint {
        if data.isEmpty {
            return ECPoint.infinityPoint()
        }
        if data[0] != 0x04 {
            fatalError("Only uncompressed point format is supported")
        }
        if data.count != 65 {
            fatalError("Invalid point encoding length")
        }
        return data.withUnsafeBufferPointer { buffer -> ECPoint in
            guard let base = buffer.baseAddress else {
                return ECPoint.infinityPoint()
            }
            return ECPoint(
                x: FpElement(BigInt256.fromBEPointer(base + 1)),
                y: FpElement(BigInt256.fromBEPointer(base + 33))
            )
        }
    }

    public static func fromHexEncoded(_ hex: String) -> ECPoint {
        if let bytes = Hex.decodeStrict(hex) {
            return fromEncoded(bytes)
        }
        // 非常规输入：保持既有的宽松解析（前缀 0x、跳过无法解析的两字符片段）
        var hexStr = hex
        if hexStr.hasPrefix("0x") || hexStr.hasPrefix("0X") {
            hexStr = String(hexStr.dropFirst(2))
        }
        var bytes = [UInt8]()
        var index = hexStr.startIndex
        while index < hexStr.endIndex {
            let nextIndex = hexStr.index(index, offsetBy: 2, limitedBy: hexStr.endIndex) ?? hexStr.endIndex
            if let byte = UInt8(hexStr[index..<nextIndex], radix: 16) {
                bytes.append(byte)
            }
            index = nextIndex
        }
        return fromEncoded(bytes)
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
