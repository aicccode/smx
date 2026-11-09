// swift-tools-version:5.7
import PackageDescription

let package = Package(
    name: "GMSwift",
    platforms: [
        .iOS(.v15), .macOS(.v10_13),
    ],
    products: [
        .library(name: "GMSwift", targets: ["GMSwift"])
    ],
    targets: [
        .target(
            name: "GMSwift",
            path: "Sources/GMSwift",
            sources: [
                "Hex.swift", "SM2.swift", "SM2BigInt.swift", "SM2ECPoint.swift", "SM2Field.swift", "SM2Point.swift",
                "SM2Scalar.swift", "SM3.swift", "SM3Compress.swift", "SM4.swift", "SM9.swift", "SM9Curve.swift",
                "SM9Field.swift", "SM9KeyExchange.swift", "SM9Pairing.swift", "SM9Support.swift", "SM9Tower.swift",
            ],
            publicHeadersPath: ""
        ),
        .testTarget(
            name: "GMSwiftTests",
            dependencies: ["GMSwift"],
            path: "Tests/GMSwiftTests"
        ),
    ]
)
