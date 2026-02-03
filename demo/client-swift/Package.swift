// swift-tools-version:5.7
import PackageDescription

let package = Package(
    name: "SM2Demo",
    platforms: [
        .macOS(.v10_15)
    ],
    dependencies: [
        .package(path: "../../swift")
    ],
    targets: [
        .executableTarget(
            name: "SM2Demo",
            dependencies: [
                .product(name: "GMSwift", package: "swift")
            ],
            path: "Sources/SM2Demo"
        )
    ]
)
