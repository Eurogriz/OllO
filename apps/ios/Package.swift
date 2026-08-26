// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "OlloCore",
    platforms: [.iOS(.v16)],
    products: [
        .library(name: "OlloCrypto", targets: ["OlloCrypto"]),
        .library(name: "OlloNetwork", targets: ["OlloNetwork"]),
        .library(name: "OlloStorage", targets: ["OlloStorage"]),
    ],
    targets: [
        .target(name: "OlloCrypto"),
        .target(name: "OlloNetwork", dependencies: ["OlloCrypto"]),
        .target(name: "OlloStorage", dependencies: ["OlloCrypto"]),
        .testTarget(
            name: "OlloCryptoTests",
            dependencies: ["OlloCrypto"],
            path: "Sources/OlloCryptoTests"
        ),
        .testTarget(
            name: "OlloNetworkTests",
            dependencies: ["OlloNetwork", "OlloCrypto"],
            path: "Sources/OlloNetworkTests"
        ),
    ]
)
