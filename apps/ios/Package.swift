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
    dependencies: [
        .package(url: "https://github.com/signalapp/libsignal-client", exact: "0.58.1"),
    ],
    targets: [
        .target(
            name: "OlloCrypto",
            dependencies: [
                .product(name: "LibSignalClient", package: "libsignal-client"),
            ]
        ),
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
