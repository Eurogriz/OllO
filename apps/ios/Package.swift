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
        .target(name: "OlloNetwork"),
        .target(name: "OlloStorage"),
        .testTarget(name: "OlloCryptoTests", dependencies: ["OlloCrypto"]),
    ]
)
