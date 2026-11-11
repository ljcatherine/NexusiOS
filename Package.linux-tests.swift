// swift-tools-version: 5.9
// Linux-only test manifest. The production Package.swift retains the SwiftUI app target.
// Sources and Tests are symlinked from the repository by prepare-linux-swift-tests.sh.
import PackageDescription

let package = Package(
    name: "NexusLinuxTests",
    platforms: [.macOS("15.0")],
    products: [
        .library(name: "NexusCore", targets: ["NexusCore"]),
        .library(name: "NexusSSH", targets: ["NexusSSH"])
    ],
    dependencies: [
        .package(path: "../../Vendor/Citadel"),
        .package(url: "https://github.com/apple/swift-nio.git", exact: "2.103.0"),
        .package(url: "https://github.com/apple/swift-nio-ssl.git", exact: "2.37.0"),
        .package(path: "../../Vendor/swift-nio-ssh"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.12.3"),
        .package(path: "../../Vendor/ZIPFoundation")
    ],
    targets: [
        .target(name: "NexusCore", dependencies: [
            .product(name: "Crypto", package: "swift-crypto"),
            .product(name: "ZIPFoundation", package: "ZIPFoundation")
        ]),
        .target(name: "NexusSSH", dependencies: ["NexusCore", "Citadel",
            .product(name: "NIO", package: "swift-nio"),
            .product(name: "NIOHTTP1", package: "swift-nio"),
            .product(name: "NIOWebSocket", package: "swift-nio"),
            .product(name: "NIOSSH", package: "swift-nio-ssh"),
            .product(name: "NIOSSL", package: "swift-nio-ssl"),
            .product(name: "Crypto", package: "swift-crypto")]),
        .testTarget(name: "NexusCoreTests", dependencies: ["NexusCore",
            .product(name: "ZIPFoundation", package: "ZIPFoundation")]),
        .testTarget(name: "NexusSSHTests", dependencies: ["NexusSSH", "NexusCore",
            .product(name: "NIO", package: "swift-nio"),
            .product(name: "NIOEmbedded", package: "swift-nio"),
            .product(name: "NIOSSH", package: "swift-nio-ssh"),
            .product(name: "Crypto", package: "swift-crypto")])
    ]
)
