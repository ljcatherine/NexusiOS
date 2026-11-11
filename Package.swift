// swift-tools-version: 5.9
import PackageDescription

// Only the explicitly selected simulator-preview script enables this alternate entry point.
let nexusDemoMode = Context.environment["NEXUS_DEMO_MODE"] == "1"
let nexusAppSwiftSettings: [SwiftSetting] = nexusDemoMode ? [.define("NEXUS_DEMO_MODE")] : []

let package = Package(
    name: "NexusKit",
    platforms: [.iOS(.v17), .macOS("15.0")],
    products: [
        .library(name: "NexusCore", targets: ["NexusCore"]),
        .library(name: "NexusSSH", targets: ["NexusSSH"]),
        .library(name: "Nexus", targets: ["NexusApp"])
    ],
    dependencies: [
        .package(path: "Vendor/Citadel"),
        .package(url: "https://github.com/apple/swift-nio.git", exact: "2.103.0"),
        .package(url: "https://github.com/apple/swift-nio-ssl.git", exact: "2.37.0"),
        .package(path: "Vendor/swift-nio-ssh"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.12.3"),
        .package(path: "Vendor/ZIPFoundation"),
        .package(path: "Vendor/SwiftTerm"),
        .package(url: "https://github.com/exyte/Grid.git", exact: "1.5.4"),
        // Tag 3.1.0 is an annotated tag; pinned commit works around SwiftPM's tag-resolution failure on Linux.
        .package(url: "https://github.com/exyte/ScalingHeaderScrollView.git", revision: "f328af2bcfda8308aa9564dac47babdf01ef7947"),
        .package(url: "https://github.com/Cindori/FluidGradient.git", exact: "1.0.0"),
        .package(url: "https://github.com/markiv/SwiftUI-Shimmer.git", exact: "1.5.1"),
        .package(url: "https://github.com/exyte/AnimatedTabBar.git", exact: "1.0.1")
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
        .target(name: "NexusApp", dependencies: ["NexusCore", "NexusSSH", "SwiftTerm",
            .product(name: "ExyteGrid", package: "Grid"),
            .product(name: "ScalingHeaderScrollView", package: "ScalingHeaderScrollView"),
            .product(name: "FluidGradient", package: "FluidGradient"),
            .product(name: "Shimmer", package: "SwiftUI-Shimmer"),
            .product(name: "AnimatedTabBar", package: "AnimatedTabBar")],
            path: "App", exclude: ["Assets.xcassets", "PrivacyInfo.xcprivacy"],
            swiftSettings: nexusAppSwiftSettings,
            linkerSettings: [.unsafeFlags(["-Xlinker", "-all_load"], .when(platforms: [.iOS]))]),
        .testTarget(name: "NexusCoreTests", dependencies: ["NexusCore",
            .product(name: "ZIPFoundation", package: "ZIPFoundation")]),
        .testTarget(name: "NexusSSHTests", dependencies: ["NexusSSH", "NexusCore",
            .product(name: "NIO", package: "swift-nio"),
            .product(name: "NIOEmbedded", package: "swift-nio"),
            .product(name: "NIOSSH", package: "swift-nio-ssh"),
            .product(name: "Crypto", package: "swift-crypto")])
    ]
)
