// swift-tools-version:5.10
// Source snapshot: Wellz26/swift-nio-ssh 0.3.4, b93961a2988607a756cbc21a811f406f27aa9ab6.
// Apache-2.0. Nexus builds only the library; see ../NEXUS-PATCHES.md.
import PackageDescription

let package = Package(
    name: "swift-nio-ssh",
    platforms: [.macOS(.v10_15), .iOS(.v13), .watchOS(.v6), .tvOS(.v13)],
    products: [.library(name: "NIOSSH", targets: ["NIOSSH"])],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.81.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", "1.0.0"..<"4.0.0"),
        .package(url: "https://github.com/apple/swift-atomics.git", from: "1.0.2")
    ],
    targets: [
        .target(name: "NIOSSH", dependencies: [
            .product(name: "NIOCore", package: "swift-nio"),
            .product(name: "NIOConcurrencyHelpers", package: "swift-nio"),
            .product(name: "NIOFoundationCompat", package: "swift-nio"),
            .product(name: "Crypto", package: "swift-crypto"),
            .product(name: "Atomics", package: "swift-atomics")
        ], swiftSettings: [
            .enableUpcomingFeature("StrictConcurrency"),
            .enableUpcomingFeature("InferSendableFromCaptures"),
            .enableUpcomingFeature("MemberImportVisibility")
        ])
    ]
)
