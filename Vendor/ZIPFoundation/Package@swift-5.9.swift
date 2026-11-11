// swift-tools-version:5.9
import PackageDescription

#if canImport(Compression)
let targets: [Target] = [
    .target(name: "ZIPFoundation", resources: [.copy("Resources/PrivacyInfo.xcprivacy")])
]
#else
let targets: [Target] = [
    .systemLibrary(name: "CZLib", pkgConfig: "zlib", providers: [.brew(["zlib"]), .apt(["zlib"])]),
    .target(name: "ZIPFoundation", dependencies: ["CZLib"], cSettings: [.define("_GNU_SOURCE", to: "1")])
]
#endif

let package = Package(
    name: "ZIPFoundation",
    platforms: [.iOS(.v12), .macOS(.v10_13), .tvOS(.v12), .watchOS(.v4), .visionOS(.v1)],
    products: [.library(name: "ZIPFoundation", targets: ["ZIPFoundation"])],
    targets: targets,
    swiftLanguageVersions: [.v5]
)
