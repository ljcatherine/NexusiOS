import XCTest
@testable import NexusCore

final class OneTimePasscodeTests: XCTestCase {
    // Reference vectors from an independent Python hmac/hashlib implementation;
    // Nexus Desktop's Rust tests use the same ones.
    private let secret = Data("1234567890".utf8)

    func testMatchesReferenceVectors() {
        XCTAssertEqual(OneTimePasscode.encode(secret), "GEZDGNBVGY3TQOJQ")
        for (time, expected) in [(0.0, "1490"), (59, "2045"), (1_111_111_109, "3293"), (2_000_000_000, "8631")] {
            XCTAssertEqual(OneTimePasscode.formatted(secret: secret, at: Date(timeIntervalSince1970: time)), expected, "t=\(time)")
        }
    }

    func testCodeChangesEveryTwentySeconds() {
        let start = Date(timeIntervalSince1970: 1_111_111_100)
        let code = OneTimePasscode.code(secret: secret, at: start)
        XCTAssertEqual(OneTimePasscode.code(secret: secret, at: start.addingTimeInterval(19)), code)
        XCTAssertEqual(OneTimePasscode.secondsRemaining(at: start), 20)
        XCTAssertEqual(OneTimePasscode.secondsRemaining(at: start.addingTimeInterval(19.5)), 1)
    }

    func testPairingKeyParsing() {
        XCTAssertEqual(OneTimePasscode.pairingSecret("gezd-gnbv-gy3t-qojq"), secret)
        XCTAssertEqual(OneTimePasscode.pairingSecret("GEZD GNBV GY3T QOJQ"), secret)
        XCTAssertNil(OneTimePasscode.pairingSecret("GEZDGNBV"))
        XCTAssertNil(OneTimePasscode.pairingSecret("GEZD-GNBV-GY3T-QOJ1"))
        XCTAssertEqual(OneTimePasscode.decode(OneTimePasscode.encode(Data([0, 255, 7, 9, 200]))), Data([0, 255, 7, 9, 200]))
    }
}
