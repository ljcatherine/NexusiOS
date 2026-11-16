import XCTest
@testable import NexusCore

final class SignInPasscodeTests: XCTestCase {
    // RFC 6238 Appendix B seeds and 8-digit vectors, re-checked with Python hmac/hashlib.
    private let sha1Seed = Data("12345678901234567890".utf8)
    private let sha256Seed = Data("12345678901234567890123456789012".utf8)
    private let sha512Seed = Data("1234567890123456789012345678901234567890123456789012345678901234".utf8)

    func testMatchesRFC6238Vectors() {
        let vectors: [(TimeInterval, String, String, String)] = [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ]
        for (time, sha1, sha256, sha512) in vectors {
            let date = Date(timeIntervalSince1970: time)
            XCTAssertEqual(SignInPasscode(secret: sha1Seed, digits: 8).code(at: date), sha1, "SHA1 t=\(time)")
            XCTAssertEqual(SignInPasscode(secret: sha256Seed, algorithm: .sha256, digits: 8).code(at: date), sha256, "SHA256 t=\(time)")
            XCTAssertEqual(SignInPasscode(secret: sha512Seed, algorithm: .sha512, digits: 8).code(at: date), sha512, "SHA512 t=\(time)")
        }
    }

    func testDefaultsMatchKeycloakSixDigitsThirtySeconds() {
        let code = SignInPasscode(secret: sha1Seed)
        XCTAssertEqual(code.code(at: Date(timeIntervalSince1970: 59)), "287082")
        XCTAssertEqual(code.code(at: Date(timeIntervalSince1970: 1_111_111_109)), "081804")
        XCTAssertEqual(code.displayCode(at: Date(timeIntervalSince1970: 59)), "287 082")
        let start = Date(timeIntervalSince1970: 1_111_111_110)
        XCTAssertEqual(code.code(at: start.addingTimeInterval(29)), code.code(at: start))
        XCTAssertEqual(code.secondsRemaining(at: start), 30)
        XCTAssertEqual(code.secondsRemaining(at: start.addingTimeInterval(29.5)), 1)
    }

    func testParsesKeycloakLink() {
        let key = OneTimePasscode.encode(sha1Seed)
        let parsed = SignInPasscode.parse("otpauth://totp/nexus:liam%40liamjc.dev?secret=\(key)&digits=6&algorithm=SHA1&issuer=Nexus&period=30")
        XCTAssertEqual(parsed?.secret, sha1Seed)
        XCTAssertEqual(parsed?.issuer, "Nexus")
        XCTAssertEqual(parsed?.account, "liam@liamjc.dev")
        XCTAssertEqual(parsed?.digits, 6)
        XCTAssertEqual(SignInPasscode.parse("otpauth://totp/x?secret=\(key)&algorithm=sha256&digits=8&period=60")?.algorithm, .sha256)
    }

    func testParsesBareKeyAsKeycloakDefaults() {
        let spaced = OneTimePasscode.encode(sha1Seed).lowercased().enumerated()
            .map { $0.offset > 0 && $0.offset % 4 == 0 ? " \($0.element)" : "\($0.element)" }.joined()
        let parsed = SignInPasscode.parse("  \(spaced)  ")
        XCTAssertEqual(parsed, SignInPasscode(secret: sha1Seed))
    }

    func testRejectsUnsafeOrUnknownInput() {
        let key = OneTimePasscode.encode(sha1Seed)
        for bad in [
            "otpauth://hotp/x?secret=\(key)&counter=1",
            "otpauth://totp/x?secret=\(key)&algorithm=MD5",
            "otpauth://totp/x?secret=\(key)&digits=4",
            "otpauth://totp/x?secret=\(key)&period=1",
            "otpauth://totp/x?secret=\(key)&secret=AAAAAAAAAAAAAAAAAAAAAAAAAA",
            "otpauth://totp/x?digits=6",
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ",   // 10 bytes: below 128 bits
            "https://example.com/?secret=\(key)",
            "GEZD-GNBV-GY3T-QOJQ",                         // the Desktop pairing key is too short
            "not base32 !!",
            "",
        ] {
            XCTAssertNil(SignInPasscode.parse(bad), bad)
        }
    }

    func testSurvivesKeychainRoundTrip() throws {
        let original = SignInPasscode(secret: sha256Seed, algorithm: .sha256, issuer: "Nexus", account: "liam@liamjc.dev")
        let decoded = try JSONDecoder().decode(SignInPasscode.self, from: JSONEncoder().encode(original))
        XCTAssertEqual(decoded, original)
    }
}
