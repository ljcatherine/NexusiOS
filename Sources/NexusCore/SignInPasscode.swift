import Foundation
import Crypto

/// Second step of signing in to Nexus at auth.liamjc.dev (Keycloak's one-time code), shown under
/// Services → Nexus sign-in.
///
/// RFC 6238 TOTP. Defaults match the `nexus` realm's OTP policy: HMAC-SHA1, 6 digits, 30 s, T0 = 0.
/// Set up once from Keycloak's QR code (an `otpauth://totp/…` link) or its "Unable to scan?" key.
/// Separate from `OneTimePasscode`, the 4-digit Nexus Desktop app-lock code.
public struct SignInPasscode: Codable, Equatable, Sendable {
    public enum Algorithm: String, Codable, Sendable { case sha1 = "SHA1", sha256 = "SHA256", sha512 = "SHA512" }

    public static let keychainAccount = "nexus-sign-in-otp"
    /// Keycloak issues 20-byte secrets; refuse anything under 128 bits.
    public static let minimumSecretLength = 16

    public var secret: Data
    public var algorithm: Algorithm = .sha1
    public var digits: Int = 6
    public var period: Int = 30
    public var issuer: String = ""
    public var account: String = ""

    public init(secret: Data, algorithm: Algorithm = .sha1, digits: Int = 6, period: Int = 30, issuer: String = "", account: String = "") {
        self.secret = secret
        self.algorithm = algorithm
        self.digits = digits
        self.period = period
        self.issuer = issuer
        self.account = account
    }

    /// Accepts an `otpauth://totp/…` link or a bare base32 key (spaces, dashes and case ignored).
    /// Rejects HOTP, unknown algorithms, odd digit counts or periods, duplicate parameters and short secrets.
    public static func parse(_ text: String) -> SignInPasscode? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.lowercased().hasPrefix("otpauth:") { return fromLink(trimmed) }
        guard let secret = OneTimePasscode.decode(trimmed), secret.count >= minimumSecretLength else { return nil }
        return SignInPasscode(secret: secret)
    }

    private static func fromLink(_ text: String) -> SignInPasscode? {
        guard let parts = URLComponents(string: text), parts.scheme?.lowercased() == "otpauth",
              parts.host?.lowercased() == "totp" else { return nil }
        var query: [String: String] = [:]
        for item in parts.queryItems ?? [] {
            let name = item.name.lowercased()
            guard query[name] == nil, let value = item.value else { return nil }
            query[name] = value
        }
        guard let secretText = query["secret"], let secret = OneTimePasscode.decode(secretText),
              secret.count >= minimumSecretLength else { return nil }
        var code = SignInPasscode(secret: secret)
        if let value = query["algorithm"] {
            guard let algorithm = Algorithm(rawValue: value.uppercased()) else { return nil }
            code.algorithm = algorithm
        }
        if let value = query["digits"] {
            guard let digits = Int(value), digits == 6 || digits == 8 else { return nil }
            code.digits = digits
        }
        if let value = query["period"] {
            guard let period = Int(value), (15...120).contains(period) else { return nil }
            code.period = period
        }
        let label = parts.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let pieces = label.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
        code.issuer = String((query["issuer"] ?? (pieces.count == 2 ? pieces[0] : "")).prefix(64))
        code.account = String((pieces.last ?? "").prefix(128))
        return code
    }

    /// The code for `date`, zero-padded to `digits`.
    public func code(at date: Date) -> String {
        let step = UInt64(max(0, date.timeIntervalSince1970) / Double(period))
        var counter = step.bigEndian
        let message = withUnsafeBytes(of: &counter) { Data($0) }
        let key = SymmetricKey(data: secret)
        let mac: [UInt8]
        switch algorithm {
        case .sha1: mac = Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: key))
        case .sha256: mac = Array(HMAC<SHA256>.authenticationCode(for: message, using: key))
        case .sha512: mac = Array(HMAC<SHA512>.authenticationCode(for: message, using: key))
        }
        let offset = Int(mac[mac.count - 1] & 0x0F)
        let binary = (UInt32(mac[offset]) & 0x7F) << 24 | UInt32(mac[offset + 1]) << 16
            | UInt32(mac[offset + 2]) << 8 | UInt32(mac[offset + 3])
        var modulus: UInt32 = 1
        for _ in 0..<digits { modulus *= 10 }
        let value = String(binary % modulus)
        return String(repeating: "0", count: digits - value.count) + value
    }

    /// The code split in two for reading, for example "287 082".
    public func displayCode(at date: Date) -> String {
        let value = code(at: date)
        let middle = value.index(value.startIndex, offsetBy: value.count / 2)
        return "\(value[..<middle]) \(value[middle...])"
    }

    /// Seconds until the code changes (1...period).
    public func secondsRemaining(at date: Date) -> Int {
        let elapsed = date.timeIntervalSince1970.truncatingRemainder(dividingBy: Double(period))
        return max(1, Int((Double(period) - elapsed).rounded(.up)))
    }
}
