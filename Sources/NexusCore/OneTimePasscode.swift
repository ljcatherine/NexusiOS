import Foundation
import Crypto

/// Unlock code for Nexus Desktop (Windows), shown under Services → One Time Passcode.
///
/// RFC 6238 TOTP: HMAC-SHA1, 20-second period, T0 = 0, 4 digits. The shared
/// secret is 10 random bytes that Nexus Desktop generates and shows as 16
/// base32 characters (`XXXX-XXXX-XXXX-XXXX`); the owner types it here once.
/// Spec: docs/OTP.md (mirrored in the NexusWindows repo).
public enum OneTimePasscode {
    public static let period: TimeInterval = 20
    public static let digits = 4
    public static let secretLength = 10
    public static let keychainAccount = "nexus-desktop-otp-secret"
    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

    /// Decodes base32, ignoring case, spaces, dashes and `=` padding.
    public static func decode(_ text: String) -> Data? {
        var out = Data()
        var buffer: UInt32 = 0
        var bits = 0
        for character in text.uppercased() where !" -=".contains(character) {
            guard let value = alphabet.firstIndex(of: character) else { return nil }
            buffer = (buffer << 5) | UInt32(value)
            bits += 5
            if bits >= 8 {
                out.append(UInt8((buffer >> UInt32(bits - 8)) & 0xFF))
                bits -= 8
            }
        }
        return out.isEmpty ? nil : out
    }

    public static func encode(_ data: Data) -> String {
        var out = ""
        var buffer: UInt32 = 0
        var bits = 0
        for byte in data {
            buffer = (buffer << 8) | UInt32(byte)
            bits += 8
            while bits >= 5 {
                out.append(alphabet[Int((buffer >> UInt32(bits - 5)) & 31)])
                bits -= 5
            }
        }
        if bits > 0 { out.append(alphabet[Int((buffer << UInt32(5 - bits)) & 31)]) }
        return out
    }

    /// The pairing key as Nexus Desktop shows it, or nil when it is not exactly 10 bytes of base32.
    public static func pairingSecret(_ text: String) -> Data? {
        guard let data = decode(text), data.count == secretLength else { return nil }
        return data
    }

    public static func code(secret: Data, at date: Date) -> Int {
        let step = UInt64(max(0, date.timeIntervalSince1970) / period)
        var counter = step.bigEndian
        let message = withUnsafeBytes(of: &counter) { Data($0) }
        let mac = Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: SymmetricKey(data: secret)))
        let offset = Int(mac[19] & 0x0F)
        let binary = (UInt32(mac[offset]) & 0x7F) << 24 | UInt32(mac[offset + 1]) << 16
            | UInt32(mac[offset + 2]) << 8 | UInt32(mac[offset + 3])
        return Int(binary % 10_000)
    }

    /// Code as four digits with leading zeros.
    public static func formatted(secret: Data, at date: Date) -> String {
        let value = String(code(secret: secret, at: date))
        return String(repeating: "0", count: digits - value.count) + value
    }

    /// Seconds until the code changes (1...20).
    public static func secondsRemaining(at date: Date) -> Int {
        let elapsed = date.timeIntervalSince1970.truncatingRemainder(dividingBy: period)
        return max(1, Int((period - elapsed).rounded(.up)))
    }
}
