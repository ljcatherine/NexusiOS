import Foundation

/// Pure bounded file/text preparation. Cryptographic validation is a separate pipeline stage.
public enum SSHPrivateKeyFile {
    public static let maximumBytes = 65_536

    public static func read(_ url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var data = Data()
        while data.count <= maximumBytes {
            let remaining = maximumBytes + 1 - data.count
            guard let chunk = try handle.read(upToCount: min(4_096, remaining)), !chunk.isEmpty else { break }
            data.append(chunk)
        }
        guard data.count <= maximumBytes, let text = String(data: data, encoding: .utf8) else {
            throw SSHFailure.invalidPrivateKey
        }
        return try normalize(text)
    }

    public static func normalize(_ text: String) throws -> String {
        guard !text.isEmpty, text.utf8.count <= maximumBytes, !text.contains("\0") else {
            throw SSHFailure.invalidPrivateKey
        }
        let clean = text.replacingOccurrences(of: "\r\n", with: "\n")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let lines = clean.components(separatedBy: "\n")
        guard lines.count >= 3,
              lines.first == "-----BEGIN OPENSSH PRIVATE KEY-----",
              lines.last == "-----END OPENSSH PRIVATE KEY-----" else {
            throw SSHFailure.invalidPrivateKey
        }
        let payload = lines.dropFirst().dropLast().joined()
        guard !payload.isEmpty, Data(base64Encoded: payload) != nil else {
            throw SSHFailure.invalidPrivateKey
        }
        return clean + "\n"
    }
}
