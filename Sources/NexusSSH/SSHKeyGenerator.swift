import Foundation
import Crypto

public struct GeneratedSSHKeyPair: Sendable, Equatable {
    /// OpenSSH private-key serialization. Keep in memory only until saved to the Keychain.
    public let privateKey: String
    /// Authorized-key line suitable for adding to a server account's `authorized_keys`.
    public let publicKey: String
}

/// Creates a local Ed25519 key pair without writing private material to the filesystem.
public enum SSHKeyGenerator {
    public static func generate(comment: String) throws -> GeneratedSSHKeyPair {
        guard !comment.isEmpty, comment.utf8.count <= 256,
              !comment.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw SSHKeyGenerationError.invalidComment
        }

        let key = Curve25519.Signing.PrivateKey()
        let publicBytes = key.publicKey.rawRepresentation
        var privateBytes = key.rawRepresentation
        privateBytes.append(publicBytes)
        let publicBlob = sshString(Data("ssh-ed25519".utf8)) + sshString(publicBytes)
        let publicLine = "ssh-ed25519 \(publicBlob.base64EncodedString()) \(comment)"

        var privateBlock = Data()
        var random = SystemRandomNumberGenerator()
        let check = UInt32.random(in: UInt32.min...UInt32.max, using: &random)
        privateBlock.appendUInt32(check)
        privateBlock.appendUInt32(check)
        privateBlock.append(sshString(Data("ssh-ed25519".utf8)))
        privateBlock.append(sshString(publicBytes))
        privateBlock.append(sshString(privateBytes))
        privateBlock.append(sshString(Data(comment.utf8)))
        let paddingCount = (8 - privateBlock.count % 8) % 8
        if paddingCount > 0 {
            privateBlock.append(contentsOf: (1...paddingCount).map(UInt8.init))
        }

        var container = Data("openssh-key-v1\0".utf8)
        container.append(sshString(Data("none".utf8)))
        container.append(sshString(Data("none".utf8)))
        container.append(sshString(Data()))
        container.appendUInt32(1)
        container.append(sshString(publicBlob))
        container.append(sshString(privateBlock))

        let encoded = container.base64EncodedString()
        let wrapped = stride(from: 0, to: encoded.count, by: 70).map { start in
            let lower = encoded.index(encoded.startIndex, offsetBy: start)
            let upper = encoded.index(lower, offsetBy: min(70, encoded.count - start))
            return String(encoded[lower..<upper])
        }.joined(separator: "\n")
        let privatePEM = "-----BEGIN OPENSSH PRIVATE KEY-----\n\(wrapped)\n-----END OPENSSH PRIVATE KEY-----\n"
        return GeneratedSSHKeyPair(privateKey: privatePEM, publicKey: publicLine)
    }
}

public enum SSHKeyGenerationError: Error, Equatable {
    case invalidComment
}

private func sshString(_ bytes: Data) -> Data {
    var result = Data()
    result.appendUInt32(UInt32(bytes.count))
    result.append(bytes)
    return result
}

private extension Data {
    mutating func appendUInt32(_ value: UInt32) {
        append(UInt8((value >> 24) & 0xff))
        append(UInt8((value >> 16) & 0xff))
        append(UInt8((value >> 8) & 0xff))
        append(UInt8(value & 0xff))
    }
}
