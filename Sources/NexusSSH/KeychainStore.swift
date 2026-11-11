import Foundation
#if canImport(Security)
import Security
import NexusCore

public struct KeychainStore: SecretStore {
    private let service: String
    public init(service: String = "com.ljcatherine.Nexus.secrets") { self.service = service }
    private func query(_ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
         kSecAttrAccount as String: account, kSecAttrSynchronizable as String: false]
    }
    public func read(_ account: String) throws -> Data? {
        var query = query(account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw KeychainFailure(status: status) }
        return result as? Data
    }
    public func write(_ data: Data, account: String) throws {
        let attributes: [String: Any] = [kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
        let status = SecItemUpdate(query(account) as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            let add = query(account).merging(attributes) { _, new in new }
            let added = SecItemAdd(add as CFDictionary, nil)
            guard added == errSecSuccess else { throw KeychainFailure(status: added) }
        } else if status != errSecSuccess { throw KeychainFailure(status: status) }
    }
    public func delete(_ account: String) throws {
        let status = SecItemDelete(query(account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw KeychainFailure(status: status) }
    }
}

public struct KeychainFailure: LocalizedError {
    public let status: OSStatus
    public var errorDescription: String? { "Keychain access failed (\(status)). Unlock your device and retry." }
}
#else
import NexusCore

/// Linux builds can exercise SSH/domain logic, but never emulate secure secret storage.
public struct KeychainStore: SecretStore {
    public init(service: String = "com.ljcatherine.Nexus.secrets") {}
    public func read(_ account: String) throws -> Data? { throw KeychainFailure() }
    public func write(_ data: Data, account: String) throws { throw KeychainFailure() }
    public func delete(_ account: String) throws { throw KeychainFailure() }
}

public struct KeychainFailure: LocalizedError {
    public init() {}
    public var errorDescription: String? { "Keychain storage is only available on Apple platforms." }
}
#endif
