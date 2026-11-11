import Foundation
import Crypto
import Citadel
import NIO
import NIOSSH
import NexusCore

public struct RemoteFileEntry: Identifiable, Sendable {
    public var id: String { path }
    public let name: String
    public let path: String
    public let isDirectory: Bool
    public let isSymbolicLink: Bool
    public let resolvedTargetPath: String?
    public let size: UInt64?
    public let modifiedAt: Date?
    public let permissions: UInt32?

    public var operationPath: String { resolvedTargetPath ?? path }
}

public struct SFTPDirectoryTransferSummary: Sendable {
    public let filesTransferred: Int
    public let directoriesCreated: Int
    public let skippedItems: Int
}

private struct SFTPDirectoryWalk: Sendable {
    var files = 0
    var directories = 0
    var skipped = 0
    var visited = 0

    mutating func add(_ other: Self) {
        files += other.files
        directories += other.directories
        skipped += other.skipped
        visited += other.visited
    }

    var publicSummary: SFTPDirectoryTransferSummary {
        SFTPDirectoryTransferSummary(filesTransferred: files,
            directoriesCreated: directories, skippedItems: skipped)
    }
}

/// Owns one strictly verified SSH connection and its SFTP subsystem.
public actor SFTPTransport {
    private var client: SSHClient?
    private var sftp: SFTPClient?
    private var deviceID: UUID?
    private var endpointAuthority: String?
    private var generation = UUID()

    private let pipeline: SSHConnectionPipeline
    public init(pipeline: SSHConnectionPipeline = .shared) { self.pipeline = pipeline }

    public func connect(device: Device, endpoint: Endpoint, secrets: any SecretStore,
                        timeout: Int) async throws {
        try device.validate(); try endpoint.validate()
        if client != nil, deviceID == device.id, endpointAuthority == endpoint.authority,
           sftp?.isActive == true { return }
        await disconnect()

        let attempt = UUID(); generation = attempt
        let connected = try await pipeline.connect(device: device, endpoint: endpoint,
            secrets: secrets, timeout: timeout)
        guard generation == attempt, !Task.isCancelled else {
            try? await connected.close()
            throw CancellationError()
        }
        do {
            let subsystem = try await connected.openSFTP()
            guard generation == attempt, !Task.isCancelled else {
                try? await subsystem.close()
                try? await connected.close()
                throw CancellationError()
            }
            client = connected
            sftp = subsystem
            deviceID = device.id
            endpointAuthority = endpoint.authority
        } catch {
            try? await connected.close()
            if Task.isCancelled { throw CancellationError() }
            throw error
        }
    }

    public func listDirectory(at path: String) async throws -> [RemoteFileEntry] {
        guard let sftp, sftp.isActive else { throw SSHFailure.notConnected }
        let resolved = try await sftp.getRealPath(atPath: path)
        let names = try await sftp.listDirectory(atPath: resolved)
        var entries: [RemoteFileEntry] = []
        for item in names {
            for component in item.components {
                let name = component.filename
                guard name != ".", name != "..", !name.isEmpty,
                      !name.contains("/"), !name.contains("\0") else { continue }
                let fullPath = resolved == "/" ? "/\(name)" : "\(resolved)/\(name)"
                let mode = component.attributes.permissions
                let entryType = mode.map { $0 & 0o170000 }
                let isSymbolicLink = entryType.map { $0 == 0o120000 }
                    ?? component.longname.first.map { $0 == "l" } ?? false
                var directory = entryType.map { $0 == 0o040000 }
                    ?? component.longname.first.map { $0 == "d" } ?? false
                var resolvedTargetPath: String?
                if isSymbolicLink, let target = try? await sftp.getRealPath(atPath: fullPath) {
                    resolvedTargetPath = target
                    if let targetAttributes = try? await sftp.getAttributes(at: target),
                       let targetPermissions = targetAttributes.permissions {
                        directory = (targetPermissions & 0o170000) == 0o040000
                    }
                }
                entries.append(RemoteFileEntry(name: name, path: fullPath,
                    isDirectory: directory, isSymbolicLink: isSymbolicLink,
                    resolvedTargetPath: resolvedTargetPath,
                    size: component.attributes.size,
                    modifiedAt: component.attributes.accessModificationTime?.modificationTime,
                    permissions: component.attributes.permissions))
            }
        }
        return entries.sorted {
            if $0.isDirectory != $1.isDirectory { return $0.isDirectory }
            return $0.name.localizedStandardCompare($1.name) == .orderedAscending
        }
    }

    /// Creates a single directory at the requested path. The caller must resolve conflicts
    /// before invoking this operation; parent directories are never created implicitly.
    public func createDirectory(at path: String) async throws {
        guard let sftp, sftp.isActive else { throw SSHFailure.notConnected }
        try validateRemotePathComponent((path as NSString).lastPathComponent)
        guard try await attributesIfPresent(at: path, using: sftp) == nil else {
            throw SFTPTransportError.remotePathAlreadyExists
        }
        try await sftp.createDirectory(atPath: path)
    }

    /// Changes only ordinary rwx bits on a regular file or directory. File type and existing
    /// special mode bits are preserved; symbolic links and unknown types fail closed.
    public func setPermissions(at path: String, accessMode: UInt32) async throws {
        guard let sftp, sftp.isActive else { throw SSHFailure.notConnected }
        guard accessMode <= 0o777 else { throw SFTPTransportError.invalidPermissionMode }
        guard !(try await isSymbolicLink(at: path, using: sftp)) else {
            throw SFTPTransportError.symbolicLinkTarget
        }
        guard let current = try await attributesIfPresent(at: path, using: sftp),
              let currentMode = current.permissions else {
            throw SFTPTransportError.fileTypeUnavailable
        }
        let fileType = currentMode & 0o170000
        guard fileType == 0o100000 || fileType == 0o040000 else {
            throw SFTPTransportError.fileTypeUnavailable
        }
        var updated = SFTPFileAttributes.none
        updated.permissions = (currentMode & ~UInt32(0o777)) | accessMode
        try await sftp.setAttributes(at: path, to: updated)
        guard let result = try await attributesIfPresent(at: path, using: sftp),
              let resultMode = result.permissions,
              resultMode & 0o777 == accessMode else {
            throw SFTPTransportError.permissionUpdateNotApplied
        }
    }

    /// Renames one entry without intentionally replacing a known destination.
    public func rename(at sourcePath: String, to newName: String) async throws {
        guard let sftp, sftp.isActive else { throw SSHFailure.notConnected }
        try validateRemotePathComponent(newName)
        let parent = (sourcePath as NSString).deletingLastPathComponent
        let destinationParent = parent.isEmpty ? "." : parent
        let destination = (destinationParent as NSString).appendingPathComponent(newName)
        let siblings = try await sftp.listDirectory(atPath: destinationParent)
        let exists = siblings.lazy.flatMap(\.components).contains { $0.filename == newName }
        guard !exists else { throw SFTPTransportError.remotePathAlreadyExists }
        try await sftp.rename(at: sourcePath, to: destination)
    }

    /// Deletes a file or symlink, or removes an empty directory. Never follows a symlink
    /// and never recursively removes directory contents.
    public func delete(_ entry: RemoteFileEntry) async throws {
        guard let sftp, sftp.isActive else { throw SSHFailure.notConnected }
        guard entry.path != "/", entry.path != ".", entry.path != ".." else {
            throw SFTPTransportError.invalidRemoteName
        }
        if entry.isDirectory && !entry.isSymbolicLink {
            try await sftp.rmdir(at: entry.path)
        } else {
            try await sftp.remove(at: entry.path)
        }
    }

    public func resolvePath(_ path: String) async throws -> String {
        guard let sftp, sftp.isActive else { throw SSHFailure.notConnected }
        return try await sftp.getRealPath(atPath: path)
    }

    /// Streams a remote file to a caller-selected local URL using bounded memory.
    public func download(remotePath: String, to localURL: URL,
                         progress: @escaping @Sendable (UInt64, UInt64?) async -> Void = { _, _ in }) async throws {
        guard let sftp, sftp.isActive else { throw SSHFailure.notConnected }
        guard FileManager.default.createFile(atPath: localURL.path, contents: nil) else {
            throw CocoaError(.fileWriteUnknown)
        }
        do {
            #if os(iOS)
            try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete],
                ofItemAtPath: localURL.path)
            #endif
            let handle = try FileHandle(forWritingTo: localURL)
            defer { try? handle.close() }
            try await sftp.withFile(filePath: remotePath, flags: .read) { file in
                let size = try await file.readAttributes().size
                var offset: UInt64 = 0
                while true {
                    try Task.checkCancellation()
                    let buffer = try await file.read(from: offset, length: 128 * 1024)
                    let count = buffer.readableBytes
                    guard count > 0 else { break }
                    try handle.write(contentsOf: Data(buffer.readableBytesView))
                    offset += UInt64(count)
                    await progress(offset, size)
                }
                if let size, offset != size { throw SFTPTransportError.remoteFileChanged }
            }
            try Task.checkCancellation()
        } catch {
            try? FileManager.default.removeItem(at: localURL)
            throw error
        }
    }

    /// Downloads a new remote directory tree. Symbolic links and special files are skipped;
    /// recursion and entry counts are bounded. On failure the partial local tree is removed.
    public func downloadDirectory(remotePath: String, to localURL: URL,
                                  progress: @escaping @Sendable (String, UInt64, UInt64?) async -> Void = { _, _, _ in }) async throws -> SFTPDirectoryTransferSummary {
        guard let sftp, sftp.isActive else { throw SSHFailure.notConnected }
        guard !FileManager.default.fileExists(atPath: localURL.path) else {
            throw CocoaError(.fileWriteFileExists)
        }
        let resolvedPath = try await sftp.getRealPath(atPath: remotePath)
        let rootAttributes = try await sftp.getAttributes(at: resolvedPath)
        guard let rootPermissions = rootAttributes.permissions else {
            throw SFTPTransportError.fileTypeUnavailable
        }
        guard rootPermissions & 0o170000 == 0o040000 else {
            throw SFTPTransportError.remotePathNotDirectory
        }
        try createProtectedDirectory(at: localURL)
        do {
            try Task.checkCancellation()
            let result = try await downloadDirectoryContents(remotePath: resolvedPath,
                localURL: localURL, relativePath: "", depth: 0, remainingItems: 10_000,
                using: sftp, progress: progress)
            return result.publicSummary
        } catch {
            try? FileManager.default.removeItem(at: localURL)
            throw error
        }
    }

    /// Streams a local file. Existing remote files require an explicit overwrite decision.
    public func upload(localURL: URL, to remotePath: String, overwrite: Bool,
                       expectedExistingSize: UInt64? = nil,
                       expectedExistingModifiedAt: Date? = nil,
                       progress: @escaping @Sendable (UInt64, UInt64?) async -> Void = { _, _ in }) async throws {
        guard let sftp, sftp.isActive else { throw SSHFailure.notConnected }
        let destinationIsSymbolicLink = try await isSymbolicLink(at: remotePath, using: sftp)
        guard !destinationIsSymbolicLink else {
            throw SFTPTransportError.symbolicLinkTarget
        }
        let initialTarget = try await attributesIfPresent(at: remotePath, using: sftp)
        if overwrite {
            try verifyOverwriteTarget(initialTarget, size: expectedExistingSize,
                modifiedAt: expectedExistingModifiedAt)
        } else if initialTarget != nil {
            throw SFTPTransportError.remotePathAlreadyExists
        }
        let values = try localURL.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey])
        guard values.isRegularFile == true, let fileSize = values.fileSize, fileSize >= 0 else {
            throw CocoaError(.fileReadUnsupportedScheme)
        }
        let transferPath = temporarySiblingPath(for: remotePath, marker: "upload")
        var creationAttributes = SFTPFileAttributes.none
        if overwrite { creationAttributes.permissions = initialTarget?.permissions }
        let input = try FileHandle(forReadingFrom: localURL)
        defer { try? input.close() }
        do {
            try await sftp.withFile(filePath: transferPath, flags: [.write, .create, .forceCreate],
                                    attributes: creationAttributes) { remoteFile in
                var offset: UInt64 = 0
                var transferHasher = SHA256()
                while true {
                    try Task.checkCancellation()
                    guard let bytes = try input.read(upToCount: 128 * 1024), !bytes.isEmpty else { break }
                    transferHasher.update(data: bytes)
                    try await remoteFile.write(ByteBuffer(bytes: bytes), at: offset)
                    offset += UInt64(bytes.count)
                    await progress(offset, UInt64(fileSize))
                }
                guard offset == UInt64(fileSize) else { throw SFTPTransportError.localFileChanged }

                let uploadedDigest = transferHasher.finalize()
                try input.seek(toOffset: 0)
                var verificationHasher = SHA256()
                var verificationOffset: UInt64 = 0
                while true {
                    try Task.checkCancellation()
                    guard let bytes = try input.read(upToCount: 128 * 1024), !bytes.isEmpty else { break }
                    verificationHasher.update(data: bytes)
                    verificationOffset += UInt64(bytes.count)
                }
                guard verificationOffset == UInt64(fileSize),
                      Data(verificationHasher.finalize()) == Data(uploadedDigest) else {
                    throw SFTPTransportError.localFileChanged
                }
            }
            try Task.checkCancellation()
            var backupPath: String?
            if overwrite {
                backupPath = try await replaceExistingFile(at: remotePath, with: transferPath,
                    expectedSize: expectedExistingSize, expectedModifiedAt: expectedExistingModifiedAt,
                    using: sftp)
            } else {
                let destinationIsSymbolicLink = try await isSymbolicLink(at: remotePath, using: sftp)
                guard !destinationIsSymbolicLink else {
                    throw SFTPTransportError.symbolicLinkTarget
                }
                guard try await attributesIfPresent(at: remotePath, using: sftp) == nil else {
                    throw SFTPTransportError.remotePathAlreadyExists
                }
                try await sftp.rename(at: transferPath, to: remotePath)
            }
            if let backupPath { try? await sftp.remove(at: backupPath) }
        } catch {
            try? await sftp.remove(at: transferPath)
            throw error
        }
    }

    /// Uploads a local directory as a new remote tree. Existing destinations are never
    /// overwritten. Symbolic links and special files are skipped. A failed/cancelled upload
    /// can leave already completed remote items in place; the caller must report that path.
    public func uploadDirectory(localURL: URL, to remotePath: String,
                                progress: @escaping @Sendable (String, UInt64, UInt64?) async -> Void = { _, _, _ in }) async throws -> SFTPDirectoryTransferSummary {
        guard let sftp, sftp.isActive else { throw SSHFailure.notConnected }
        let values = try localURL.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
        guard values.isDirectory == true, values.isSymbolicLink != true else {
            throw SFTPTransportError.localPathNotDirectory
        }
        try validateRemotePathComponent((remotePath as NSString).lastPathComponent)
        let destinationIsSymbolicLink = try await isSymbolicLink(at: remotePath, using: sftp)
        let destinationAttributes = try await attributesIfPresent(at: remotePath, using: sftp)
        guard !destinationIsSymbolicLink, destinationAttributes == nil else {
            throw SFTPTransportError.remotePathAlreadyExists
        }
        try await sftp.createDirectory(atPath: remotePath)
        try Task.checkCancellation()
        let result = try await uploadDirectoryContents(localURL: localURL,
            remotePath: remotePath, relativePath: "", depth: 0, remainingItems: 10_000,
            using: sftp, progress: progress)
        return result.publicSummary
    }

    private func uploadDirectoryContents(localURL: URL, remotePath: String, relativePath: String, depth: Int,
        remainingItems: Int, using sftp: SFTPClient,
        progress: @escaping @Sendable (String, UInt64, UInt64?) async -> Void) async throws -> SFTPDirectoryWalk {
        guard depth <= 64 else { throw SFTPTransportError.directoryDepthLimit }
        let children = try FileManager.default.contentsOfDirectory(at: localURL,
            includingPropertiesForKeys: [.isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey])
        var result = SFTPDirectoryWalk()
        for child in children {
            try Task.checkCancellation()
            guard result.visited < remainingItems else { throw SFTPTransportError.directoryItemLimit }
            result.visited += 1
            let name = child.lastPathComponent
            try validateRemotePathComponent(name)
            let values = try child.resourceValues(forKeys: [.isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey])
            if values.isSymbolicLink == true {
                result.skipped += 1
                continue
            }
            let destination = (remotePath as NSString).appendingPathComponent(name)
            let childRelativePath = relativePath.isEmpty ? name : (relativePath as NSString).appendingPathComponent(name)
            if values.isDirectory == true {
                try await sftp.createDirectory(atPath: destination)
                var nested = try await uploadDirectoryContents(localURL: child, remotePath: destination,
                    relativePath: childRelativePath,
                    depth: depth + 1, remainingItems: remainingItems - result.visited,
                    using: sftp, progress: progress)
                nested.directories += 1
                result.add(nested)
            } else if values.isRegularFile == true {
                try await upload(localURL: child, to: destination, overwrite: false) { sent, total in
                    await progress(childRelativePath, sent, total)
                }
                result.files += 1
            } else {
                result.skipped += 1
            }
        }
        return result
    }

    private func downloadDirectoryContents(remotePath: String, localURL: URL, relativePath: String, depth: Int,
        remainingItems: Int, using sftp: SFTPClient,
        progress: @escaping @Sendable (String, UInt64, UInt64?) async -> Void) async throws -> SFTPDirectoryWalk {
        guard depth <= 64 else { throw SFTPTransportError.directoryDepthLimit }
        let entries = try await listDirectory(at: remotePath)
        var result = SFTPDirectoryWalk()
        for entry in entries {
            try Task.checkCancellation()
            guard result.visited < remainingItems else { throw SFTPTransportError.directoryItemLimit }
            result.visited += 1
            try validateRemotePathComponent(entry.name)
            let isLinkNow = try await isSymbolicLink(at: entry.path, using: sftp)
            guard !entry.isSymbolicLink, !isLinkNow else {
                result.skipped += 1
                continue
            }
            let attributes = try await sftp.getAttributes(at: entry.path)
            guard let permissions = attributes.permissions else {
                throw SFTPTransportError.fileTypeUnavailable
            }
            let kind = permissions & 0o170000
            let localChild = localURL.appending(path: entry.name,
                directoryHint: kind == 0o040000 ? .isDirectory : .notDirectory)
            let childRelativePath = relativePath.isEmpty ? entry.name : (relativePath as NSString).appendingPathComponent(entry.name)
            if kind == 0o040000 {
                try createProtectedDirectory(at: localChild)
                var nested = try await downloadDirectoryContents(remotePath: entry.path,
                    localURL: localChild, relativePath: childRelativePath, depth: depth + 1,
                    remainingItems: remainingItems - result.visited,
                    using: sftp, progress: progress)
                nested.directories += 1
                result.add(nested)
            } else if kind == 0o100000 {
                try await download(remotePath: entry.path, to: localChild) { sent, total in
                    await progress(childRelativePath, sent, total)
                }
                result.files += 1
            } else {
                result.skipped += 1
            }
        }
        return result
    }

    private func createProtectedDirectory(at url: URL) throws {
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
        #if os(iOS)
        try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete],
            ofItemAtPath: url.path)
        #endif
    }

    /// Reads only small UTF-8 text files for preview/edit. The size limit is checked before allocation.
    public func readTextFile(at path: String, maximumBytes: UInt64 = 1_048_576) async throws -> (String, UInt64, Date?) {
        guard let sftp, sftp.isActive else { throw SSHFailure.notConnected }
        return try await sftp.withFile(filePath: path, flags: .read) { file in
            let attributes = try await file.readAttributes()
            guard let size = attributes.size, size <= maximumBytes else {
                throw SFTPTransportError.fileTooLarge
            }
            var data = Data()
            data.reserveCapacity(Int(size))
            while UInt64(data.count) < size {
                try Task.checkCancellation()
                let remaining = min(UInt64(64 * 1024), size - UInt64(data.count))
                let buffer = try await file.read(from: UInt64(data.count), length: UInt32(remaining))
                guard buffer.readableBytes > 0 else { break }
                data.append(contentsOf: buffer.readableBytesView)
            }
            guard UInt64(data.count) == size else {
                throw SFTPTransportError.remoteFileChanged
            }
            guard let contents = String(data: data, encoding: .utf8) else {
                throw SFTPTransportError.notUTF8Text
            }
            return (contents, size, attributes.accessModificationTime?.modificationTime)
        }
    }

    /// Save only if the current remote size and modification time still match the preview.
    public func saveTextFile(_ contents: String, at path: String, expectedSize: UInt64,
                             expectedModifiedAt: Date?) async throws {
        guard let sftp, sftp.isActive else { throw SSHFailure.notConnected }
        let initialTarget = try await attributesIfPresent(at: path, using: sftp)
        try verifyOverwriteTarget(initialTarget, size: expectedSize, modifiedAt: expectedModifiedAt)
        let data = Data(contents.utf8)
        guard data.count <= 1_048_576 else { throw SFTPTransportError.fileTooLarge }
        let temporaryPath = temporarySiblingPath(for: path, marker: "edit")
        var creationAttributes = SFTPFileAttributes.none
        creationAttributes.permissions = initialTarget?.permissions
        do {
            try await sftp.withFile(filePath: temporaryPath, flags: [.write, .create, .forceCreate],
                                    attributes: creationAttributes) { file in
                try await file.write(ByteBuffer(bytes: Array(data)), at: 0)
            }
            let backupPath = try await replaceExistingFile(at: path, with: temporaryPath,
                expectedSize: expectedSize, expectedModifiedAt: expectedModifiedAt, using: sftp)
            try? await sftp.remove(at: backupPath)
        } catch {
            try? await sftp.remove(at: temporaryPath)
            throw error
        }
    }

    public func disconnect() async {
        generation = UUID()
        let oldSFTP = sftp; sftp = nil
        let oldClient = client; client = nil
        deviceID = nil; endpointAuthority = nil
        try? await oldSFTP?.close()
        try? await oldClient?.close()
    }

    private func attributesIfPresent(at path: String, using sftp: SFTPClient) async throws -> SFTPFileAttributes? {
        do { return try await sftp.getAttributes(at: path) }
        catch let SFTPError.errorStatus(status) where status.errorCode == .noSuchFile { return nil }
        catch let status as SFTPMessage.Status where status.errorCode == .noSuchFile { return nil }
    }

    private func isSymbolicLink(at path: String, using sftp: SFTPClient) async throws -> Bool {
        let parent = (path as NSString).deletingLastPathComponent
        let name = (path as NSString).lastPathComponent
        guard !name.isEmpty else { return false }
        let entries = try await sftp.listDirectory(atPath: parent.isEmpty ? "." : parent)
        guard let entry = entries.lazy.flatMap(\.components).first(where: { $0.filename == name }) else {
            return false
        }
        if let permissions = entry.attributes.permissions {
            return (permissions & 0o170000) == 0o120000
        }
        guard let type = entry.longname.first else {
            throw SFTPTransportError.fileTypeUnavailable
        }
        return type == "l"
    }

    private func verifyOverwriteTarget(_ attributes: SFTPFileAttributes?, size: UInt64?,
                                       modifiedAt: Date?) throws {
        guard let attributes, let size, let modifiedAt,
              attributes.size == size,
              attributes.accessModificationTime?.modificationTime == modifiedAt,
              let permissions = attributes.permissions,
              (permissions & 0o170000) == 0o100000 else {
            throw SFTPTransportError.remoteFileChanged
        }
    }

    private func replaceExistingFile(at path: String, with temporaryPath: String,
                                     expectedSize: UInt64?, expectedModifiedAt: Date?,
                                     using sftp: SFTPClient) async throws -> String {
        let destinationIsSymbolicLink = try await isSymbolicLink(at: path, using: sftp)
        guard !destinationIsSymbolicLink else {
            throw SFTPTransportError.symbolicLinkTarget
        }
        let current = try await attributesIfPresent(at: path, using: sftp)
        try verifyOverwriteTarget(current, size: expectedSize, modifiedAt: expectedModifiedAt)
        let backupPath = temporarySiblingPath(for: path, marker: "backup")
        try await sftp.rename(at: path, to: backupPath)
        do {
            try await sftp.rename(at: temporaryPath, to: path)
            return backupPath
        } catch {
            do { try await sftp.rename(at: backupPath, to: path) }
            catch { throw SFTPTransportError.recoveryFileRetained(backupPath) }
            throw error
        }
    }

    private func temporarySiblingPath(for path: String, marker: String) -> String {
        let parent = (path as NSString).deletingLastPathComponent
        let name = ".nexus-\(marker)-\(UUID().uuidString)"
        return parent.isEmpty || parent == "." ? name : (parent as NSString).appendingPathComponent(name)
    }

    private func validateRemotePathComponent(_ name: String) throws {
        guard !name.isEmpty, name != ".", name != "..", !name.contains("/"),
              !name.contains("\\"), !name.contains("\0"),
              name.utf8.count <= 255,
              !name.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else {
            throw SFTPTransportError.invalidRemoteName
        }
    }

}

public enum SFTPTransportError: LocalizedError {
    case fileTooLarge
    case notUTF8Text
    case remoteFileChanged
    case localFileChanged
    case recoveryFileRetained(String)
    case remotePathAlreadyExists
    case symbolicLinkTarget
    case fileTypeUnavailable
    case invalidRemoteName
    case remotePathNotDirectory
    case localPathNotDirectory
    case directoryDepthLimit
    case directoryItemLimit
    case invalidPermissionMode
    case permissionUpdateNotApplied

    public var errorDescription: String? {
        switch self {
        case .fileTooLarge: return "This file exceeds the 1 MiB limit for text preview and editing."
        case .notUTF8Text: return "This file is not valid UTF-8 text and cannot be previewed in the editor."
        case .remoteFileChanged: return "The remote file changed, or its server does not provide modification times. Reload it before saving."
        case .localFileChanged: return "The local file changed while it was being uploaded. No completed upload was published."
        case .recoveryFileRetained(let path): return "The upload could not replace the target, and the original remains at \(path). Reconcile that remote backup manually."
        case .remotePathAlreadyExists: return "A remote file with that name appeared while the upload was in progress. Refresh the directory before deciding whether to replace it."
        case .symbolicLinkTarget: return "Nexus will not replace a symbolic link. Refresh the directory and choose a different filename."
        case .fileTypeUnavailable: return "The server did not provide enough metadata to safely check this destination. Refresh the directory and choose another filename."
        case .invalidRemoteName: return "Use a single filename without path separators, control characters, or a name longer than 255 bytes."
        case .remotePathNotDirectory: return "The selected remote item is no longer a directory. Refresh the remote listing before retrying."
        case .localPathNotDirectory: return "The selected local item is no longer a regular directory. Refresh the local listing before retrying."
        case .directoryDepthLimit: return "The directory tree exceeds Nexus’s safe nesting limit of 64 levels."
        case .directoryItemLimit: return "The directory tree exceeds Nexus’s safe limit of 10,000 items."
        case .invalidPermissionMode: return "Permissions must use only the owner, group, and other read/write/execute bits."
        case .permissionUpdateNotApplied: return "The server did not apply the requested permissions. Refresh the folder to see the actual mode."
        }
    }
}
