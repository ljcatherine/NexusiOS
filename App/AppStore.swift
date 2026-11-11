import SwiftUI
import LocalAuthentication
import UserNotifications
import NexusCore
import NexusSSH

struct CachedServiceInventory: Equatable {
    let endpointAuthority: String
    let username: String
    let observedAt: Date
    let totalCount: Int
    let services: [LinuxService]
}

@MainActor @Observable
final class AppStore {
    private static var defaultCloudflareMinecraftPanelURL: String? {
        DeploymentConfiguration.current.gatewayOrigin.map { "\($0)/" }
    }
    var devices: [Device] = []
    var sessions: [TerminalSession] = []
    var commandRecipes: [CommandRecipe] = []
    var commandHistory: [CommandRunRecord] = []
    var metricsHistory: [UUID: [HostMetricsHistoryRecord]] = [:]
    var favoriteDeviceIDs: Set<UUID> = []
    var hostMonitorStates: [UUID: HostMonitorState] = [:]
    var serviceInventories: [UUID: CachedServiceInventory] = [:]
    var pendingHostMetricsTrust: PendingHostMetricsTrust?
    var error: String?
    var locked = false
    var theme: String { didSet { defaults.set(theme, forKey: "theme") } }
    var fontSize: Double { didSet { defaults.set(fontSize, forKey: "fontSize") } }
    var timeout: Int { didSet { defaults.set(timeout, forKey: "timeout") } }
    var appLock: Bool { didSet { defaults.set(appLock, forKey: "appLock") } }
    var showFavoriteShortcuts: Bool { didSet { defaults.set(showFavoriteShortcuts, forKey: "showFavoriteShortcuts") } }
    let isDemoMode: Bool
    private(set) var lowResourceAlerts = false
    let secrets = KeychainStore()
    let fileTransport = SFTPTransport()
    let serviceTransport = ServiceTransport()
    let commandTransport = CommandTransport()
    private let configurationURL: URL
    private let commandRecipesURL: URL
    private let commandHistoryURL: URL
    private let metricsHistoryURL: URL
    private let defaults: UserDefaults
    private var monitorTasks: [UUID: Task<Void, Never>] = [:]
    private var monitorRefreshes = HostMetricsRefreshRegistry()
    private var needsProtectedFileReload = false
    init(demoMode: Bool = false) {
        isDemoMode = demoMode
        let defaults = demoMode
            ? UserDefaults(suiteName: "com.ljcatherine.Nexus.Demo")!
            : UserDefaults.standard
        self.defaults = defaults
        theme = demoMode ? "dark" : (defaults.string(forKey: "theme") ?? "dark")
        fontSize = defaults.object(forKey: "fontSize") as? Double ?? 14
        timeout = defaults.object(forKey: "timeout") as? Int ?? 15
        appLock = demoMode ? false : defaults.bool(forKey: "appLock")
        showFavoriteShortcuts = defaults.object(forKey: "showFavoriteShortcuts") as? Bool ?? true
        favoriteDeviceIDs = Set((defaults.stringArray(forKey: "favoriteDeviceIDs") ?? []).compactMap {
            UUID(uuidString: $0)
        })
        lowResourceAlerts = demoMode ? false : defaults.bool(forKey: "lowResourceAlerts")
        locked = demoMode ? false : defaults.bool(forKey: "appLock")
        let storageRoot = demoMode
            ? FileManager.default.temporaryDirectory.appending(path: "Nexus-Demo-Preview")
            : URL.applicationSupportDirectory.appending(path: "Nexus")
        configurationURL = storageRoot.appending(path: "devices.json")
        commandRecipesURL = storageRoot.appending(path: "command-recipes.json")
        commandHistoryURL = storageRoot.appending(path: "command-history.json")
        metricsHistoryURL = storageRoot.appending(path: "metrics-history.json")
        if demoMode {
            devices = Self.demoDevices
            favoriteDeviceIDs = Set(devices.map(\.id))
            hostMonitorStates = Dictionary(uniqueKeysWithValues: devices.map { device in
                let state = HostMonitorState(deviceID: device.id)
                state.snapshot = Self.demoMetrics
                state.sourceEndpoint = device.orderedEndpoints.first
                state.lastAttempt = Self.demoMetrics.observedAt
                return (device.id, state)
            })
            commandRecipes = []
            return
        }
        do {
            if FileManager.default.fileExists(atPath: configurationURL.path) {
                devices = try Configuration.decode(Data(contentsOf: configurationURL)).devices
            } else { devices = Device.suggestions }
        } catch {
            needsProtectedFileReload = true
            self.error = "Cannot load saved devices: \(error.localizedDescription)"
        }
        loadLocalProtectedData()
        hostMonitorStates = Dictionary(uniqueKeysWithValues: devices.map {
            ($0.id, HostMonitorState(deviceID: $0.id))
        })
    }

    private static var demoDevices: [Device] {
        [
            Device(name: "NixOS Workstation", username: "demo", endpoints: [
                Endpoint(host: "nixos.example.invalid", kind: .lan)
            ]),
            Device(name: "Debian Homelab Server", username: "demo", endpoints: [
                Endpoint(host: "debian.example.invalid", kind: .tailscale)
            ])
        ]
    }

    private static var demoMetrics: HostMetricsSnapshot {
        HostMetricsSnapshot(observedAt: .now.addingTimeInterval(-90), uptimeSeconds: 1_036_800,
            loadAverage: HostLoadAverage(oneMinute: 0.42, fiveMinutes: 0.38, fifteenMinutes: 0.31),
            logicalCPUCount: 12, cpuUtilizationPercent: 24.0,
            memoryTotalBytes: 16 * 1024 * 1024 * 1024,
            memoryAvailableBytes: 6 * 1024 * 1024 * 1024,
            rootFilesystem: HostFilesystemUsage(totalBytes: 512 * 1024 * 1024 * 1024,
                usedBytes: 220 * 1024 * 1024 * 1024, availableBytes: 292 * 1024 * 1024 * 1024),
            networkInterfaces: [HostNetworkCounters(interface: "enp5s0", receivedBytes: 8_400_000_000,
                transmittedBytes: 2_900_000_000)], nvidiaSMIAvailable: false, nvidiaGPUs: [])
    }
    func save(_ device: Device, credential: Credential?) async throws {
        try device.validate()
        if isDemoMode {
            if let index = devices.firstIndex(where: { $0.id == device.id }) { devices[index] = device }
            else { devices.append(device) }
            hostMonitorStates[device.id] = HostMonitorState(deviceID: device.id)
            return
        }
        let existing = devices.first(where: { $0.id == device.id })
        if let existing,
           existing.authentication != device.authentication, credential == nil {
            throw DeviceSaveError.credentialRequiredForAuthenticationChange
        }
        let account = SSHTransport.credentialAccount(device)
        let removeSSHCredential = credential == nil && device.endpoints.allSatisfy { $0.kind == .cloudflare }
        var previousCredential: Data?
        if let credential {
            try await SSHConnectionPipeline.shared.validateCredential(for: device, credential: credential)
            try Task.checkCancellation()
            previousCredential = try secrets.read(account)
        } else if removeSSHCredential {
            previousCredential = try secrets.read(account)
        }
        var updated = devices
        if let index = updated.firstIndex(where: { $0.id == device.id }) { updated[index] = device }
        else { updated.append(device) }
        let obsoletePins = try obsoleteHostKeyPins(from: devices, to: updated)
        do {
            if let credential {
                try secrets.write(JSONEncoder().encode(credential), account: account)
            } else if removeSSHCredential {
                try secrets.delete(account)
            }
            for pin in obsoletePins { try secrets.delete(pin.account) }
            try persist(updated)
        } catch let persistenceError {
            var rollbackErrors: [String] = []
            if credential != nil || removeSSHCredential {
                do {
                    if let previousCredential { try secrets.write(previousCredential, account: account) }
                    else { try secrets.delete(account) }
                } catch {
                    rollbackErrors.append("credential: \(error.localizedDescription)")
                }
            }
            rollbackErrors.append(contentsOf: restoreHostKeyPins(obsoletePins))
            guard rollbackErrors.isEmpty else {
                throw DeviceSaveError.rollbackFailed(
                    saveError: persistenceError.localizedDescription,
                    rollbackErrors: rollbackErrors)
            }
            throw persistenceError
        }
        devices = updated
        serviceInventories[device.id] = nil
        Task { await fileTransport.disconnect() }
        monitorRefreshes.invalidate(deviceID: device.id)
        monitorTasks[device.id]?.cancel()
        monitorTasks[device.id] = nil
        if pendingHostMetricsTrust?.device.id == device.id { pendingHostMetricsTrust = nil }
        if let existing,
           let state = hostMonitorStates[device.id] {
            let retainsEndpoint = state.sourceEndpoint.map { source in
                device.endpoints.contains(where: { $0.authority == source.authority })
            } ?? (state.snapshot == nil)
            let retainsSnapshotIdentity = existing.username == device.username
                && existing.authentication == device.authentication
                && retainsEndpoint
            if retainsSnapshotIdentity, let sourceEndpoint = state.sourceEndpoint {
                state.sourceEndpoint = device.endpoints.first(where: {
                    $0.authority == sourceEndpoint.authority
                })
            } else if !retainsSnapshotIdentity {
                hostMonitorStates[device.id] = HostMonitorState(deviceID: device.id)
                removeLowResourceNotification(for: device.id)
            } else {
                state.isRefreshing = false
            }
        } else {
            hostMonitorStates[device.id] = HostMonitorState(deviceID: device.id)
        }
        pruneMetricsHistory(for: device)
    }

    func cacheServiceInventory(_ services: [LinuxService], for device: Device, endpoint: Endpoint) {
        guard !isDemoMode else { return }
        serviceInventories[device.id] = CachedServiceInventory(endpointAuthority: endpoint.authority,
            username: device.username, observedAt: .now, totalCount: services.count,
            services: Array(services.prefix(100)))
    }

    func minecraftPanelURL() throws -> URL? {
        guard !isDemoMode else { return nil }
        guard let data = try secrets.read("minecraft-panel-url"),
              let value = String(data: data, encoding: .utf8) else {
            guard let defaultURL = Self.defaultCloudflareMinecraftPanelURL else { return nil }
            return try Self.validatedMinecraftPanelURL(defaultURL)
        }
        let savedURL = try Self.validatedMinecraftPanelURL(value)
        if savedURL.host?.lowercased().hasSuffix(".ts.net") == true,
           let defaultURL = Self.defaultCloudflareMinecraftPanelURL {
            let migrated = try Self.validatedMinecraftPanelURL(defaultURL)
            try secrets.write(Data(migrated.absoluteString.utf8), account: "minecraft-panel-url")
            return migrated
        }
        return savedURL
    }

    func saveMinecraftPanelURL(_ value: String) throws {
        guard !isDemoMode else { throw DeviceConfigurationImportError.demoModeReadOnly }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            try secrets.delete("minecraft-panel-url")
            return
        }
        let url = try Self.validatedMinecraftPanelURL(trimmed)
        guard let data = url.absoluteString.data(using: .utf8) else {
            throw MinecraftPanelConfigurationError.invalidURL
        }
        try secrets.write(data, account: "minecraft-panel-url")
    }

    private static func validatedMinecraftPanelURL(_ value: String) throws -> URL {
        do {
            return try MinecraftPanelAddress(value).url
        } catch {
            throw MinecraftPanelConfigurationError.invalidURL
        }
    }
    private func pruneMetricsHistory(for device: Device) {
        let existing = metricsHistory[device.id] ?? []
        let matching = existing.filter { $0.belongs(to: device) }
        guard matching.count != existing.count else { return }
        metricsHistory[device.id] = matching
        do {
            try persistCommandData(metricsHistory.values.flatMap { $0 }, at: metricsHistoryURL)
            hostMonitorStates[device.id]?.historyError = nil
        } catch {
            hostMonitorStates[device.id]?.historyError = "Profile saved, but obsolete host history could not be removed from protected storage."
        }
    }
    private func persist(_ updated: [Device]) throws {
        try FileManager.default.createDirectory(at: configurationURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try JSONEncoder().encode(Configuration(devices: updated)).write(to: configurationURL,
            options: [.atomic, .completeFileProtection])
    }
    func exportDeviceConfiguration() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(Configuration(devices: devices))
    }
    func readDeviceConfiguration(from url: URL) throws -> Data {
        guard !isDemoMode else { throw DeviceConfigurationImportError.demoModeReadOnly }
        let values = try url.resourceValues(forKeys: [.fileSizeKey])
        guard let size = values.fileSize, size <= 1_048_576 else {
            throw DeviceConfigurationImportError.fileTooLarge
        }
        return try Data(contentsOf: url, options: .mappedIfSafe)
    }
    func previewDeviceConfigurationImport(_ data: Data) throws -> (added: Int, updated: Int) {
        let (_, importedDevices, addedCount) = try mergedDeviceConfiguration(from: data)
        return (addedCount, importedDevices.count - addedCount)
    }
    func importDeviceConfiguration(_ data: Data) throws {
        guard !isDemoMode else { throw DeviceConfigurationImportError.demoModeReadOnly }
        let (updated, importedDevices, _) = try mergedDeviceConfiguration(from: data)
        let previousDevices = devices
        let obsoletePins = try obsoleteHostKeyPins(from: previousDevices, to: updated)
        do {
            for pin in obsoletePins { try secrets.delete(pin.account) }
            try persist(updated)
        } catch let importError {
            let rollbackErrors = restoreHostKeyPins(obsoletePins)
            guard rollbackErrors.isEmpty else {
                throw DeviceConfigurationImportError.rollbackFailed(
                    importError: importError.localizedDescription,
                    rollbackErrors: rollbackErrors)
            }
            throw importError
        }
        devices = updated
        for importedDevice in importedDevices {
            removeLowResourceNotification(for: importedDevice.id)
            monitorRefreshes.invalidate(deviceID: importedDevice.id)
            monitorTasks[importedDevice.id]?.cancel()
            monitorTasks[importedDevice.id] = nil
            hostMonitorStates[importedDevice.id] = HostMonitorState(deviceID: importedDevice.id)
            pruneMetricsHistory(for: importedDevice)
            if pendingHostMetricsTrust?.device.id == importedDevice.id { pendingHostMetricsTrust = nil }
        }
        Task { await fileTransport.disconnect() }
    }

    private func obsoleteHostKeyPins(from previous: [Device], to updated: [Device]) throws -> [(account: String, data: Data?)] {
        let previousAuthorities = Set(previous.flatMap(\.endpoints).map(\.authority))
        let retainedAuthorities = Set(updated.flatMap(\.endpoints).map(\.authority))
        return try previousAuthorities.subtracting(retainedAuthorities).map { authority in
            let account = "hostkey:" + authority
            return (account, try secrets.read(account))
        }
    }

    private func restoreHostKeyPins(_ pins: [(account: String, data: Data?)]) -> [String] {
        var errors: [String] = []
        for pin in pins {
            do {
                if let data = pin.data { try secrets.write(data, account: pin.account) }
                else { try secrets.delete(pin.account) }
            } catch {
                errors.append("\(pin.account): \(error.localizedDescription)")
            }
        }
        return errors
    }

    private func mergedDeviceConfiguration(from data: Data) throws -> ([Device], [Device], Int) {
        guard data.count <= 1_048_576 else { throw DeviceConfigurationImportError.fileTooLarge }
        let imported = try Configuration.decode(data)
        guard imported.devices.count <= 100,
              imported.devices.allSatisfy({ $0.endpoints.count <= 100 }) else {
            throw DeviceConfigurationImportError.tooManyProfiles
        }

        var updated = devices
        var addedCount = 0
        for importedDevice in imported.devices {
            if let index = updated.firstIndex(where: { $0.id == importedDevice.id }) {
                guard updated[index].authentication == importedDevice.authentication else {
                    throw DeviceConfigurationImportError.authenticationChanged(importedDevice.name)
                }
                updated[index] = importedDevice
            } else {
                updated.append(importedDevice)
                addedCount += 1
            }
        }
        return (updated, imported.devices, addedCount)
    }
    func saveCommandRecipe(_ recipe: CommandRecipe) throws {
        guard !isDemoMode else { throw DeviceConfigurationImportError.demoModeReadOnly }
        try recipe.validate()
        var updated = commandRecipes
        if let index = updated.firstIndex(where: { $0.id == recipe.id }) { updated[index] = recipe }
        else { updated.append(recipe) }
        try persistCommandData(updated, at: commandRecipesURL)
        commandRecipes = updated
    }
    func removeCommandRecipe(_ recipe: CommandRecipe) throws {
        guard !isDemoMode else { throw DeviceConfigurationImportError.demoModeReadOnly }
        let updated = commandRecipes.filter { $0.id != recipe.id }
        try persistCommandData(updated, at: commandRecipesURL)
        commandRecipes = updated
    }
    func toggleFavorite(_ device: Device) {
        if favoriteDeviceIDs.contains(device.id) { favoriteDeviceIDs.remove(device.id) }
        else { favoriteDeviceIDs.insert(device.id) }
        defaults.set(favoriteDeviceIDs.map(\.uuidString), forKey: "favoriteDeviceIDs")
    }
    func recordCommandRun(_ record: CommandRunRecord) throws {
        guard !isDemoMode else { throw DeviceConfigurationImportError.demoModeReadOnly }
        var updated = [record] + commandHistory.filter { $0.id != record.id }
        updated = Array(updated.prefix(100))
        try persistCommandData(updated, at: commandHistoryURL)
        commandHistory = updated
    }
    private func persistCommandData<T: Encodable>(_ value: T, at url: URL) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try JSONEncoder().encode(value).write(to: url, options: [.atomic, .completeFileProtection])
    }
    private func loadLocalProtectedData() {
        do {
            let loadedDevices = FileManager.default.fileExists(atPath: configurationURL.path)
                ? try Configuration.decode(Data(contentsOf: configurationURL)).devices
                : Device.suggestions
            let loadedRecipes = FileManager.default.fileExists(atPath: commandRecipesURL.path)
                ? try JSONDecoder().decode([CommandRecipe].self, from: Data(contentsOf: commandRecipesURL))
                : []
            let loadedCommandHistory = FileManager.default.fileExists(atPath: commandHistoryURL.path)
                ? try JSONDecoder().decode([CommandRunRecord].self, from: Data(contentsOf: commandHistoryURL))
                : []
            let loadedMetricsHistory: [UUID: [HostMetricsHistoryRecord]]
            if FileManager.default.fileExists(atPath: metricsHistoryURL.path) {
                let saved = try JSONDecoder().decode([HostMetricsHistoryRecord].self,
                    from: Data(contentsOf: metricsHistoryURL))
                loadedMetricsHistory = Dictionary(grouping: Self.retainedMetricHistory(saved), by: \.deviceID)
            } else {
                loadedMetricsHistory = [:]
            }

            // Apply one consistent snapshot only after every protected file is readable.
            for task in monitorTasks.values { task.cancel() }
            monitorTasks.removeAll()
            monitorRefreshes.invalidateAll()
            pendingHostMetricsTrust = nil
            serviceInventories.removeAll()
            devices = loadedDevices
            commandRecipes = loadedRecipes
            commandHistory = loadedCommandHistory
            metricsHistory = loadedMetricsHistory
            hostMonitorStates = Dictionary(uniqueKeysWithValues: loadedDevices.map {
                ($0.id, HostMonitorState(deviceID: $0.id))
            })
            needsProtectedFileReload = false
            if error?.hasPrefix("Cannot load saved devices:") == true ||
                error?.hasPrefix("Cannot load protected Nexus data:") == true {
                error = nil
            }
        } catch {
            needsProtectedFileReload = true
            if !locked { self.error = "Cannot load protected Nexus data: \(error.localizedDescription)" }
        }
    }
    func remove(_ device: Device) throws {
        if isDemoMode {
            devices.removeAll { $0.id == device.id }
            serviceInventories[device.id] = nil
            favoriteDeviceIDs.remove(device.id)
            hostMonitorStates[device.id] = nil
            sessions.filter { $0.device.id == device.id }.forEach { close($0) }
            return
        }
        guard !needsProtectedFileReload else {
            throw DeviceRemovalError.protectedDataUnavailable
        }
        let updated = devices.filter { $0.id != device.id }
        let retainedAuthorities = Set(updated.flatMap(\.endpoints).map(\.authority))
        let removedAuthorities = Set(device.endpoints.map(\.authority)).subtracting(retainedAuthorities)
        let accounts = [SSHTransport.credentialAccount(device)] + removedAuthorities.map { "hostkey:" + $0 }
        let previousItems = try accounts.map { account in
            (account: account, data: try secrets.read(account))
        }
        let historyFileExists = FileManager.default.fileExists(atPath: metricsHistoryURL.path)
        let previousHistoryData = historyFileExists ? try Data(contentsOf: metricsHistoryURL) : nil
        let updatedHistory = metricsHistory.values.flatMap { $0 }.filter { $0.deviceID != device.id }
        var historyWriteAttempted = false

        do {
            for item in previousItems { try secrets.delete(item.account) }
            historyWriteAttempted = true
            try persistCommandData(updatedHistory, at: metricsHistoryURL)
            try persist(updated)
        } catch let removalError {
            var rollbackErrors: [String] = []
            for item in previousItems {
                do {
                    if let data = item.data { try secrets.write(data, account: item.account) }
                    else { try secrets.delete(item.account) }
                } catch {
                    rollbackErrors.append("\(item.account): \(error.localizedDescription)")
                }
            }
            if historyWriteAttempted {
                do {
                    if let previousHistoryData {
                        try previousHistoryData.write(to: metricsHistoryURL,
                            options: [.atomic, .completeFileProtection])
                    } else if FileManager.default.fileExists(atPath: metricsHistoryURL.path) {
                        try FileManager.default.removeItem(at: metricsHistoryURL)
                    }
                } catch {
                    rollbackErrors.append("metrics history: \(error.localizedDescription)")
                }
            }
            if !rollbackErrors.isEmpty {
                throw DeviceRemovalError.rollbackFailed(
                    removalError: removalError.localizedDescription,
                    rollbackErrors: rollbackErrors)
            }
            throw removalError
        }

        devices = updated
        serviceInventories[device.id] = nil
        Task { await fileTransport.disconnect() }
        sessions.filter { $0.device.id == device.id }.forEach { close($0) }
        monitorRefreshes.invalidate(deviceID: device.id)
        monitorTasks[device.id]?.cancel()
        monitorTasks[device.id] = nil
        hostMonitorStates[device.id] = nil
        if pendingHostMetricsTrust?.device.id == device.id { pendingHostMetricsTrust = nil }
        removeLowResourceNotification(for: device.id)
        favoriteDeviceIDs.remove(device.id)
        defaults.set(favoriteDeviceIDs.map(\.uuidString), forKey: "favoriteDeviceIDs")
        metricsHistory[device.id] = nil
    }
    @discardableResult func open(_ device: Device, endpoint: Endpoint? = nil) -> TerminalSession {
        let session = TerminalSession(device: device, secrets: secrets, timeout: timeout, demoMode: isDemoMode)
        sessions.append(session); session.connect(endpoint: endpoint)
        return session
    }

    func refreshMetrics(for device: Device, preferredEndpoint: Endpoint? = nil) {
        guard !locked, !monitorTasks.keys.contains(device.id) else { return }
        let state = hostMonitorStates[device.id] ?? HostMonitorState(deviceID: device.id)
        hostMonitorStates[device.id] = state
        if isDemoMode {
            state.snapshot = Self.demoMetrics
            state.sourceEndpoint = preferredEndpoint ?? device.orderedEndpoints.first
            state.lastAttempt = .now
            state.isRefreshing = false
            state.error = nil
            return
        }
        state.isRefreshing = true
        state.error = nil
        state.lastAttempt = .now
        let attemptID = monitorRefreshes.begin(deviceID: device.id)

        var endpoints = device.orderedEndpoints
        if let preferredEndpoint {
            endpoints = [preferredEndpoint] + endpoints.filter { $0.id != preferredEndpoint.id }
        }

        let task = Task { [weak self] in
            guard let self else { return }
            var lastError: String?

            endpointLoop: for endpoint in endpoints {
                guard !Task.isCancelled,
                      monitorRefreshes.isCurrent(attemptID, for: device.id) else { return }
                do {
                    let snapshot = try await SSHTransport().fetchMetrics(
                        device: device, endpoint: endpoint, secrets: secrets, timeout: timeout)
                    guard !Task.isCancelled,
                          monitorRefreshes.isCurrent(attemptID, for: device.id) else { return }
                    state.snapshot = snapshot
                    state.sourceEndpoint = endpoint
                    state.error = nil
                    notifyIfLowResources(snapshot, device: device)
                    let previousHistory = metricsHistory[device.id] ?? []
                    let matchingHistory = previousHistory.filter { $0.belongs(to: device) }
                    let record = HostMetricsHistoryRecord(deviceID: device.id, deviceName: device.name,
                        endpoint: endpoint, sshUsername: device.username,
                        authentication: device.authentication, snapshot: snapshot)
                    metricsHistory[device.id] = matchingHistory + [record]
                    metricsHistory[device.id] = Self.retainedMetricHistory(metricsHistory[device.id] ?? [])
                    do {
                        try persistCommandData(metricsHistory.values.flatMap { $0 }, at: metricsHistoryURL)
                        state.historyError = nil
                    } catch {
                        metricsHistory[device.id] = previousHistory
                        state.historyError = "Snapshot is live, but local history could not be saved."
                    }
                    state.isRefreshing = false
                    state.lastAttempt = .now
                    if monitorRefreshes.finish(attemptID, for: device.id) {
                        monitorTasks[device.id] = nil
                    }
                    return
                } catch let challenge as HostKeyChallenge {
                    guard !Task.isCancelled,
                          monitorRefreshes.isCurrent(attemptID, for: device.id) else { return }
                    state.isRefreshing = false
                    state.lastAttempt = .now
                    if challenge.changed {
                        state.error = "The server host key changed. Monitoring is blocked. Verify and recover the pin through a terminal session."
                    } else {
                        pendingHostMetricsTrust = PendingHostMetricsTrust(device: device, challenge: challenge)
                    }
                    if monitorRefreshes.finish(attemptID, for: device.id) {
                        monitorTasks[device.id] = nil
                    }
                    return
                } catch {
                    guard !Task.isCancelled,
                          monitorRefreshes.isCurrent(attemptID, for: device.id) else { return }
                    lastError = error.localizedDescription
                    if let failure = error as? SSHFailure, failure.allowsEndpointFallback {
                        continue endpointLoop
                    }
                    break endpointLoop
                }
            }

            guard !Task.isCancelled,
                  monitorRefreshes.isCurrent(attemptID, for: device.id) else { return }
            state.isRefreshing = false
            state.lastAttempt = .now
            state.error = lastError ?? "No configured endpoint could be reached."
            if monitorRefreshes.finish(attemptID, for: device.id) {
                monitorTasks[device.id] = nil
            }
        }
        monitorTasks[device.id] = task
    }

    private static func retainedMetricHistory(_ records: [HostMetricsHistoryRecord]) -> [HostMetricsHistoryRecord] {
        let cutoff = Date.now.addingTimeInterval(-30 * 24 * 60 * 60)
        return Dictionary(grouping: records.filter { $0.snapshot.observedAt >= cutoff }, by: \.deviceID)
            .values.flatMap { $0.sorted { $0.snapshot.observedAt > $1.snapshot.observedAt }.prefix(500) }
            .sorted { $0.snapshot.observedAt < $1.snapshot.observedAt }
    }

    func setLowResourceAlerts(_ enabled: Bool) async {
        if isDemoMode {
            lowResourceAlerts = enabled
            defaults.set(enabled, forKey: "lowResourceAlerts")
            return
        }
        guard enabled else {
            lowResourceAlerts = false
            defaults.set(false, forKey: "lowResourceAlerts")
            await removeAllLowResourceNotifications()
            return
        }
        let center = UNUserNotificationCenter.current()
        let current = await center.notificationSettings().authorizationStatus
        let authorized: Bool
        if current == .notDetermined {
            authorized = (try? await center.requestAuthorization(options: [.alert, .sound])) ?? false
        } else {
            authorized = current == .authorized || current == .provisional || current == .ephemeral
        }
        guard authorized else {
            error = "Low-resource alerts were not enabled. Allow notifications for Nexus in iOS Settings, then try again."
            return
        }
        lowResourceAlerts = true
        defaults.set(true, forKey: "lowResourceAlerts")
        defaults.set([String: String](), forKey: "lowResourceAlertStates")
    }

    func refreshLowResourceAlertAuthorization() async {
        guard !isDemoMode else { return }
        guard defaults.bool(forKey: "lowResourceAlerts") else {
            lowResourceAlerts = false
            return
        }
        let status = await UNUserNotificationCenter.current().notificationSettings().authorizationStatus
        guard status == .authorized || status == .provisional || status == .ephemeral else {
            lowResourceAlerts = false
            defaults.set(false, forKey: "lowResourceAlerts")
            await removeAllLowResourceNotifications()
            error = "Low-resource alerts were turned off because notifications are no longer allowed for Nexus. You can re-enable them in Settings after allowing notifications."
            return
        }
        lowResourceAlerts = true
    }

    private func notifyIfLowResources(_ snapshot: HostMetricsSnapshot, device: Device) {
        guard lowResourceAlerts else { return }
        let warnings = snapshot.lowResourceWarnings
        let state = warnings.map(\.rawValue).joined(separator: ",")
        var previous = defaults.dictionary(forKey: "lowResourceAlertStates") as? [String: String] ?? [:]
        let key = device.id.uuidString
        let was = previous[key] ?? ""
        previous[key] = state
        defaults.set(previous, forKey: "lowResourceAlertStates")
        guard !state.isEmpty, state != was else { return }

        let content = UNMutableNotificationContent()
        content.title = "Low host resources · \(device.name)"
        content.body = warnings.map { warning -> String in
            switch warning {
            case .rootFilesystemLow: return "Root filesystem is below 10% free."
            case .memoryLow: return "Memory is below 10% available."
            }
        }.joined(separator: " ")
        content.sound = .default
        let request = UNNotificationRequest(identifier: "low-resources-\(device.id.uuidString)",
            content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request) { [weak self] schedulingError in
            guard let schedulingError else { return }
            Task { @MainActor [weak self] in
                guard let self else { return }
                guard self.lowResourceAlerts,
                      self.devices.contains(where: { $0.id == device.id }) else { return }
                var current = defaults.dictionary(forKey: "lowResourceAlertStates") as? [String: String] ?? [:]
                if current[key] == state {
                    current[key] = was
                    defaults.set(current, forKey: "lowResourceAlertStates")
                }
                self.error = "A low-resource notification could not be scheduled: \(schedulingError.localizedDescription)"
            }
        }
    }

    private func removeLowResourceNotification(for deviceID: UUID) {
        let identifier = "low-resources-\(deviceID.uuidString)"
        let center = UNUserNotificationCenter.current()
        center.removePendingNotificationRequests(withIdentifiers: [identifier])
        center.removeDeliveredNotifications(withIdentifiers: [identifier])
        var states = defaults.dictionary(forKey: "lowResourceAlertStates") as? [String: String] ?? [:]
        states.removeValue(forKey: deviceID.uuidString)
        defaults.set(states, forKey: "lowResourceAlertStates")
    }

    private func removeAllLowResourceNotifications() async {
        let center = UNUserNotificationCenter.current()
        let prefix = "low-resources-"
        let pendingIdentifiers: [String] = await withCheckedContinuation { (continuation: CheckedContinuation<[String], Never>) in
            center.getPendingNotificationRequests { requests in
                continuation.resume(returning: requests.map(\.identifier).filter { $0.hasPrefix(prefix) })
            }
        }
        let deliveredIdentifiers: [String] = await withCheckedContinuation { (continuation: CheckedContinuation<[String], Never>) in
            center.getDeliveredNotifications { notifications in
                continuation.resume(returning: notifications.map(\.request.identifier).filter { $0.hasPrefix(prefix) })
            }
        }
        center.removePendingNotificationRequests(withIdentifiers: pendingIdentifiers)
        center.removeDeliveredNotifications(withIdentifiers: deliveredIdentifiers)
        defaults.set([String: String](), forKey: "lowResourceAlertStates")
    }

    func approveMetricsHostKey() {
        guard !isDemoMode else { pendingHostMetricsTrust = nil; return }
        guard let pending = pendingHostMetricsTrust, !pending.challenge.changed else { return }
        do {
            try HostKeyVerifier.approve(pending.challenge, secrets: secrets)
            pendingHostMetricsTrust = nil
            refreshMetrics(for: pending.device, preferredEndpoint: pending.challenge.endpoint)
        } catch {
            hostMonitorStates[pending.device.id]?.error = error.localizedDescription
            pendingHostMetricsTrust = nil
        }
    }

    func rejectMetricsHostKey() {
        guard let pending = pendingHostMetricsTrust else { return }
        hostMonitorStates[pending.device.id]?.error = "Host key was not approved; no monitoring connection was made."
        pendingHostMetricsTrust = nil
    }

    func close(_ session: TerminalSession) { session.disconnect(); sessions.removeAll { $0.id == session.id } }
    func suspend() {
        sessions.forEach { $0.disconnect() }
        Task { await fileTransport.disconnect() }
        Task { await commandTransport.disconnectAll() }
        for (id, task) in monitorTasks {
            monitorRefreshes.invalidate(deviceID: id)
            task.cancel()
            hostMonitorStates[id]?.isRefreshing = false
        }
        monitorTasks.removeAll()
        pendingHostMetricsTrust = nil
        if appLock { locked = true }
    }
    func becameActive() async {
        guard !isDemoMode else { return }
        if needsProtectedFileReload, !locked { loadLocalProtectedData() }
        await refreshLowResourceAlertAuthorization()
    }
    func unlock() async {
        guard !isDemoMode else { locked = false; return }
        do {
            let allowed = try await LAContext().evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Access Nexus terminals and credentials")
            if allowed {
                locked = false
                if needsProtectedFileReload { loadLocalProtectedData() }
            }
        } catch { self.error = "Unlock failed. Use device authentication to retry." }
    }
    func setAppLock(_ enabled: Bool) async {
        if isDemoMode {
            appLock = false
            locked = false
            return
        }
        if !enabled { appLock = false; return }
        do {
            let context = LAContext()
            guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: nil) else {
                error = "Configure a device passcode before enabling Nexus app lock."; return
            }
            if try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Enable Nexus app lock") {
                appLock = true
            }
        } catch { self.error = "App lock was not enabled because device authentication did not succeed." }
    }
}

private enum DeviceSaveError: LocalizedError {
    case credentialRequiredForAuthenticationChange
    case rollbackFailed(saveError: String, rollbackErrors: [String])

    var errorDescription: String? {
        switch self {
        case .credentialRequiredForAuthenticationChange:
            return "Enter a credential for the new authentication method before saving this device."
        case .rollbackFailed(let saveError, let rollbackErrors):
            return "Device settings could not be saved (\(saveError)), and Keychain rollback was incomplete: \(rollbackErrors.joined(separator: "; ")). Reopen this device's settings and verify its profile, credential, and host-key trust."
        }
    }
}

private enum MinecraftPanelConfigurationError: LocalizedError {
    case invalidURL

    var errorDescription: String? {
        "Enter a valid HTTPS panel address without a username, password, query, or fragment."
    }
}

private enum DeviceRemovalError: LocalizedError {
    case protectedDataUnavailable
    case rollbackFailed(removalError: String, rollbackErrors: [String])

    var errorDescription: String? {
        switch self {
        case .protectedDataUnavailable:
            return "Unlock Nexus and retry after protected device and metrics data has loaded."
        case .rollbackFailed(let removalError, let rollbackErrors):
            return "Device removal failed (\(removalError)), and related local data rollback was incomplete: \(rollbackErrors.joined(separator: "; ")). Check the device profile, credentials, host-key trust, and metrics history before retrying."
        }
    }
}

enum DeviceConfigurationImportError: LocalizedError {
    case demoModeReadOnly
    case fileTooLarge
    case tooManyProfiles
    case authenticationChanged(String)
    case rollbackFailed(importError: String, rollbackErrors: [String])

    var errorDescription: String? {
        switch self {
        case .demoModeReadOnly:
            return "This action is disabled in the simulator preview."
        case .fileTooLarge:
            return "The configuration file is larger than 1 MiB."
        case .tooManyProfiles:
            return "The configuration contains too many devices or endpoints."
        case .authenticationChanged(let name):
            return "The authentication method for \(name) differs from the saved profile. Change it in Devices and provide a matching credential before importing this profile."
        case .rollbackFailed(let importError, let rollbackErrors):
            return "Profile import failed (\(importError)), and Keychain rollback was incomplete: \(rollbackErrors.joined(separator: "; ")). Review saved profiles and host-key trust before connecting."
        }
    }
}
