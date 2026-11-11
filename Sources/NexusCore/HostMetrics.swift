import Foundation

public struct HostLoadAverage: Codable, Equatable, Sendable {
    public let oneMinute: Double
    public let fiveMinutes: Double
    public let fifteenMinutes: Double

    public init(oneMinute: Double, fiveMinutes: Double, fifteenMinutes: Double) {
        self.oneMinute = oneMinute
        self.fiveMinutes = fiveMinutes
        self.fifteenMinutes = fifteenMinutes
    }
}

public struct HostFilesystemUsage: Codable, Equatable, Sendable {
    public let totalBytes: UInt64
    public let usedBytes: UInt64
    public let availableBytes: UInt64

    public init(totalBytes: UInt64, usedBytes: UInt64, availableBytes: UInt64) {
        self.totalBytes = totalBytes
        self.usedBytes = usedBytes
        self.availableBytes = availableBytes
    }
}

public struct HostNetworkCounters: Codable, Equatable, Identifiable, Sendable {
    public var id: String { interface }
    public let interface: String
    public let receivedBytes: UInt64
    public let transmittedBytes: UInt64

    public init(interface: String, receivedBytes: UInt64, transmittedBytes: UInt64) {
        self.interface = interface
        self.receivedBytes = receivedBytes
        self.transmittedBytes = transmittedBytes
    }
}

public struct HostNetworkRate: Equatable, Identifiable, Sendable {
    public var id: String { interface }
    public let interface: String
    public let receivedBytesPerSecond: Double
    public let transmittedBytesPerSecond: Double
    public let intervalSeconds: TimeInterval
}

public struct HostGPUUsage: Codable, Equatable, Identifiable, Sendable {
    public var id: Int { index }
    public let index: Int
    public let utilizationPercent: Double?
    public let memoryTotalMiB: UInt64?
    public let memoryUsedMiB: UInt64?
    public let temperatureCelsius: Double?
}

public enum HostResourceWarning: String, CaseIterable, Sendable {
    case rootFilesystemLow = "disk"
    case memoryLow = "memory"
}

/// Allows only the newest on-demand metrics request for a device to publish state.
public struct HostMetricsRefreshRegistry: Sendable {
    private var attempts: [UUID: UUID] = [:]

    public init() {}

    @discardableResult
    public mutating func begin(deviceID: UUID) -> UUID {
        let attemptID = UUID()
        attempts[deviceID] = attemptID
        return attemptID
    }

    public func isCurrent(_ attemptID: UUID, for deviceID: UUID) -> Bool {
        attempts[deviceID] == attemptID
    }

    @discardableResult
    public mutating func finish(_ attemptID: UUID, for deviceID: UUID) -> Bool {
        guard isCurrent(attemptID, for: deviceID) else { return false }
        attempts[deviceID] = nil
        return true
    }

    public mutating func invalidate(deviceID: UUID) {
        attempts[deviceID] = nil
    }

    public mutating func invalidateAll() {
        attempts.removeAll()
    }
}

/// A point-in-time snapshot of values read from Linux procfs and `df` over SSH.
/// Optional fields stay absent when a host does not provide a valid value.
public struct HostMetricsSnapshot: Codable, Equatable, Sendable {
    public let observedAt: Date
    /// Identifies the Linux boot for counter continuity, never SSH host trust.
    public let bootID: UUID?
    public let uptimeSeconds: Double?
    public let loadAverage: HostLoadAverage?
    public let logicalCPUCount: Int?
    public let cpuUtilizationPercent: Double?
    public let memoryTotalBytes: UInt64?
    public let memoryAvailableBytes: UInt64?
    public let rootFilesystem: HostFilesystemUsage?
    public let networkInterfaces: [HostNetworkCounters]
    public let nvidiaSMIAvailable: Bool
    public let nvidiaGPUs: [HostGPUUsage]

    private var rootFilesystemIsConsistent: Bool {
        guard let filesystem = rootFilesystem, filesystem.totalBytes > 0,
              filesystem.usedBytes <= filesystem.totalBytes else { return false }
        return filesystem.availableBytes <= filesystem.totalBytes - filesystem.usedBytes
    }

    /// True only when both inputs used by the low-resource summary are valid.
    public var hasCompleteResourceWarningInputs: Bool {
        let filesystemAvailable = rootFilesystemIsConsistent
        let memoryAvailable = memoryTotalBytes.map { total in
            total > 0 && (memoryAvailableBytes.map { $0 <= total } ?? false)
        } ?? false
        return filesystemAvailable && memoryAvailable
    }

    /// Thresholds are shared by Dashboard summaries and optional local notifications.
    public var lowResourceWarnings: [HostResourceWarning] {
        var warnings: [HostResourceWarning] = []
        if let filesystem = rootFilesystem, rootFilesystemIsConsistent,
           Double(filesystem.availableBytes) / Double(filesystem.totalBytes) < 0.1 {
            warnings.append(.rootFilesystemLow)
        }
        if let total = memoryTotalBytes, let available = memoryAvailableBytes,
           total > 0, available <= total,
           Double(available) / Double(total) < 0.1 {
            warnings.append(.memoryLow)
        }
        return warnings
    }

    public init(observedAt: Date, uptimeSeconds: Double?, loadAverage: HostLoadAverage?,
                logicalCPUCount: Int?, cpuUtilizationPercent: Double?,
                memoryTotalBytes: UInt64?, memoryAvailableBytes: UInt64?,
                rootFilesystem: HostFilesystemUsage?, networkInterfaces: [HostNetworkCounters],
                nvidiaSMIAvailable: Bool, nvidiaGPUs: [HostGPUUsage], bootID: UUID? = nil) {
        self.observedAt = observedAt
        self.bootID = bootID
        self.uptimeSeconds = uptimeSeconds
        self.loadAverage = loadAverage
        self.logicalCPUCount = logicalCPUCount
        self.cpuUtilizationPercent = cpuUtilizationPercent
        self.memoryTotalBytes = memoryTotalBytes
        self.memoryAvailableBytes = memoryAvailableBytes
        self.rootFilesystem = rootFilesystem
        self.networkInterfaces = networkInterfaces
        self.nvidiaSMIAvailable = nvidiaSMIAvailable
        self.nvidiaGPUs = nvidiaGPUs
    }
}

/// One user-requested sample. History stores measurements only, never credentials or commands.
public struct HostMetricsHistoryRecord: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public let deviceID: UUID
    public let deviceName: String
    public let endpoint: Endpoint
    public let sshUsername: String?
    public let authentication: AuthenticationKind?
    public let snapshot: HostMetricsSnapshot

    public init(id: UUID = UUID(), deviceID: UUID, deviceName: String,
                endpoint: Endpoint, sshUsername: String? = nil,
                authentication: AuthenticationKind? = nil, snapshot: HostMetricsSnapshot) {
        self.id = id
        self.deviceID = deviceID
        self.deviceName = deviceName
        self.endpoint = endpoint
        self.sshUsername = sshUsername
        self.authentication = authentication
        self.snapshot = snapshot
    }

    /// Legacy records without an SSH identity are intentionally not reused for current-profile charts.
    public func belongs(to device: Device) -> Bool {
        guard deviceID == device.id, sshUsername == device.username,
              authentication == device.authentication,
              device.endpoints.contains(where: { $0.authority == endpoint.authority }) else { return false }
        return true
    }
}

/// Derives interval averages only when two consecutive manual samples contain monotonic counters.
public enum HostNetworkRateCalculator {
    public static func rates(for deviceID: UUID,
                             in history: [HostMetricsHistoryRecord]) -> [HostNetworkRate] {
        let samples = history.filter { $0.deviceID == deviceID }
            .sorted { $0.snapshot.observedAt < $1.snapshot.observedAt }
        guard samples.count >= 2,
              let previous = samples.dropLast().last,
              let current = samples.last,
              previous.endpoint.authority == current.endpoint.authority,
              previous.snapshot.bootID == current.snapshot.bootID else { return [] }
        if let earlierUptime = previous.snapshot.uptimeSeconds,
           let latestUptime = current.snapshot.uptimeSeconds,
           latestUptime < earlierUptime { return [] }
        let interval = current.snapshot.observedAt.timeIntervalSince(previous.snapshot.observedAt)
        guard interval.isFinite, interval > 0 else { return [] }

        var previousByInterface: [String: HostNetworkCounters] = [:]
        for counter in previous.snapshot.networkInterfaces {
            previousByInterface[counter.interface] = counter
        }
        return current.snapshot.networkInterfaces.compactMap { latest in
            guard let earlier = previousByInterface[latest.interface],
                  latest.receivedBytes >= earlier.receivedBytes,
                  latest.transmittedBytes >= earlier.transmittedBytes else { return nil }
            let receiveRate = Double(latest.receivedBytes - earlier.receivedBytes) / interval
            let transmitRate = Double(latest.transmittedBytes - earlier.transmittedBytes) / interval
            guard receiveRate.isFinite, transmitRate.isFinite else { return nil }
            return HostNetworkRate(interface: latest.interface,
                receivedBytesPerSecond: receiveRate,
                transmittedBytesPerSecond: transmitRate,
                intervalSeconds: interval)
        }
    }
}

public enum HostMetricsParseError: LocalizedError {
    case unsupportedPayload

    public var errorDescription: String? {
        "The server returned metrics in an unsupported format."
    }
}

public enum HostMetricsParser {
    private static let header = "nexus_metrics\t1"

    public static func parse(_ output: String, observedAt: Date = .now) throws -> HostMetricsSnapshot {
        let lines = output.split(whereSeparator: \.isNewline).map(String.init)
        guard lines.first == header else { throw HostMetricsParseError.unsupportedPayload }

        var uptime: Double?
        var bootID: UUID?
        var load: HostLoadAverage?
        var cpuCount: Int?
        var cpuUtilization: Double?
        var memoryTotal: UInt64?
        var memoryAvailable: UInt64?
        var filesystem: HostFilesystemUsage?
        var interfaces: [String: HostNetworkCounters] = [:]
        var nvidiaSMIAvailable = false
        var nvidiaGPUs: [Int: HostGPUUsage] = [:]

        for line in lines.dropFirst() {
            let fields = line.split(separator: "\t", omittingEmptySubsequences: false).map(String.init)
            guard let kind = fields.first else { continue }
            switch kind {
            case "boot_id" where fields.count == 2:
                bootID = UUID(uuidString: fields[1])
            case "uptime" where fields.count == 2:
                if let value = Double(fields[1]), value.isFinite, value >= 0 { uptime = value }
            case "load" where fields.count == 4:
                if let one = Double(fields[1]), let five = Double(fields[2]),
                   let fifteen = Double(fields[3]), [one, five, fifteen].allSatisfy({ $0.isFinite && $0 >= 0 }) {
                    load = HostLoadAverage(oneMinute: one, fiveMinutes: five, fifteenMinutes: fifteen)
                }
            case "cpu_count" where fields.count == 2:
                if let value = Int(fields[1]), value > 0 { cpuCount = value }
            case "cpu_utilization" where fields.count == 2:
                if let value = Double(fields[1]), value.isFinite, (0...100).contains(value) {
                    cpuUtilization = value
                }
            case "memory" where fields.count == 3:
                if let total = UInt64(fields[1]), let available = UInt64(fields[2]),
                   total > 0, available <= total {
                    memoryTotal = total
                    memoryAvailable = available
                }
            case "filesystem" where fields.count == 4:
                if let total = UInt64(fields[1]), let used = UInt64(fields[2]),
                   let available = UInt64(fields[3]), total > 0,
                   used <= total, available <= total - used {
                    filesystem = HostFilesystemUsage(totalBytes: total, usedBytes: used, availableBytes: available)
                }
            case "network" where fields.count == 4:
                let interface = fields[1]
                guard interface.range(of: "^[A-Za-z0-9_.:-]{1,32}$", options: .regularExpression) != nil,
                      let received = UInt64(fields[2]), let transmitted = UInt64(fields[3]) else { continue }
                interfaces[interface] = HostNetworkCounters(interface: interface,
                    receivedBytes: received, transmittedBytes: transmitted)
            case "nvidia_tool" where fields.count == 2:
                nvidiaSMIAvailable = fields[1] == "available"
            case "nvidia" where fields.count == 6:
                guard let index = Int(fields[1]), index >= 0 else { continue }
                let utilization = finiteDouble(fields[2], range: 0...100)
                let memoryTotal = UInt64(fields[3])
                let memoryUsed = UInt64(fields[4])
                let temperature = finiteDouble(fields[5], range: 0...200)
                let validMemory: Bool
                if let memoryTotal, let memoryUsed {
                    validMemory = memoryTotal > 0 && memoryUsed <= memoryTotal
                }
                else { validMemory = false }
                guard utilization != nil || validMemory || temperature != nil else { continue }
                nvidiaGPUs[index] = HostGPUUsage(index: index,
                    utilizationPercent: utilization,
                    memoryTotalMiB: validMemory ? memoryTotal : nil,
                    memoryUsedMiB: validMemory ? memoryUsed : nil,
                    temperatureCelsius: temperature)
            default:
                continue
            }
        }

        return HostMetricsSnapshot(observedAt: observedAt, uptimeSeconds: uptime,
            loadAverage: load, logicalCPUCount: cpuCount, cpuUtilizationPercent: cpuUtilization,
            memoryTotalBytes: memoryTotal,
            memoryAvailableBytes: memoryAvailable, rootFilesystem: filesystem,
            networkInterfaces: interfaces.values.sorted { $0.interface < $1.interface },
            nvidiaSMIAvailable: nvidiaSMIAvailable,
            nvidiaGPUs: nvidiaGPUs.values.sorted { $0.index < $1.index }, bootID: bootID)
    }

    private static func finiteDouble(_ value: String, range: ClosedRange<Double>) -> Double? {
        guard let parsed = Double(value), parsed.isFinite, range.contains(parsed) else { return nil }
        return parsed
    }
}
