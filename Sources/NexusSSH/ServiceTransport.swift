import Foundation
import Citadel
import NIO
import NIOSSH
import NexusCore

public struct LinuxService: Identifiable, Equatable, Sendable {
    public var id: String { name }
    public let name: String
    public let loadState: String
    public let activeState: String
    public let subState: String
    public let description: String

    public var isActive: Bool { activeState == "active" }
}

public struct LinuxProcess: Identifiable, Equatable, Sendable {
    public var id: Int { pid }
    public let pid: Int
    public let user: String
    public let cpuPercent: Double
    public let memoryPercent: Double
    public let state: String
    public let command: String
}

public struct LinuxSystemInspection: Equatable, Sendable {
    public let distribution: String
    public let kernel: String
    public let nixosVersion: String?
    public let activeSystemPath: String?
    public let configurationFiles: [String]

    public var isNixOS: Bool { nixosVersion != nil }
}

public enum ServiceAction: String, CaseIterable, Hashable, Sendable {
    case start, stop, restart
}

public enum NixOSRebuildAction: Equatable, Sendable {
    case validate
    case switchSystem
}

public struct NixOSCommandResult: Sendable {
    public let exitCode: Int
    public let output: String
    public var succeeded: Bool { exitCode == 0 }
}

public actor ServiceTransport {
    private let pipeline: SSHConnectionPipeline
    public init(pipeline: SSHConnectionPipeline = .shared) { self.pipeline = pipeline }

    public func listServices(device: Device, endpoint: Endpoint, secrets: any SecretStore,
                             timeout: Int) async throws -> [LinuxService] {
        let output = try await execute(device: device, endpoint: endpoint, secrets: secrets,
            timeout: timeout,
            command: "systemctl --no-legend --no-pager --plain list-units --type=service --all",
            maxResponseSize: 256 * 1024)
        return Self.parseServices(output)
    }

    static func parseServices(_ output: String) -> [LinuxService] {
        output.split(whereSeparator: \.isNewline).compactMap { line in
            let fields = line.split(maxSplits: 4, omittingEmptySubsequences: true, whereSeparator: \.isWhitespace)
            guard fields.count >= 4 else { return nil }
            let name = String(fields[0])
            guard Self.isValidUnit(name) else { return nil }
            return LinuxService(name: name, loadState: String(fields[1]),
                activeState: String(fields[2]), subState: String(fields[3]),
                description: fields.count > 4 ? String(fields[4]) : "")
        }.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    public func recentLogs(for unit: String, device: Device, endpoint: Endpoint,
                           secrets: any SecretStore, timeout: Int) async throws -> String {
        guard Self.isValidUnit(unit) else { throw ServiceTransportError.invalidUnit }
        return try await execute(device: device, endpoint: endpoint, secrets: secrets,
            timeout: timeout,
            command: "journalctl --no-pager --output=short-iso --lines=100 --unit \(Shell.quote(unit)) 2>&1",
            maxResponseSize: 128 * 1024)
    }

    /// Read a bounded process snapshot. Arguments are omitted because they can contain secrets.
    public func topProcesses(device: Device, endpoint: Endpoint, secrets: any SecretStore,
                            timeout: Int) async throws -> [LinuxProcess] {
        let output = try await execute(device: device, endpoint: endpoint, secrets: secrets,
            timeout: timeout,
            command: "ps -eo pid=,user=,pcpu=,pmem=,stat=,comm= --sort=-pcpu | head -n 21",
            maxResponseSize: 32 * 1024)
        return Self.parseProcesses(output)
    }

    static func parseProcesses(_ output: String) -> [LinuxProcess] {
        output.split(whereSeparator: \.isNewline).compactMap { line in
            let fields = line.split(maxSplits: 5, omittingEmptySubsequences: true,
                whereSeparator: \.isWhitespace)
            guard fields.count == 6, let pid = Int(fields[0]), pid > 0,
                  let cpu = Double(fields[2]), cpu.isFinite, cpu >= 0,
                  let memory = Double(fields[3]), memory.isFinite, memory >= 0 else { return nil }
            return LinuxProcess(pid: pid, user: String(fields[1]), cpuPercent: cpu,
                memoryPercent: memory, state: String(fields[4]), command: String(fields[5]))
        }
    }

    /// Read OS and active NixOS generation metadata without opening configuration contents.
    public func inspectSystem(device: Device, endpoint: Endpoint, secrets: any SecretStore,
                              timeout: Int) async throws -> LinuxSystemInspection {
        let script = """
        printf 'kernel\\t'; uname -sr
        if command -v nixos-version >/dev/null 2>&1; then
          printf 'distribution\\tNixOS\\n'
          printf 'nixos_version\\t'; nixos-version
          printf 'active_system\\t'; readlink -f /run/current-system 2>/dev/null || true
          [ -f /etc/nixos/flake.nix ] && printf 'configuration\\tflake.nix\\n'
          [ -f /etc/nixos/configuration.nix ] && printf 'configuration\\tconfiguration.nix\\n'
          true
        elif [ -r /etc/os-release ]; then
          distribution=$(awk -F= '
            $1 == "PRETTY_NAME" {
              value = substr($0, index($0, "=") + 1)
              first = substr(value, 1, 1)
              last = substr(value, length(value), 1)
              double_quote = sprintf("%c", 34)
              single_quote = sprintf("%c", 39)
              if ((first == double_quote && last == double_quote) ||
                  (first == single_quote && last == single_quote)) {
                value = substr(value, 2, length(value) - 2)
              }
              gsub(/[[:cntrl:]]/, " ", value)
              printf "%s", value
              found = 1
              exit
            }
            END { if (!found) printf "Linux" }
          ' /etc/os-release)
          printf 'distribution\\t%s\\n' "${distribution:-Linux}"
        else
          printf 'distribution\\tLinux\\n'
        fi
        """
        let output = try await execute(device: device, endpoint: endpoint, secrets: secrets,
            timeout: timeout, command: script, maxResponseSize: 16 * 1024)
        var values: [String: String] = [:]
        var files: [String] = []
        for line in output.split(whereSeparator: \.isNewline) {
            let fields = line.split(maxSplits: 1, omittingEmptySubsequences: false,
                whereSeparator: { $0 == "\t" })
            guard fields.count == 2 else { continue }
            let key = String(fields[0]), value = String(fields[1]).trimmingCharacters(in: .whitespacesAndNewlines)
            if key == "configuration" { files.append(value) }
            else { values[key] = value }
        }
        guard let distribution = values["distribution"], let kernel = values["kernel"],
              !distribution.isEmpty, !kernel.isEmpty else {
            throw ServiceTransportError.invalidSystemInspection
        }
        return LinuxSystemInspection(distribution: distribution, kernel: kernel,
            nixosVersion: values["nixos_version"].flatMap { $0.isEmpty ? nil : $0 },
            activeSystemPath: values["active_system"].flatMap { $0.isEmpty ? nil : $0 },
            configurationFiles: files)
    }

    /// Run one explicitly confirmed systemd action. Sudo is non-interactive and follows host policy.
    public func perform(_ action: ServiceAction, on unit: String, useSudo: Bool, device: Device,
                        endpoint: Endpoint, secrets: any SecretStore, timeout: Int) async throws -> String {
        guard Self.isValidUnit(unit) else { throw ServiceTransportError.invalidUnit }
        let privilege = useSudo ? "sudo -n " : ""
        return try await execute(device: device, endpoint: endpoint, secrets: secrets,
            timeout: timeout,
            command: "\(privilege)systemctl \(action.rawValue) \(Shell.quote(unit))",
            maxResponseSize: 32 * 1024)
    }

    /// Validate a selected NixOS flake target, or revalidate it immediately before switching.
    /// The reference is restricted to a simple flake attribute and never accepts a shell command.
    public func rebuildNixOS(_ action: NixOSRebuildAction, flakeAttribute: String?,
                             device: Device, endpoint: Endpoint, secrets: any SecretStore,
                             timeout: Int) async throws -> NixOSCommandResult {
        let command = try Self.nixosCommand(action, flakeAttribute: flakeAttribute)
        let marker = "NEXUS_REBUILD_\(UUID().uuidString.replacingOccurrences(of: "-", with: ""))="
        let reportingCommand = "{ \(command); } 2>&1; nexus_exit=$?; printf '\\n\(marker)%s\\n' \"$nexus_exit\""
        let response = try await execute(device: device, endpoint: endpoint, secrets: secrets,
            timeout: timeout, commandTimeout: 1_800, command: reportingCommand,
            maxResponseSize: 128 * 1024)
        guard let markerRange = response.range(of: marker, options: .backwards),
              let endOfLine = response[markerRange.upperBound...].firstIndex(of: "\n"),
              let exitCode = Int(response[markerRange.upperBound..<endOfLine]),
              (0...255).contains(exitCode) else {
            throw ServiceTransportError.invalidNixOSResponse
        }
        let output = String(response[..<markerRange.lowerBound])
            .trimmingCharacters(in: .newlines)
        return NixOSCommandResult(exitCode: exitCode, output: output)
    }

    public static func nixosCommand(_ action: NixOSRebuildAction,
                                    flakeAttribute: String?) throws -> String {
        let flakeOption: String
        if let flakeAttribute {
            guard flakeAttribute.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
                                      options: .regularExpression) != nil else {
                throw ServiceTransportError.invalidNixOSFlakeAttribute
            }
            flakeOption = " --flake " + Shell.quote("/etc/nixos#\(flakeAttribute)")
        } else {
            flakeOption = ""
        }
        let dryBuild = "sudo -n nixos-rebuild dry-build\(flakeOption)"
        switch action {
        case .validate:
            return dryBuild
        case .switchSystem:
            return dryBuild + " && sudo -n nixos-rebuild switch\(flakeOption)"
        }
    }

    public static func isValidUnit(_ name: String) -> Bool {
        name.range(of: "^[A-Za-z0-9][A-Za-z0-9_.:@\\-]*\\.service$",
                   options: .regularExpression) != nil
    }

    private func execute(device: Device, endpoint: Endpoint, secrets: any SecretStore,
                         timeout: Int, commandTimeout: Int? = nil, command: String,
                         maxResponseSize: Int) async throws -> String {
        try device.validate(); try endpoint.validate()
        let client = try await pipeline.connect(device: device, endpoint: endpoint,
            secrets: secrets, timeout: timeout)

        do {
            try Task.checkCancellation()
            let bounded = Self.bounded(command, timeout: commandTimeout ?? timeout)
            let buffer = try await client.executeCommand(bounded, maxResponseSize: maxResponseSize)
            try? await client.close()
            return String(decoding: buffer.readableBytesView, as: UTF8.self)
        } catch let failure as SSHClient.CommandFailed {
            try? await client.close()
            if failure.exitCode == 124 || failure.exitCode == 137 { throw ServiceTransportError.commandTimedOut }
            throw ServiceTransportError.commandFailed(exitCode: failure.exitCode)
        } catch {
            try? await client.close()
            if Task.isCancelled { throw CancellationError() }
            throw error
        }
    }

    private static func bounded(_ command: String, timeout: Int) -> String {
        RemoteCommandTimeout.wrap(command, timeout: timeout, maximum: 1_800, errorPrefix: "nexus_service_error")
    }
}

public enum ServiceTransportError: LocalizedError {
    case invalidUnit
    case invalidSystemInspection
    case invalidNixOSFlakeAttribute
    case invalidNixOSResponse
    case commandTimedOut
    case commandFailed(exitCode: Int)

    public var errorDescription: String? {
        switch self {
        case .invalidUnit: return "Nexus rejected an invalid systemd service name."
        case .invalidSystemInspection: return "The host returned incomplete system information."
        case .invalidNixOSFlakeAttribute: return "Enter a valid flake output attribute using letters, numbers, periods, underscores, or hyphens."
        case .invalidNixOSResponse: return "Nexus could not read the result of the NixOS operation. Inspect the host before retrying."
        case .commandTimedOut: return "The remote command exceeded its time limit."
        case .commandFailed(let exitCode): return "The remote command failed with exit code \(exitCode). Check the SSH account's permissions and the remote system state."
        }
    }
}
