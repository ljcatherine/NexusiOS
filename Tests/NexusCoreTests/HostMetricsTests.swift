import XCTest
@testable import NexusCore

final class HostMetricsTests: XCTestCase {
    private let observedAt = Date(timeIntervalSince1970: 1_750_000_000)

    func testRefreshRegistryRejectsLateCompletionsAfterReplacementOrInvalidation() {
        let deviceID = UUID()
        var registry = HostMetricsRefreshRegistry()

        let first = registry.begin(deviceID: deviceID)
        XCTAssertTrue(registry.isCurrent(first, for: deviceID))

        let replacement = registry.begin(deviceID: deviceID)
        XCTAssertFalse(registry.isCurrent(first, for: deviceID))
        XCTAssertFalse(registry.finish(first, for: deviceID))
        XCTAssertTrue(registry.isCurrent(replacement, for: deviceID))
        XCTAssertTrue(registry.finish(replacement, for: deviceID))
        XCTAssertFalse(registry.isCurrent(replacement, for: deviceID))

        let invalidated = registry.begin(deviceID: deviceID)
        registry.invalidate(deviceID: deviceID)
        XCTAssertFalse(registry.isCurrent(invalidated, for: deviceID))
        XCTAssertFalse(registry.finish(invalidated, for: deviceID))
    }

    func testRefreshRegistryTracksDevicesIndependently() {
        let firstDevice = UUID()
        let secondDevice = UUID()
        var registry = HostMetricsRefreshRegistry()
        let first = registry.begin(deviceID: firstDevice)
        let second = registry.begin(deviceID: secondDevice)

        registry.invalidate(deviceID: firstDevice)

        XCTAssertFalse(registry.isCurrent(first, for: firstDevice))
        XCTAssertTrue(registry.isCurrent(second, for: secondDevice))
    }

    func testParserReadsSupportedValuesAndIgnoresUnknownRecords() throws {
        let payload = """
        nexus_metrics\t1
        uptime\t12345.5
        load\t1.2\t0.8\t0.4
        cpu_count\t8
        cpu_utilization\t42.5
        memory\t1000\t250
        filesystem\t10000\t6000\t4000
        network\teth0\t1200\t3400
        nvidia_tool\tavailable
        nvidia\t0\t75\t8192\t2048\t61
        future_field\tignored
        """

        let result = try HostMetricsParser.parse(payload, observedAt: observedAt)

        XCTAssertEqual(result.observedAt, observedAt)
        XCTAssertEqual(result.uptimeSeconds, 12_345.5)
        XCTAssertEqual(result.loadAverage?.oneMinute, 1.2)
        XCTAssertEqual(result.logicalCPUCount, 8)
        XCTAssertEqual(result.cpuUtilizationPercent, 42.5)
        XCTAssertEqual(result.memoryTotalBytes, 1_000)
        XCTAssertEqual(result.memoryAvailableBytes, 250)
        XCTAssertEqual(result.rootFilesystem?.usedBytes, 6_000)
        XCTAssertEqual(result.networkInterfaces.map(\.interface), ["eth0"])
        XCTAssertTrue(result.nvidiaSMIAvailable)
        XCTAssertEqual(result.nvidiaGPUs.first?.temperatureCelsius, 61)
    }

    func testParserRejectsWrongProtocolHeader() {
        XCTAssertThrowsError(try HostMetricsParser.parse("nexus_metrics\t2\nuptime\t1"))
        XCTAssertThrowsError(try HostMetricsParser.parse("uptime\t1"))
    }

    func testParserOmitsMalformedAndOutOfRangeMeasurements() throws {
        let payload = """
        nexus_metrics\t1
        uptime\t-inf
        load\t1\tNaN\t3
        cpu_count\t0
        cpu_utilization\t101
        memory\t100\t101
        filesystem\t100\t60\t50
        network\tbad/name\t1\t2
        nvidia\t-1\t50\t100\t20\t40
        nvidia\t0\t101\t100\t20\t40
        """

        let result = try HostMetricsParser.parse(payload, observedAt: observedAt)

        XCTAssertNil(result.uptimeSeconds)
        XCTAssertNil(result.loadAverage)
        XCTAssertNil(result.logicalCPUCount)
        XCTAssertNil(result.cpuUtilizationPercent)
        XCTAssertNil(result.memoryTotalBytes)
        XCTAssertNil(result.rootFilesystem)
        XCTAssertTrue(result.networkInterfaces.isEmpty)
        XCTAssertEqual(result.nvidiaGPUs.count, 1)
        XCTAssertEqual(result.nvidiaGPUs[0].index, 0)
        XCTAssertNil(result.nvidiaGPUs[0].utilizationPercent)
        XCTAssertEqual(result.nvidiaGPUs[0].memoryTotalMiB, 100)
        XCTAssertEqual(result.nvidiaGPUs[0].memoryUsedMiB, 20)
        XCTAssertEqual(result.nvidiaGPUs[0].temperatureCelsius, 40)
    }

    func testParserAcceptsOnlyConsistentCapacityAndPartialGPUValues() throws {
        let payload = """
        nexus_metrics\t1
        memory\t100\t100
        filesystem\t100\t99\t1
        nvidia_tool\tavailable
        nvidia\t2\tinvalid\t4096\t2048\t-1
        """

        let result = try HostMetricsParser.parse(payload, observedAt: observedAt)

        XCTAssertEqual(result.memoryAvailableBytes, 100)
        XCTAssertEqual(result.rootFilesystem?.availableBytes, 1)
        XCTAssertEqual(result.nvidiaGPUs.count, 1)
        XCTAssertNil(result.nvidiaGPUs[0].utilizationPercent)
        XCTAssertEqual(result.nvidiaGPUs[0].memoryUsedMiB, 2_048)
        XCTAssertNil(result.nvidiaGPUs[0].temperatureCelsius)
    }

    func testLowResourceWarningsRequireValidInputsAndUseStrictTenPercentThreshold() {
        let exactlyTenPercent = snapshot(memoryTotal: 1_000, memoryAvailable: 100,
            filesystem: .init(totalBytes: 10_000, usedBytes: 9_000, availableBytes: 1_000))
        XCTAssertTrue(exactlyTenPercent.hasCompleteResourceWarningInputs)
        XCTAssertTrue(exactlyTenPercent.lowResourceWarnings.isEmpty)

        let belowThreshold = snapshot(memoryTotal: 1_000, memoryAvailable: 99,
            filesystem: .init(totalBytes: 10_000, usedBytes: 9_001, availableBytes: 999))
        XCTAssertEqual(Set(belowThreshold.lowResourceWarnings), Set([.memoryLow, .rootFilesystemLow]))

        let missingFilesystem = snapshot(memoryTotal: 1_000, memoryAvailable: 99, filesystem: nil)
        XCTAssertFalse(missingFilesystem.hasCompleteResourceWarningInputs)
        XCTAssertEqual(missingFilesystem.lowResourceWarnings, [.memoryLow])

        let invalidMemory = snapshot(memoryTotal: 1_000, memoryAvailable: 1_001,
            filesystem: .init(totalBytes: 10_000, usedBytes: 9_500, availableBytes: 500))
        XCTAssertFalse(invalidMemory.hasCompleteResourceWarningInputs)
        XCTAssertEqual(invalidMemory.lowResourceWarnings, [.rootFilesystemLow])

        let inconsistentFilesystem = snapshot(memoryTotal: 1_000, memoryAvailable: 500,
            filesystem: .init(totalBytes: 10_000, usedBytes: 9_500, availableBytes: 600))
        XCTAssertFalse(inconsistentFilesystem.hasCompleteResourceWarningInputs)
        XCTAssertTrue(inconsistentFilesystem.lowResourceWarnings.isEmpty)

        let overusedFilesystem = snapshot(memoryTotal: 1_000, memoryAvailable: 500,
            filesystem: .init(totalBytes: 10_000, usedBytes: 10_001, availableBytes: 0))
        XCTAssertFalse(overusedFilesystem.hasCompleteResourceWarningInputs)
        XCTAssertTrue(overusedFilesystem.lowResourceWarnings.isEmpty)
    }

    func testNetworkRatesUseMatchingInterfacesAndMonotonicCounters() {
        let deviceID = UUID()
        let endpoint = Endpoint(host: "server.example")
        let previous = record(deviceID: deviceID, endpoint: endpoint, time: 100,
            counters: [.init(interface: "eth0", receivedBytes: 1_000, transmittedBytes: 2_000),
                      .init(interface: "wlan0", receivedBytes: 10, transmittedBytes: 20)])
        let current = record(deviceID: deviceID, endpoint: endpoint, time: 110,
            counters: [.init(interface: "eth0", receivedBytes: 1_500, transmittedBytes: 2_800),
                      .init(interface: "eth1", receivedBytes: 50, transmittedBytes: 60),
                      .init(interface: "wlan0", receivedBytes: 9, transmittedBytes: 25)])

        let rates = HostNetworkRateCalculator.rates(for: deviceID, in: [current, previous])

        XCTAssertEqual(rates.map(\.interface), ["eth0"])
        XCTAssertEqual(rates.first?.receivedBytesPerSecond, 50)
        XCTAssertEqual(rates.first?.transmittedBytesPerSecond, 80)
        XCTAssertEqual(rates.first?.intervalSeconds, 10)
    }

    func testNetworkRatesRequireSameDeviceAuthorityAndPositiveInterval() {
        let deviceID = UUID()
        let endpoint = Endpoint(host: "server.example")
        let counter = HostNetworkCounters(interface: "eth0", receivedBytes: 10, transmittedBytes: 20)
        let earlier = record(deviceID: deviceID, endpoint: endpoint, time: 100, counters: [counter])
        let later = record(deviceID: deviceID, endpoint: endpoint, time: 100, counters: [counter])
        XCTAssertTrue(HostNetworkRateCalculator.rates(for: deviceID, in: [earlier, later]).isEmpty)

        let otherEndpoint = Endpoint(host: "other.example")
        let fromOtherEndpoint = record(deviceID: deviceID, endpoint: otherEndpoint, time: 110, counters: [counter])
        XCTAssertTrue(HostNetworkRateCalculator.rates(for: deviceID, in: [earlier, fromOtherEndpoint]).isEmpty)

        let otherDevice = record(deviceID: UUID(), endpoint: endpoint, time: 110,
            counters: [.init(interface: "eth0", receivedBytes: 100, transmittedBytes: 200)])
        let validLater = record(deviceID: deviceID, endpoint: endpoint, time: 110,
            counters: [.init(interface: "eth0", receivedBytes: 20, transmittedBytes: 40)])
        XCTAssertEqual(HostNetworkRateCalculator.rates(for: deviceID, in: [earlier, otherDevice, validLater]).count, 1)
    }

    func testHistoryBelongsOnlyToCurrentSSHIdentityAndSavedEndpoint() {
        let deviceID = UUID()
        let endpoint = Endpoint(host: "server.example")
        let device = Device(id: deviceID, name: "Fixture", username: "admin", endpoints: [endpoint])
        let sample = record(deviceID: deviceID, endpoint: endpoint, time: 100,
            counters: [.init(interface: "eth0", receivedBytes: 10, transmittedBytes: 20)],
            username: "admin", authentication: .ed25519)

        XCTAssertTrue(sample.belongs(to: device))
        XCTAssertFalse(sample.belongs(to: Device(id: deviceID, name: "Fixture", username: "other",
            endpoints: [endpoint])))
        XCTAssertFalse(sample.belongs(to: Device(id: deviceID, name: "Fixture", username: "admin",
            endpoints: [endpoint], authentication: .legacyPassword)))
        XCTAssertFalse(sample.belongs(to: Device(id: deviceID, name: "Fixture", username: "admin",
            endpoints: [Endpoint(host: "other.example")])))

        let legacy = record(deviceID: deviceID, endpoint: endpoint, time: 90,
            counters: [], username: nil, authentication: nil)
        XCTAssertFalse(legacy.belongs(to: device))
    }

    func testNetworkRatesResetAcrossBootsEvenWhenCountersHaveGrown() {
        let deviceID = UUID()
        let endpoint = Endpoint(host: "server.example")
        let firstBoot = UUID()
        let secondBoot = UUID()
        let previous = record(deviceID: deviceID, endpoint: endpoint, time: 100,
            counters: [.init(interface: "eth0", receivedBytes: 100, transmittedBytes: 200)],
            bootID: firstBoot, uptime: 50)
        let afterReboot = record(deviceID: deviceID, endpoint: endpoint, time: 200,
            counters: [.init(interface: "eth0", receivedBytes: 500, transmittedBytes: 800)],
            bootID: secondBoot, uptime: 60)
        XCTAssertTrue(HostNetworkRateCalculator.rates(for: deviceID, in: [previous, afterReboot]).isEmpty)

        let next = record(deviceID: deviceID, endpoint: endpoint, time: 210,
            counters: [.init(interface: "eth0", receivedBytes: 600, transmittedBytes: 1_000)],
            bootID: secondBoot, uptime: 70)
        let rates = HostNetworkRateCalculator.rates(for: deviceID, in: [previous, afterReboot, next])
        XCTAssertEqual(rates.first?.receivedBytesPerSecond, 10)
        XCTAssertEqual(rates.first?.transmittedBytesPerSecond, 20)
    }

    func testLegacyRatesResetWhenUptimeFallsOrBootTrackingBecomesAvailable() {
        let deviceID = UUID()
        let endpoint = Endpoint(host: "server.example")
        let previous = record(deviceID: deviceID, endpoint: endpoint, time: 100,
            counters: [.init(interface: "eth0", receivedBytes: 100, transmittedBytes: 200)], uptime: 90)
        let afterReboot = record(deviceID: deviceID, endpoint: endpoint, time: 110,
            counters: [.init(interface: "eth0", receivedBytes: 500, transmittedBytes: 800)], uptime: 5)
        XCTAssertTrue(HostNetworkRateCalculator.rates(for: deviceID, in: [previous, afterReboot]).isEmpty)
        let firstTracked = record(deviceID: deviceID, endpoint: endpoint, time: 120,
            counters: [.init(interface: "eth0", receivedBytes: 600, transmittedBytes: 900)],
            bootID: UUID(), uptime: 110)
        XCTAssertTrue(HostNetworkRateCalculator.rates(for: deviceID, in: [previous, firstTracked]).isEmpty)
    }

    func testBootIdentityParsingAndLegacyHistoryDecoding() throws {
        let bootID = UUID()
        let snapshot = try HostMetricsParser.parse("nexus_metrics\t1\nboot_id\t\(bootID.uuidString)\nuptime\t10")
        XCTAssertEqual(snapshot.bootID, bootID)
        XCTAssertEqual(try HostMetricsParser.parse("nexus_metrics\t1\nboot_id\tnot-a-uuid").bootID, nil)
        let encoded = try JSONEncoder().encode(snapshot)
        XCTAssertEqual(try JSONDecoder().decode(HostMetricsSnapshot.self, from: encoded).bootID, bootID)
        var legacy = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        legacy.removeValue(forKey: "bootID")
        let decoded = try JSONDecoder().decode(HostMetricsSnapshot.self,
            from: JSONSerialization.data(withJSONObject: legacy))
        XCTAssertNil(decoded.bootID)
        XCTAssertEqual(decoded.uptimeSeconds, 10)
    }

    private func snapshot(memoryTotal: UInt64?, memoryAvailable: UInt64?,
                          filesystem: HostFilesystemUsage?) -> HostMetricsSnapshot {
        HostMetricsSnapshot(observedAt: observedAt, uptimeSeconds: nil, loadAverage: nil,
            logicalCPUCount: nil, cpuUtilizationPercent: nil,
            memoryTotalBytes: memoryTotal, memoryAvailableBytes: memoryAvailable,
            rootFilesystem: filesystem, networkInterfaces: [],
            nvidiaSMIAvailable: false, nvidiaGPUs: [])
    }

    private func record(deviceID: UUID, endpoint: Endpoint, time: TimeInterval,
                        counters: [HostNetworkCounters], username: String? = nil,
                        authentication: AuthenticationKind? = nil, bootID: UUID? = nil,
                        uptime: Double? = nil) -> HostMetricsHistoryRecord {
        let snapshot = HostMetricsSnapshot(observedAt: Date(timeIntervalSince1970: time),
            uptimeSeconds: uptime, loadAverage: nil, logicalCPUCount: nil,
            cpuUtilizationPercent: nil, memoryTotalBytes: nil,
            memoryAvailableBytes: nil, rootFilesystem: nil,
            networkInterfaces: counters, nvidiaSMIAvailable: false, nvidiaGPUs: [], bootID: bootID)
        return HostMetricsHistoryRecord(deviceID: deviceID, deviceName: "Fixture",
            endpoint: endpoint, sshUsername: username, authentication: authentication, snapshot: snapshot)
    }
}
