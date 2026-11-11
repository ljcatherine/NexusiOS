import SwiftUI
import Charts
import NexusCore

/// Plots timestamped SSH samples only. Missing, invalid and old values never become chart points.
struct NexusResourceTrendsChart: View {
    let history: [HostMetricsHistoryRecord]
    var now: Date = .now

    private struct Sample: Identifiable {
        let id: String
        let date: Date
        let resource: String
        let percent: Double
    }

    private var samples: [Sample] {
        history
            .filter { $0.snapshot.observedAt >= now.addingTimeInterval(-60) && $0.snapshot.observedAt <= now }
            .sorted { $0.snapshot.observedAt < $1.snapshot.observedAt }
            .flatMap { record -> [Sample] in
                let snapshot = record.snapshot
                var points: [Sample] = []
                if let total = snapshot.memoryTotalBytes, let available = snapshot.memoryAvailableBytes,
                   total > 0, available <= total {
                    points.append(Sample(id: "\(record.id)-memory", date: snapshot.observedAt,
                                         resource: "Memory", percent: Double(total - available) / Double(total) * 100))
                }
                if let disk = snapshot.rootFilesystem, disk.totalBytes > 0,
                   disk.usedBytes <= disk.totalBytes {
                    points.append(Sample(id: "\(record.id)-storage", date: snapshot.observedAt,
                                         resource: "Storage", percent: Double(disk.usedBytes) / Double(disk.totalBytes) * 100))
                }
                return points
            }
    }

    var body: some View {
        if samples.isEmpty {
            ContentUnavailableView("No recent resource samples", systemImage: "chart.xyaxis.line",
                description: Text("Check a device to measure memory and storage."))
                .frame(height: 180)
        } else {
            Chart(samples) { sample in
                LineMark(x: .value("Time", sample.date), y: .value("Used (%)", sample.percent))
                    .foregroundStyle(by: .value("Resource", sample.resource))
                    .lineStyle(StrokeStyle(lineWidth: 2.5, lineCap: .round))
                PointMark(x: .value("Time", sample.date), y: .value("Used (%)", sample.percent))
                    .foregroundStyle(by: .value("Resource", sample.resource))
            }
            .chartForegroundStyleScale(["Memory": NexusPalette.purple, "Storage": NexusPalette.green])
            .chartYScale(domain: 0...100)
            .chartXAxis(.hidden)
            .frame(height: 180)
            .accessibilityLabel("Measured memory and storage utilization over the last minute")
        }
    }
}

/// Calculates each network datapoint from a verified pair of measured counter snapshots.
/// The first SSH sample alone cannot establish throughput, and a reboot/counter reset is skipped.
struct NexusNetworkTrendsChart: View {
    let history: [HostMetricsHistoryRecord]
    let deviceID: UUID
    var now: Date = .now

    private struct Sample: Identifiable {
        let id: String
        let date: Date
        let direction: String
        let megabitsPerSecond: Double
    }

    private var samples: [Sample] {
        let ordered = history.sorted { $0.snapshot.observedAt < $1.snapshot.observedAt }
        guard ordered.count >= 2 else { return [] }
        return (1..<ordered.count).flatMap { index -> [Sample] in
            let previous = ordered[index - 1]
            let current = ordered[index]
            let date = current.snapshot.observedAt
            guard date >= now.addingTimeInterval(-60), date <= now else { return [] }
            let rates = HostNetworkRateCalculator.rates(for: deviceID, in: [previous, current])
            guard !rates.isEmpty else { return [] }
            let down = rates.reduce(0) { $0 + $1.receivedBytesPerSecond } * 8 / 1_000_000
            let up = rates.reduce(0) { $0 + $1.transmittedBytesPerSecond } * 8 / 1_000_000
            guard down.isFinite, up.isFinite else { return [] }
            return [
                Sample(id: "\(current.id)-down", date: date, direction: "Download", megabitsPerSecond: down),
                Sample(id: "\(current.id)-up", date: date, direction: "Upload", megabitsPerSecond: up)
            ]
        }
    }

    var body: some View {
        if samples.isEmpty {
            ContentUnavailableView("No measured network rate", systemImage: "chart.xyaxis.line",
                description: Text("Refresh twice to compare SSH network counters."))
                .frame(height: 180)
        } else {
            Chart(samples) { sample in
                LineMark(x: .value("Time", sample.date), y: .value("Traffic (Mb/s)", sample.megabitsPerSecond))
                    .foregroundStyle(by: .value("Direction", sample.direction))
                    .lineStyle(StrokeStyle(lineWidth: 2.5, lineCap: .round))
                PointMark(x: .value("Time", sample.date), y: .value("Traffic (Mb/s)", sample.megabitsPerSecond))
                    .foregroundStyle(by: .value("Direction", sample.direction))
            }
            .chartForegroundStyleScale(["Download": NexusPalette.blue, "Upload": NexusPalette.amber])
            .chartYScale(domain: .automatic(includesZero: true))
            .chartXAxis(.hidden)
            .frame(height: 180)
            .accessibilityLabel("Measured network download and upload rates over the last minute in megabits per second")
        }
    }
}
