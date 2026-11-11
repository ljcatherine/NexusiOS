import Foundation
import Observation
import NexusCore
import NexusSSH

@MainActor @Observable
final class HostMonitorState {
    let deviceID: UUID
    var snapshot: HostMetricsSnapshot?
    var sourceEndpoint: Endpoint?
    var isRefreshing = false
    var lastAttempt: Date?
    var error: String?
    var historyError: String?

    init(deviceID: UUID) { self.deviceID = deviceID }
}

struct PendingHostMetricsTrust: Identifiable {
    let device: Device
    let challenge: HostKeyChallenge
    var id: String { challenge.id }
}
