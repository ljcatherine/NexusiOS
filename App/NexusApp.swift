import SwiftUI
import LocalAuthentication
import UserNotifications
import NexusCore
import NexusSSH

#if !NEXUS_DEMO_MODE
@main
struct NexusApp: App {
    @State private var store = AppStore()
    @Environment(\.scenePhase) private var scenePhase
    init() {
        UNUserNotificationCenter.current().delegate = NexusNotificationPresenter.shared
    }
    var body: some Scene {
        WindowGroup {
            RootView(store: store)
                // Respect the user's configured Dynamic Type instead of forcing
                // the entire interface to be at least Extra Large on every
                // device. That minimum caused compact iPhone controls to crowd.
                .disabled(store.locked || scenePhase != .active)
                .accessibilityHidden(store.locked || scenePhase != .active)
                .preferredColorScheme(store.theme == "system" ? nil : (store.theme == "dark" ? .dark : .light))
                .overlay {
                    if store.locked || scenePhase != .active {
                        VStack(spacing: 20) {
                            Image(systemName: "lock.shield").font(.largeTitle)
                            Text("Nexus is locked").font(.title2)
                            if store.locked {
                                Button("Unlock") { Task { await store.unlock() } }.buttonStyle(.borderedProminent)
                            }
                        }
                        .frame(maxWidth: .infinity, maxHeight: .infinity).background(.background)
                    }
                }
                .task {
                    await store.becameActive()
                    if store.locked { await store.unlock() }
                }
                .onChange(of: scenePhase) { _, phase in
                    if phase == .background { store.suspend() }
                    if phase == .active { Task { await store.becameActive() } }
                }
        }
    }
}
#endif

private final class NexusNotificationPresenter: NSObject, UNUserNotificationCenterDelegate {
    static let shared = NexusNotificationPresenter()

    func userNotificationCenter(_ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .sound])
    }
}
