import SwiftUI
import UIKit
import WebKit
import NexusCore

struct MinecraftPanelView: View {
    @Bindable var store: AppStore
    var cloudflareAccessLoginHost: String? = nil
    @State private var reloadID = UUID()
    @State private var loadFailed = false
    @State private var panelAddress = ""
    @State private var configuredURL: URL?
    @State private var configurationError: String?
    @State private var editingAddress = false
    #if NEXUS_DEMO_MODE
    private var panelURL: URL? { URL(string: "https://panel.example.invalid/") }
    #else
    private var panelURL: URL? { configuredURL }
    #endif

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Debian Homelab Panel").font(.headline)
                    Text("Cloudflare Access · panel admin sign-in")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .accessibilityIdentifier("minecraft.panel.tailscale-note")
                }
                Spacer(minLength: 0)
                #if !NEXUS_DEMO_MODE
                if configuredURL != nil && !editingAddress {
                    Button("Panel address", systemImage: "gearshape") {
                        editingAddress = true
                    }
                    .labelStyle(.iconOnly)
                    .accessibilityIdentifier("minecraft.panel.edit-address")
                }
                #endif
                Button("Reload", systemImage: "arrow.clockwise") {
                    loadFailed = false
                    reloadID = UUID()
                }
                .accessibilityIdentifier("minecraft.panel.reload")
            }
            .padding(.horizontal)
            .padding(.vertical, 10)

            Divider()

            #if NEXUS_DEMO_MODE
            demoPanelContent
            #else
            if let panelURL, !editingAddress {
                if loadFailed {
                ContentUnavailableView {
                    Label("Panel unavailable", systemImage: "network.slash")
                } description: {
                    Text("Cloudflare Access may ask you to sign in in this panel. After Access returns here, sign in to the panel account.")
                } actions: {
                    Button("Retry") {
                        loadFailed = false
                        reloadID = UUID()
                    }
                    .buttonStyle(.borderedProminent)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                MinecraftPanelWebView(url: panelURL, reloadID: reloadID,
                    cloudflareAccessLoginHost: cloudflareAccessLoginHost) { failed in
                    loadFailed = failed
                }
            }
            } else {
                panelSetup
            }
            #endif
        }
        .navigationTitle("Minecraft")
        .navigationBarTitleDisplayMode(.inline)
        .background(NexusPalette.background.ignoresSafeArea())
        .tint(NexusPalette.blue)
        .onAppear(perform: loadPanelConfiguration)
    }

    private var panelSetup: some View {
        ContentUnavailableView {
            Label("Set up your panel", systemImage: "server.rack")
        } description: {
            VStack(spacing: 12) {
                Text("Enter the panel’s HTTPS address. Nexus stores it in this device’s Keychain and does not include it in exports.")
                TextField("https://your-panel.example", text: $panelAddress)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("minecraft.panel.address")
                if let configurationError {
                    Text(configurationError).foregroundStyle(.red)
                }
            }
        } actions: {
            Button("Save panel address") {
                do {
                    try store.saveMinecraftPanelURL(panelAddress)
                    configuredURL = try store.minecraftPanelURL()
                    configurationError = nil
                    editingAddress = false
                } catch {
                    configurationError = error.localizedDescription
                }
            }
            .buttonStyle(.borderedProminent)
            .accessibilityIdentifier("minecraft.panel.save-address")
            if configuredURL != nil {
                Button("Cancel") { editingAddress = false }
                    .accessibilityIdentifier("minecraft.panel.cancel-address")
            }
        }
        .padding()
    }

    #if NEXUS_DEMO_MODE
    private var demoPanelContent: some View {
        ContentUnavailableView("Panel unavailable", systemImage: "network.slash",
            description: Text("The simulator preview uses fictional data and does not load a private server panel."))
    }
    #endif

    private func loadPanelConfiguration() {
        #if !NEXUS_DEMO_MODE
        do {
            configuredURL = try store.minecraftPanelURL()
            panelAddress = configuredURL?.absoluteString ?? ""
        } catch {
            configurationError = "Unlock Nexus and reopen this screen to load the saved panel address."
        }
        #endif
    }
}

private struct MinecraftPanelWebView: UIViewRepresentable {
    let url: URL
    let reloadID: UUID
    let cloudflareAccessLoginHost: String?
    let onLoadFailure: (Bool) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(allowedOrigin: HTTPSOrigin(url: url), cloudflareAccessLoginHost: cloudflareAccessLoginHost,
            onLoadFailure: onLoadFailure)
    }

    func makeUIView(context: Context) -> WKWebView {
        let webView = WKWebView(frame: .zero, configuration: WKWebViewConfiguration())
        webView.navigationDelegate = context.coordinator
        webView.allowsBackForwardNavigationGestures = true
        webView.load(URLRequest(url: url, timeoutInterval: 20))
        context.coordinator.lastReloadID = reloadID
        context.coordinator.lastLoadedURL = url
        return webView
    }

    func updateUIView(_ webView: WKWebView, context: Context) {
        context.coordinator.onLoadFailure = onLoadFailure
        if context.coordinator.lastLoadedURL != url {
            context.coordinator.lastLoadedURL = url
            context.coordinator.allowedOrigin = HTTPSOrigin(url: url)
            context.coordinator.lastReloadID = reloadID
            webView.load(URLRequest(url: url, timeoutInterval: 20))
            return
        }
        guard context.coordinator.lastReloadID != reloadID else { return }
        context.coordinator.lastReloadID = reloadID
        webView.load(URLRequest(url: url, timeoutInterval: 20))
    }

    final class Coordinator: NSObject, WKNavigationDelegate {
        var allowedOrigin: HTTPSOrigin
        let cloudflareAccessLoginHost: String?
        var onLoadFailure: (Bool) -> Void
        var lastReloadID: UUID?
        var lastLoadedURL: URL?

        init(allowedOrigin: HTTPSOrigin, cloudflareAccessLoginHost: String?, onLoadFailure: @escaping (Bool) -> Void) {
            self.allowedOrigin = allowedOrigin
            self.cloudflareAccessLoginHost = cloudflareAccessLoginHost
            self.onLoadFailure = onLoadFailure
        }

        func webView(
            _ webView: WKWebView,
            decidePolicyFor navigationAction: WKNavigationAction,
            decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
        ) {
            guard let target = navigationAction.request.url, isAllowedOrigin(target) || isAllowedAccessSignIn(target) else {
                decisionHandler(.cancel)
                return
            }
            decisionHandler(.allow)
        }

        func webView(
            _ webView: WKWebView,
            decidePolicyFor navigationResponse: WKNavigationResponse,
            decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void
        ) {
            guard let target = navigationResponse.response.url,
                  isAllowedOrigin(target) || isAllowedAccessSignIn(target) else {
                decisionHandler(.cancel)
                return
            }
            decisionHandler(.allow)
        }

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            onLoadFailure(false)
        }

        func webView(
            _ webView: WKWebView,
            didFailProvisionalNavigation navigation: WKNavigation!,
            withError error: Error
        ) {
            reportNavigationFailure(error)
        }

        func webView(
            _ webView: WKWebView,
            didFail navigation: WKNavigation!,
            withError error: Error
        ) {
            reportNavigationFailure(error)
        }

        private func reportNavigationFailure(_ error: Error) {
            guard (error as NSError).code != NSURLErrorCancelled else { return }
            onLoadFailure(true)
        }

        private func isAllowedOrigin(_ url: URL) -> Bool {
            allowedOrigin.allows(url)
        }

        private func isAllowedAccessSignIn(_ url: URL) -> Bool {
            url.scheme?.lowercased() == "https" && url.host?.caseInsensitiveCompare(cloudflareAccessLoginHost ?? "") == .orderedSame
                && (url.port ?? 443) == 443 && url.user == nil && url.password == nil
        }
    }
}
