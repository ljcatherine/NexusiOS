import AuthenticationServices
import UIKit
import NexusCore

@MainActor
final class NativeOIDCSignIn: NSObject, ASWebAuthenticationPresentationContextProviding {
    static let shared = NativeOIDCSignIn()
    private var session: ASWebAuthenticationSession?

    func signIn(configuration: OIDCClientConfiguration) async throws -> OIDCSessionCredential {
        let metadata = try await OIDCClient.discover(configuration: configuration)
        let transaction = OIDCFlow.makeTransaction()
        let url = try OIDCFlow.authorizationURL(metadata: metadata, configuration: configuration,
                                                transaction: transaction)
        let callbackScheme = configuration.callbackURLScheme

        return try await withCheckedThrowingContinuation { continuation in
            let authenticationSession = ASWebAuthenticationSession(url: url, callbackURLScheme: callbackScheme) {
                [weak self] callback, error in
                Task { @MainActor in
                    self?.session = nil
                    do {
                        if let error { throw error }
                        guard let callback else { throw OIDCFlowError.invalidCallback }
                        let code = try OIDCFlow.authorizationCode(from: callback, configuration: configuration,
                                                                  expectedState: transaction.state)
                        let tokens = try await OIDCClient.exchange(code: code, transaction: transaction,
                            configuration: configuration, metadata: metadata)
                        continuation.resume(returning: tokens)
                    } catch { continuation.resume(throwing: error) }
                }
            }
            authenticationSession.presentationContextProvider = self
            session = authenticationSession
            guard authenticationSession.start() else {
                session = nil
                continuation.resume(throwing: OIDCFlowError.invalidCallback)
                return
            }
        }
    }

    func presentationAnchor(for _: ASWebAuthenticationSession) -> ASPresentationAnchor {
        UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap(\.windows)
            .first(where: \.isKeyWindow) ?? ASPresentationAnchor()
    }
}
