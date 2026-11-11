import XCTest
import Dispatch
@testable import NexusCore

final class BoundedDNSResolverTests: XCTestCase {
    func testReturnsInjectedLookupResult() async {
        let result = await BoundedDNSResolver.resolve(host: "host.test") { host in
            .resolved(addresses: [host], milliseconds: 3)
        }

        XCTAssertEqual(result, .resolved(addresses: ["host.test"], milliseconds: 3))
    }

    func testTimeoutReturnsWithoutWaitingForBlockingLookup() async {
        let enteredLookup = DispatchSemaphore(value: 0)
        let releaseLookup = DispatchSemaphore(value: 0)
        let result = await BoundedDNSResolver.resolve(host: "slow.test", timeout: 0.05) { _ in
            enteredLookup.signal()
            _ = releaseLookup.wait(timeout: .now() + 2)
            return .resolved(addresses: ["192.0.2.11"], milliseconds: 250)
        }

        XCTAssertEqual(enteredLookup.wait(timeout: .now() + 1), .success)
        releaseLookup.signal()
        XCTAssertEqual(result, .failed("Timed out after 1 seconds"))
    }

    func testCancellationReturnsAndDiscardsLateLookupResult() async throws {
        let enteredLookup = DispatchSemaphore(value: 0)
        let releaseLookup = DispatchSemaphore(value: 0)
        let task = Task {
            await BoundedDNSResolver.resolve(host: "cancel.test", timeout: 5) { _ in
                enteredLookup.signal()
                _ = releaseLookup.wait(timeout: .now() + 2)
                return .resolved(addresses: ["192.0.2.12"], milliseconds: 250)
            }
        }

        XCTAssertEqual(enteredLookup.wait(timeout: .now() + 1), .success)
        task.cancel()
        let result = await task.value
        releaseLookup.signal()

        XCTAssertEqual(result, .failed("Lookup cancelled"))
    }

    func testInvalidTimeoutUsesSafeDefault() async {
        let result = await BoundedDNSResolver.resolve(host: "host.test", timeout: .infinity) { _ in
            .resolved(addresses: ["192.0.2.13"], milliseconds: 1)
        }

        XCTAssertEqual(result, .resolved(addresses: ["192.0.2.13"], milliseconds: 1))
    }
}
