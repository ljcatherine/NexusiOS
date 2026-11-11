import Foundation
import XCTest
@testable import NexusCore

final class PS5NexusPatchTests: XCTestCase {
    func testPatchLimitsAndErrorsAreConfinedToExactRoutes() {
        let root = "/nexus/workspaces/debian/code/patches"
        XCTAssertTrue(PS5NexusPatchClient.isPatchRoute(root))
        XCTAssertTrue(PS5NexusPatchClient.isPatchRoute(root + "/" + String(repeating: "a", count: 32) + "/decision"))
        for action in ["apply", "reconcile"] {
            XCTAssertTrue(PS5NexusPatchClient.isPatchRoute(root + "/" + String(repeating: "a", count: 32) + "/" + action))
        }
        for suffix in ["/apply", "-other", "/../../patches", "/" + String(repeating: "A", count: 32), "?x=1", "\n"] {
            XCTAssertFalse(PS5NexusPatchClient.isPatchRoute(root + suffix), suffix)
        }
        XCTAssertEqual(PS5NexusHTTPClient.httpFailure(404, method: "GET", path: root), .patchNotFound)
        XCTAssertEqual(PS5NexusHTTPClient.httpFailure(409, method: "POST", path: root), .patchReviewConflict)
        XCTAssertEqual(PS5NexusHTTPClient.httpFailure(409, method: "POST", path: "/nexus/models"), .failed(409))
    }
}
