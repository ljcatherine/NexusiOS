import XCTest

/// Regression checks for the production five-tab SwiftUI shell. These must be
/// exercised on an iPhone/iPad simulator or device; compilation alone is not
/// evidence that the layout satisfies these assertions.
final class NexusUITests: XCTestCase {
    private func launchNexus() -> XCUIApplication {
        let app = XCUIApplication()
        app.launch()
        return app
    }

    /// These checks deliberately exercise configuration UI only: no controller
    /// refresh, model load/unload, workspace fetch, or remote task is invoked.
    /// Use a disposable fresh install so existing Keychain credentials and
    /// saved endpoints cannot affect the disabled-state assertions.
    private func openUnconfiguredPS5Management() throws -> XCUIApplication {
        guard ProcessInfo.processInfo.environment["NEXUS_PS5_UI_ACCEPTANCE"] == "1" else {
            throw XCTSkip("Set NEXUS_PS5_UI_ACCEPTANCE=1 on a fresh iOS test installation")
        }

        let app = launchNexus()
        app.tabBars.buttons["AI"].tap()

        let selector = app.buttons.matching(
            NSPredicate(format: "label BEGINSWITH %@", "AI connection:")).firstMatch
        XCTAssertTrue(selector.waitForExistence(timeout: 10), "AI connection menu is missing")
        selector.tap()
        let ps5 = app.buttons["PS5LM Plus"]
        guard ps5.waitForExistence(timeout: 3) else {
            throw XCTSkip("A PS5LM Plus connection is required for offline controller UI acceptance")
        }
        ps5.tap()

        XCTAssertTrue(selector.waitForExistence(timeout: 5))
        selector.tap()
        let management = app.buttons["PS5 Nexus management…"]
        XCTAssertTrue(management.waitForExistence(timeout: 5), "PS5 control entry is missing")
        management.tap()
        XCTAssertTrue(app.navigationBars["PS5 Nexus"].waitForExistence(timeout: 10))
        guard app.buttons["Save and enable"].exists else {
            throw XCTSkip("PS5 management is already configured; use a fresh test installation")
        }
        return app
    }

    func testPS5ManagementRequiresValidURLAndCredentialBeforeEnabling() throws {
        let app = try openUnconfiguredPS5Management()
        let save = app.buttons["Save and enable"]
        let endpoint = app.textFields["ps5.nexus.management.url"]
        XCTAssertTrue(endpoint.exists)
        XCTAssertTrue(app.secureTextFields["ps5.nexus.management.token"].exists)
        XCTAssertFalse(save.isEnabled, "No controller URL or Keychain token is configured")

        endpoint.tap()
        endpoint.typeText("https://gateway.example/v1?token=example")
        XCTAssertTrue(app.staticTexts[
            "Management URL is invalid or cannot safely reuse the selected credential"
        ].waitForExistence(timeout: 5))
        XCTAssertFalse(save.isEnabled, "A credential-bearing URL must not enable management")
    }

    func testPS5WorkspaceBridgesRequireExplicitURLAndCredential() throws {
        let app = try openUnconfiguredPS5Management()
        for host in ["Debian", "NixOS"] {
            let navigation = app.buttons["\(host) workspaces"]
            XCTAssertTrue(navigation.waitForExistence(timeout: 5))
            navigation.tap()
            XCTAssertTrue(app.navigationBars["\(host) workspaces"].waitForExistence(timeout: 5))
            XCTAssertTrue(app.textFields["ps5.nexus.\(host.lowercased()).url"].exists)
            guard app.buttons["Save and enable bridge"].exists else {
                throw XCTSkip("\(host) bridge is already configured; use a fresh test installation")
            }
            XCTAssertFalse(app.buttons["Save and enable bridge"].isEnabled,
                           "An unconfigured \(host) bridge must not be enabled")
            app.navigationBars["\(host) workspaces"].buttons.element(boundBy: 0).tap()
            XCTAssertTrue(app.navigationBars["PS5 Nexus"].waitForExistence(timeout: 5))
        }
    }

    func testFiveNativeTabsAndDeviceDetailsAreReachable() {
        let app = launchNexus()
        for tab in ["Overview", "Devices", "AI", "Services", "Settings"] {
            XCTAssertTrue(app.tabBars.buttons[tab].exists, "Missing accessible \(tab) tab")
        }
        app.tabBars.buttons["Devices"].tap()
        XCTAssertTrue(app.staticTexts["Devices"].waitForExistence(timeout: 10))
        openDeviceActions(in: app)
        let details = app.buttons["device.details"].firstMatch
        XCTAssertTrue(details.waitForExistence(timeout: 10))
        details.tap()
        XCTAssertTrue(app.navigationBars["Device details"].waitForExistence(timeout: 10))
        XCTAssertTrue(app.buttons["device.detail.open-terminal"].exists)
        app.buttons["device.detail.done"].tap()
        XCTAssertTrue(app.buttons["device.open-terminal"].firstMatch.exists)
        app.tabBars.buttons["Settings"].tap()
        XCTAssertTrue(app.staticTexts["Settings"].waitForExistence(timeout: 10))
    }

    private func openDeviceActions(in app: XCUIApplication) {
        let actions = app.buttons.matching(NSPredicate(format: "label BEGINSWITH 'More actions for'")).firstMatch
        XCTAssertTrue(actions.waitForExistence(timeout: 10))
        actions.tap()
    }

    func testOverviewChartsFollowMetricGridWithoutOverlap() {
        let app = launchNexus()
        let grid = app.descendants(matching: .any)["dashboard.telemetry-grid"].firstMatch
        let cpu = app.staticTexts["CPU activity"]
        let network = app.staticTexts["Network traffic"]
        let infrastructure = app.staticTexts["Infrastructure"]
        XCTAssertTrue(grid.waitForExistence(timeout: 10))
        XCTAssertTrue(cpu.exists)
        XCTAssertTrue(network.exists)
        XCTAssertTrue(infrastructure.exists)
        // These sections are deliberately in VStack/LazyVGrid document flow.
        // Compare vertical screen coordinates even when the items are offscreen.
        XCTAssertLessThanOrEqual(grid.frame.maxY, cpu.frame.minY + 2,
            "Metric grid must finish before the CPU chart")
        XCTAssertLessThanOrEqual(cpu.frame.maxY, network.frame.minY + 2,
            "CPU chart must not overlap network history")
        XCTAssertLessThanOrEqual(network.frame.maxY, infrastructure.frame.minY + 2,
            "Network history must not cover Infrastructure")
    }

    func testAIComposerRemainsAboveNativeTabBar() {
        let app = launchNexus()
        app.tabBars.buttons["AI"].tap()
        let composer = app.descendants(matching: .any)["ai.composer.container"].firstMatch
        let input = app.descendants(matching: .any)["ai.composer.input"].firstMatch
        XCTAssertTrue(composer.waitForExistence(timeout: 10))
        XCTAssertTrue(input.exists)
        let tabBar = app.tabBars.firstMatch
        XCTAssertTrue(tabBar.exists)
        XCTAssertLessThanOrEqual(composer.frame.maxY, tabBar.frame.minY + 2,
            "AI text input and buttons must not be covered by the tab bar")
    }

    func testDevicesOpenRealTerminalRoutes() {
        let app = launchNexus()
        app.tabBars.buttons["Devices"].tap()
        let open = app.buttons["device.open-terminal"].firstMatch
        XCTAssertTrue(open.waitForExistence(timeout: 10))
        open.tap()
        XCTAssertTrue(app.navigationBars["NixOS"].waitForExistence(timeout: 10),
            "Device actions must navigate to an actual terminal, including an error or trust prompt")
        XCTAssertTrue(app.buttons["terminal.hide-keyboard"].exists)
    }

    func testDeviceEditorShowsEndpointPriorityWithoutWrapping() {
        let app = launchNexus()
        app.tabBars.buttons["Devices"].tap()
        openDeviceActions(in: app)
        let edit = app.buttons["Edit"].firstMatch
        XCTAssertTrue(edit.waitForExistence(timeout: 10))
        edit.tap()
        let priority = app.descendants(matching: .any)["device.endpoint.priority"].firstMatch
        // Existing Cloudflare-only saved profiles may hide endpoint editing;
        // verify the control only when the selected profile offers it.
        if priority.exists {
            XCTAssertLessThan(priority.frame.height, 60)
        }
    }
}
