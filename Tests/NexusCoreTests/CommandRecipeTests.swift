import XCTest
@testable import NexusCore

final class CommandRecipeTests: XCTestCase {
    func testRenderShellQuotesEveryRuntimeValueAndRequiresExactParameters() throws {
        let recipe = CommandRecipe(name: "Show service", commandTemplate: "systemctl status {{unit}} --no-pager")
        XCTAssertEqual(try recipe.render(parameters: ["unit": "ssh.service; touch /tmp/no"]),
                       "systemctl status 'ssh.service; touch /tmp/no' --no-pager")
        XCTAssertThrowsError(try recipe.render(parameters: [:]))
        XCTAssertThrowsError(try recipe.render(parameters: ["unit": "ssh.service", "extra": "x"]))
        XCTAssertThrowsError(try recipe.render(parameters: ["unit": ""]))
        XCTAssertThrowsError(try recipe.render(parameters: ["unit": "a\0b"]))
    }

    func testRejectsParametersInQuotedAndCommentContextsAtValidationTime() {
        for template in [
            "printf '%s' '{{value}}'",
            "printf \"%s\" \"{{value}}\"",
            "echo {{value}} # {{comment}}",
        ] {
            XCTAssertThrowsError(try CommandRecipe(name: "Unsafe", commandTemplate: template).validate(), template)
        }
        XCTAssertThrowsError(try CommandRecipe(name: "Unsafe", commandTemplate: "cat <<EOF\n{{value}}\nEOF").validate())
    }

    func testRejectsInlineSecretAssignmentsAndSensitiveParameterNames() {
        for template in [
            "API_TOKEN=example-value ./client",
            "AWS_SECRET_ACCESS_KEY=example-value ./client",
            "curl --password example-value https://service.invalid",
            "./client --api-key=example-value",
        ] {
            XCTAssertThrowsError(try CommandRecipe(name: "Unsafe", commandTemplate: template).validate(), template)
        }
        for parameter in ["password", "accessToken", "private_key", "sshKey"] {
            let recipe = CommandRecipe(name: "Unsafe", commandTemplate: "./client {{\(parameter)}}")
            XCTAssertThrowsError(try recipe.validate(), parameter)
        }
    }

    func testAllowsServerSideProtectedEnvironmentReferences() throws {
        let recipe = CommandRecipe(name: "Use configured account",
            commandTemplate: "TOKEN=\"$TOKEN\" ./client --endpoint {{endpoint}}")
        XCTAssertEqual(try recipe.render(parameters: ["endpoint": "server.example"]),
                       "TOKEN=\"$TOKEN\" ./client --endpoint 'server.example'")
    }

    func testRejectsMalformedPlaceholdersAndOversizedInputs() {
        for template in ["echo {{}}", "echo {{2bad}}", "echo {{open", "echo close}}",
                         "echo " + String(repeating: "x", count: 4_097)] {
            XCTAssertThrowsError(try CommandRecipe(name: "Check", commandTemplate: template).validate(), template)
        }
    }
}
