import Foundation

public struct CommandRecipe: Codable, Hashable, Identifiable, Sendable {
    public var id: UUID
    public var name: String
    public var commandTemplate: String

    public init(id: UUID = UUID(), name: String, commandTemplate: String) {
        self.id = id
        self.name = name
        self.commandTemplate = commandTemplate
    }

    public var parameterNames: [String] {
        let pattern = #"\{\{([A-Za-z][A-Za-z0-9_]*)\}\}"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
        let range = NSRange(commandTemplate.startIndex..., in: commandTemplate)
        let names = regex.matches(in: commandTemplate, range: range).compactMap { match -> String? in
            guard let range = Range(match.range(at: 1), in: commandTemplate) else { return nil }
            return String(commandTemplate[range])
        }
        return Array(Set(names)).sorted()
    }

    public func render(parameters: [String: String]) throws -> String {
        try validate()
        guard placeholdersAreUnquotedShellWords() else {
            throw CommandRecipeError.invalidPlaceholderContext
        }
        guard Set(parameters.keys) == Set(parameterNames),
              parameters.values.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 1024 && !$0.contains("\0") }) else {
            throw CommandRecipeError.invalidParameters
        }
        var rendered = commandTemplate
        for name in parameterNames {
            guard let value = parameters[name] else { throw CommandRecipeError.invalidParameters }
            rendered = rendered.replacingOccurrences(of: "{{\(name)}}", with: Shell.quote(value))
        }
        return rendered
    }

    public func validate() throws {
        guard !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              name.utf8.count <= 80,
              !commandTemplate.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              commandTemplate.utf8.count <= 4096,
              !commandTemplate.contains("\0"),
              !Self.containsInlineSecret(commandTemplate) else {
            throw CommandRecipeError.invalidRecipe
        }
        let pattern = #"\{\{([A-Za-z][A-Za-z0-9_]*)\}\}"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else {
            throw CommandRecipeError.invalidRecipe
        }
        let range = NSRange(commandTemplate.startIndex..., in: commandTemplate)
        let matches = regex.matches(in: commandTemplate, range: range)
        let stripped = regex.stringByReplacingMatches(in: commandTemplate, range: range,
            withTemplate: "")
        guard !stripped.contains("{{"), !stripped.contains("}}"), matches.count <= 20 else {
            throw CommandRecipeError.invalidRecipe
        }
        guard placeholdersAreUnquotedShellWords() else {
            throw CommandRecipeError.invalidPlaceholderContext
        }
        guard parameterNames.isEmpty || !commandTemplate.contains("<<") else {
            throw CommandRecipeError.parameterizedHereDocument
        }
        guard !parameterNames.contains(where: Self.isSensitiveParameter) else {
            throw CommandRecipeError.sensitiveParameter
        }
    }

    private static func containsInlineSecret(_ template: String) -> Bool {
        let sensitiveName = #"[A-Za-z0-9_-]*(?:password|passwd|token|secret|api[_-]?key|private[_-]?key|ssh[_-]?key|access[_-]?key)[A-Za-z0-9_-]*"#
        let pattern = "(?i)(?:--" + sensitiveName + #"(?:=|\s+)|(?:^|[;\s&|])"# + sensitiveName +
            #"(?:\s*=\s*))\s*(?:'([^']*)'|"([^"]*)"|([^\s;]+))"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return true }
        let range = NSRange(template.startIndex..., in: template)
        for match in regex.matches(in: template, range: range) {
            for group in 1..<match.numberOfRanges {
                guard let valueRange = Range(match.range(at: group), in: template) else { continue }
                let value = String(template[valueRange])
                if (value.hasPrefix("{{") && value.hasSuffix("}}")) || value.hasPrefix("$") { break }
                if !value.isEmpty { return true }
            }
        }
        return false
    }

    private static func isSensitiveParameter(_ name: String) -> Bool {
        let normalized = name.lowercased()
        return ["password", "passwd", "token", "secret", "key"].contains { normalized.contains($0) }
    }

    private func placeholdersAreUnquotedShellWords() -> Bool {
        let characters = Array(commandTemplate)
        var quote: Character?
        var escaped = false
        var comment = false
        var index = 0
        while index < characters.count {
            if comment {
                if characters[index] == "{", index + 1 < characters.count,
                   characters[index + 1] == "{" { return false }
                if characters[index] == "\n" { comment = false }
                index += 1
                continue
            }
            if characters[index] == "{", index + 1 < characters.count, characters[index + 1] == "{" {
                guard quote == nil, !escaped, !comment else { return false }
                var end = index + 2
                while end + 1 < characters.count && !(characters[end] == "}" && characters[end + 1] == "}") {
                    end += 1
                }
                index = min(characters.count, end + 2)
                continue
            }
            let character = characters[index]
            if quote == "'" {
                if character == "'" { quote = nil }
                index += 1
                continue
            }
            if escaped {
                escaped = false
                index += 1
                continue
            }
            if character == "\\" {
                escaped = true
                index += 1
                continue
            }
            if let activeQuote = quote {
                if character == activeQuote { quote = nil }
                index += 1
                continue
            }
            if character == "'" || character == "\"" { quote = character }
            else if character == "#", index == 0 || characters[index - 1].isWhitespace { comment = true }
            index += 1
        }
        return true
    }
}

public struct CommandRunRecord: Codable, Hashable, Identifiable, Sendable {
    public let id: UUID
    public let recipeName: String
    public let deviceName: String
    public let endpointAuthority: String
    public let usedSudo: Bool
    public let startedAt: Date
    public let exitCode: Int?

    public init(id: UUID = UUID(), recipeName: String, deviceName: String,
                endpointAuthority: String, usedSudo: Bool, startedAt: Date = .now, exitCode: Int?) {
        self.id = id
        self.recipeName = recipeName
        self.deviceName = deviceName
        self.endpointAuthority = endpointAuthority
        self.usedSudo = usedSudo
        self.startedAt = startedAt
        self.exitCode = exitCode
    }

    public var succeeded: Bool { exitCode == 0 }
}

public enum CommandRecipeError: LocalizedError {
    case invalidRecipe
    case invalidParameters
    case sensitiveParameter
    case invalidPlaceholderContext
    case parameterizedHereDocument

    public var errorDescription: String? {
        switch self {
        case .invalidRecipe:
            return "Enter a recipe name and command template. Use {{parameterName}} for values supplied at run time, and never include passwords, tokens, or other secrets."
        case .invalidParameters:
            return "Provide a value for every recipe parameter. Values are shell-quoted and are not saved in the recipe."
        case .sensitiveParameter:
            return "Do not pass passwords, tokens, or private keys as recipe parameters. Read credentials from a protected store on the server instead."
        case .invalidPlaceholderContext:
            return "Placeholders must appear outside shell quotes. Nexus quotes each runtime value to prevent shell injection."
        case .parameterizedHereDocument:
            return "Recipes with runtime parameters cannot contain the << sequence. Put parameters in ordinary shell words so Nexus can quote them safely."
        }
    }
}
