import Foundation

/// A user-authored, reusable prompt guide. Skills provide conversation guidance only;
/// they do not add tools, permissions, or executable actions.
public struct AIAssistantSkill: Codable, Identifiable, Equatable, Sendable {
    public static let maximumSkills = 30
    public static let maximumLibraryBytes = 256 * 1_024
    public static let maximumInstructionBytes = 16 * 1_024

    public let id: UUID
    public var name: String
    public var summary: String
    public var instructions: String
    public var updatedAt: Date

    public init(id: UUID = UUID(), name: String, summary: String = "",
                instructions: String, updatedAt: Date = .now) {
        self.id = id
        self.name = name
        self.summary = summary
        self.instructions = instructions
        self.updatedAt = updatedAt
    }

    public var isValid: Bool {
        let cleanName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanSummary = summary.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanInstructions = instructions.trimmingCharacters(in: .whitespacesAndNewlines)
        return !cleanName.isEmpty && cleanName.utf8.count <= 80 &&
            !cleanName.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) &&
            cleanSummary.utf8.count <= 256 &&
            !cleanSummary.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) &&
            !cleanInstructions.isEmpty && cleanInstructions.utf8.count <= Self.maximumInstructionBytes &&
            !cleanInstructions.unicodeScalars.contains(where: {
                CharacterSet.controlCharacters.contains($0) && $0 != "\n" && $0 != "\t"
            })
    }

    public static func isValidLibrary(_ skills: [AIAssistantSkill]) -> Bool {
        skills.count <= maximumSkills && skills.allSatisfy(\.isValid) &&
            Set(skills.map(\.id)).count == skills.count &&
            Set(skills.map { $0.name.trimmingCharacters(in: .whitespacesAndNewlines).folding(
                options: [.caseInsensitive, .diacriticInsensitive], locale: .current) }).count == skills.count &&
            skills.reduce(0) { $0 + $1.instructions.utf8.count + $1.summary.utf8.count + $1.name.utf8.count } <= maximumLibraryBytes
    }
}
