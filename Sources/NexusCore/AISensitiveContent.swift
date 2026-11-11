import Foundation

public enum AISensitiveContentCategory: String, CaseIterable, Sendable {
    case privateKey
    case credentialAssignment
    case recognizedToken
    case imageTextCouldNotBeChecked

    public var title: String {
        switch self {
        case .privateKey: "private-key material"
        case .credentialAssignment: "a credential assignment"
        case .recognizedToken: "a token or access-key pattern"
        case .imageTextCouldNotBeChecked: "image text that Nexus could not check"
        }
    }
}

/// High-confidence warning patterns for new text sent to an AI provider.
/// The scanner returns category names only and never retains or returns matches.
public enum AISensitiveContentScanner {
    private static let patterns: [AISensitiveContentCategory: [String]] = [
        .privateKey: [#"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"#],
        .credentialAssignment: [
            #"\b(?:[A-Z0-9]+_)*(?:PASSWORD|PASSPHRASE|API[_-]?KEY|ACCESS[_-]?TOKEN|REFRESH[_-]?TOKEN|CLIENT[_-]?SECRET|SECRET[_-]?KEY|SECRET_ACCESS_KEY)\s*[:=]\s*[\"']?[^\"'\s,;]{8,}"#
        ],
        .recognizedToken: [
            #"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16})\b"#,
            #"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"#
        ]
    ]

    /// Returns ordered finding categories, never the matched values. Callers should
    /// present these as a warning and require confirmation before transmitting text.
    public static func categories(in texts: [String]) -> [AISensitiveContentCategory] {
        AISensitiveContentCategory.allCases.filter { category in
            guard let categoryPatterns = patterns[category] else { return false }
            return texts.contains { text in
                categoryPatterns.contains { pattern in
                    text.range(of: pattern, options: [.regularExpression, .caseInsensitive]) != nil
                }
            }
        }
    }

    /// Scans model-ready text messages, including context enriched onto user turns.
    public static func categories(in messages: [AIChatMessage]) -> [AISensitiveContentCategory] {
        categories(in: messages.map(\.content))
    }
}

/// A bounded in-memory cache of image-review categories keyed by a SHA-256 image digest.
/// It intentionally has no API for retaining recognized OCR text.
public struct AIImageTextScanCache: Sendable {
    public static let maximumEntries = 64
    private var categoriesByDigest: [Data: [AISensitiveContentCategory]] = [:]

    public init() {}

    public var count: Int { categoriesByDigest.count }

    public func categories(for digest: Data) -> [AISensitiveContentCategory]? {
        guard digest.count == 32 else { return nil }
        return categoriesByDigest[digest]
    }

    /// Merges scan results and clears old entries before exceeding the fixed memory bound.
    /// Invalid digest keys are ignored. If one batch is oversized, its lexically first
    /// digests are retained deterministically up to the limit.
    public mutating func merge(_ additions: [Data: [AISensitiveContentCategory]]) {
        if categoriesByDigest.count + additions.keys.filter({ $0.count == 32 }).count > Self.maximumEntries {
            categoriesByDigest.removeAll(keepingCapacity: true)
        }
        for digest in additions.keys.filter({ $0.count == 32 }).sorted(by: { $0.lexicographicallyPrecedes($1) }) {
            guard categoriesByDigest.count < Self.maximumEntries else { break }
            categoriesByDigest[digest] = additions[digest]
        }
    }
}
