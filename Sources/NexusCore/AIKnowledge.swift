import Foundation

/// Text imported by the owner for private, on-device lexical retrieval.
/// Original source files are never retained by this model.
public struct AIKnowledgeDocument: Codable, Identifiable, Equatable, Sendable {
    public static let maximumDocuments = 50
    public static let maximumDocumentBytes = 256 * 1_024
    public static let maximumLibraryBytes = 4 * 1_024 * 1_024

    public let id: UUID
    public let title: String
    public let content: String
    public let importedAt: Date

    public init(id: UUID = UUID(), title: String, content: String, importedAt: Date = .now) {
        self.id = id
        self.title = title
        self.content = content
        self.importedAt = importedAt
    }

    public var isValid: Bool {
        let name = title.trimmingCharacters(in: .whitespacesAndNewlines)
        return !name.isEmpty && name.utf8.count <= 128 &&
            !name.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) &&
            !content.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty &&
            content.utf8.count <= Self.maximumDocumentBytes
    }

    public static func isValidLibrary(_ documents: [AIKnowledgeDocument]) -> Bool {
        documents.count <= maximumDocuments && documents.allSatisfy(\.isValid) &&
            documents.reduce(0) { $0 + $1.content.utf8.count } <= maximumLibraryBytes
    }
}

/// Bounded BM25-style retrieval over the user's explicitly imported text.
/// It searches lexical terms and titles; it is not embeddings or a claim of semantic matching.
public enum AILocalKnowledgeSearch {
    public static let maximumResults = 3
    public static let maximumResultBytes = 4 * 1_024
    public static let maximumCombinedResultBytes = 12 * 1_024

    private struct Chunk {
        let title: String
        let text: String
        let termFrequencies: [String: Int]
        let termCount: Int
        let position: Int
    }

    public static func retrieve(_ query: String, from documents: [AIKnowledgeDocument],
                                limit: Int = maximumResults) -> [AIContextAttachment] {
        guard AIKnowledgeDocument.isValidLibrary(documents), (1...maximumResults).contains(limit) else { return [] }
        let queryTerms = Set(tokens(String(query.prefix(4_096))).prefix(64))
        guard !queryTerms.isEmpty else { return [] }
        let chunks = documents.flatMap(makeChunks)
        guard !chunks.isEmpty else { return [] }

        var documentFrequency: [String: Int] = [:]
        for chunk in chunks {
            for term in chunk.termFrequencies.keys where queryTerms.contains(term) {
                documentFrequency[term, default: 0] += 1
            }
        }
        let averageLength = max(1, Double(chunks.reduce(0) { $0 + $1.termCount }) / Double(chunks.count))
        let foldedQuery = query.trimmingCharacters(in: .whitespacesAndNewlines)
            .prefix(256).description.folding(options: [.caseInsensitive, .diacriticInsensitive], locale: .current)
        let ranked = chunks.compactMap { chunk -> (Chunk, Double)? in
            var score = 0.0
            let length = Double(chunk.termCount)
            for term in queryTerms {
                let frequency = Double(chunk.termFrequencies[term, default: 0])
                guard frequency > 0 else { continue }
                let df = Double(documentFrequency[term, default: 0])
                let idf = log(1 + (Double(chunks.count) - df + 0.5) / (df + 0.5))
                score += idf * (frequency * 2.2) / (frequency + 1.2 * (0.25 + 0.75 * length / averageLength))
            }
            score += Double(queryTerms.intersection(tokens(chunk.title)).count) * 1.5
            let foldedText = chunk.text.folding(options: [.caseInsensitive, .diacriticInsensitive], locale: .current)
            if foldedQuery.count >= 3, foldedText.contains(foldedQuery) { score += 0.25 }
            return score > 0 ? (chunk, score) : nil
        }.sorted {
            if $0.1 != $1.1 { return $0.1 > $1.1 }
            if $0.0.title != $1.0.title { return $0.0.title.localizedStandardCompare($1.0.title) == .orderedAscending }
            return $0.0.position < $1.0.position
        }

        var results: [AIContextAttachment] = []
        var combinedBytes = 0
        for (chunk, _) in ranked {
            guard results.count < limit else { break }
            let text = prefix(chunk.text, byteLimit: maximumResultBytes)
            guard !text.isEmpty, combinedBytes + text.utf8.count <= maximumCombinedResultBytes else { continue }
            results.append(AIContextAttachment(title: "Knowledge · \(chunk.title)", content: text, observedAt: .now))
            combinedBytes += text.utf8.count
        }
        return results
    }

    private static func makeChunks(_ document: AIKnowledgeDocument) -> [Chunk] {
        let words = document.content.split(whereSeparator: \.isWhitespace)
        var output: [Chunk] = []
        let maximumChunkBytes = 1_800
        let overlapWords = 24
        var start = 0
        while start < words.count {
            if words[start].utf8.count > maximumChunkBytes {
                start += 1
                continue
            }
            var end = start
            var bytes = 0
            while end < words.count {
                let wordBytes = words[end].utf8.count
                guard wordBytes <= maximumChunkBytes else { break }
                let addition = (end == start ? 0 : 1) + wordBytes
                guard bytes + addition <= maximumChunkBytes else { break }
                bytes += addition
                end += 1
            }
            if end > start {
                appendChunk(Array(words[start..<end]), document: document, position: output.count, to: &output)
            }
            guard end < words.count else { break }
            let consumedWords = end - start
            let overlap = min(overlapWords, consumedWords / 2)
            start = max(start + 1, end - overlap)
        }
        return output
    }

    private static func appendChunk(_ words: [Substring], document: AIKnowledgeDocument,
                                    position: Int, to output: inout [Chunk]) {
        let text = words.joined(separator: " ")
        let terms = tokens(text)
        let frequencies = Dictionary(grouping: terms, by: { $0 }).mapValues(\.count)
        output.append(Chunk(title: document.title, text: text, termFrequencies: frequencies,
            termCount: terms.count, position: position))
    }

    private static func tokens(_ value: String) -> [String] {
        let stopWords: Set<String> = ["a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "how", "in", "is", "it", "of", "on", "or", "that", "the", "this", "to", "was", "what", "when", "where", "which", "with"]
        return value.lowercased().split(whereSeparator: { !$0.isLetter && !$0.isNumber })
            .map(String.init).filter { $0.count > 1 && !stopWords.contains($0) }
    }

    private static func prefix(_ value: String, byteLimit: Int) -> String {
        var result = ""
        for character in value {
            guard result.utf8.count + String(character).utf8.count <= byteLimit else { break }
            result.append(character)
        }
        return result
    }
}
