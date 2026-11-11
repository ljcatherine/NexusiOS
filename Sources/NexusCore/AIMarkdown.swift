import Foundation

/// One block of a Markdown document. Inline styling stays as Markdown text so
/// the view layer can render it.
public indirect enum AIMarkdownBlock: Equatable, Sendable {
    case heading(level: Int, text: String)
    case paragraph(String)
    case quote([AIMarkdownBlock])
    case list(AIMarkdownList)
    case code(language: String?, source: String)
    case table(AIMarkdownTable)
    case rule
}

public struct AIMarkdownList: Equatable, Sendable {
    public var isOrdered: Bool
    public var start: Int
    public var items: [AIMarkdownListItem]

    public init(isOrdered: Bool, start: Int = 1, items: [AIMarkdownListItem]) {
        self.isOrdered = isOrdered
        self.start = start
        self.items = items
    }
}

public struct AIMarkdownListItem: Equatable, Sendable {
    /// nil for an ordinary item; true or false for a task-list checkbox.
    public var isChecked: Bool?
    public var blocks: [AIMarkdownBlock]

    public init(isChecked: Bool? = nil, blocks: [AIMarkdownBlock]) {
        self.isChecked = isChecked
        self.blocks = blocks
    }
}

public struct AIMarkdownTable: Equatable, Sendable {
    public enum Alignment: Equatable, Sendable { case leading, center, trailing }

    public var headers: [String]
    public var alignments: [Alignment]
    public var rows: [[String]]

    public init(headers: [String], alignments: [Alignment], rows: [[String]]) {
        self.headers = headers
        self.alignments = alignments
        self.rows = rows
    }
}

/// Parses block-level CommonMark and GitHub tables for streamed AI replies.
/// Unfinished input is always valid, because replies are parsed as they arrive.
public enum AIMarkdownParser {
    /// Stops hostile or malformed nesting from recursing without limit.
    private static let maximumDepth = 12

    public static func blocks(in markdown: String) -> [AIMarkdownBlock] {
        let lines = markdown.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline).map(String.init)
        return parse(lines, depth: 0)
    }

    private static func parse(_ lines: [String], depth: Int) -> [AIMarkdownBlock] {
        guard depth < maximumDepth else {
            let text = lines.joined(separator: "\n").trimmingCharacters(in: .whitespacesAndNewlines)
            return text.isEmpty ? [] : [.paragraph(text)]
        }
        var result: [AIMarkdownBlock] = []
        var index = 0
        while index < lines.count {
            let line = lines[index]
            if isBlank(line) {
                index += 1
            } else if indentation(of: line) >= 4 {
                result.append(parseIndentedCode(lines, &index))
            } else if let fence = AIMarkdownCodeParser.openingFenceInfo(in: line) {
                result.append(parseFence(fence, lines, &index))
            } else if let heading = heading(in: line) {
                result.append(.heading(level: heading.level, text: heading.text))
                index += 1
            } else if isRule(line) {
                result.append(.rule)
                index += 1
            } else if quoteContent(of: line) != nil {
                result.append(parseQuote(lines, &index, depth: depth))
            } else if listMarker(in: line) != nil {
                result.append(parseList(lines, &index, depth: depth))
            } else if isTableStart(lines, at: index) {
                result.append(parseTable(lines, &index))
            } else {
                result.append(parseParagraph(lines, &index))
            }
        }
        return result
    }

    // MARK: Leaf blocks

    private static func parseIndentedCode(_ lines: [String], _ index: inout Int) -> AIMarkdownBlock {
        var code: [String] = []
        while index < lines.count, isBlank(lines[index]) || indentation(of: lines[index]) >= 4 {
            code.append(removingIndentation(lines[index], upTo: 4))
            index += 1
        }
        while code.last.map(isBlank) == true { code.removeLast() }
        return .code(language: nil, source: code.joined(separator: "\n"))
    }

    private static func parseFence(_ fence: (character: Character, length: Int, language: String?),
                                   _ lines: [String], _ index: inout Int) -> AIMarkdownBlock {
        let opening = indentation(of: lines[index])
        index += 1
        var code: [String] = []
        while index < lines.count {
            let line = lines[index]
            index += 1
            let spaces = indentation(of: line)
            let trimmed = line.dropFirst(min(3, spaces))
            let run = trimmed.prefix(while: { $0 == fence.character }).count
            if spaces <= 3, run >= fence.length,
               trimmed.dropFirst(run).trimmingCharacters(in: .whitespaces).isEmpty { break }
            code.append(removingIndentation(line, upTo: opening))
        }
        return .code(language: fence.language, source: code.joined(separator: "\n"))
    }

    private static func parseParagraph(_ lines: [String], _ index: inout Int) -> AIMarkdownBlock {
        var text: [String] = []
        while index < lines.count {
            let line = lines[index]
            if !text.isEmpty {
                if let level = setextLevel(line) {
                    index += 1
                    return .heading(level: level, text: text.joined(separator: "\n"))
                }
                if isBlank(line) || interruptsParagraph(line) || isTableStart(lines, at: index) { break }
            }
            text.append(line.trimmingCharacters(in: .whitespaces))
            index += 1
        }
        return .paragraph(text.joined(separator: "\n"))
    }

    // MARK: Container blocks

    private static func parseQuote(_ lines: [String], _ index: inout Int, depth: Int) -> AIMarkdownBlock {
        var content: [String] = []
        while index < lines.count {
            let line = lines[index]
            if let quoted = quoteContent(of: line) {
                content.append(quoted)
            } else if !isBlank(line), !interruptsParagraph(line), content.last.map(isBlank) == false {
                content.append(line) // A lazy continuation of the quoted paragraph.
            } else {
                break
            }
            index += 1
        }
        return .quote(parse(content, depth: depth + 1))
    }

    private static func parseList(_ lines: [String], _ index: inout Int, depth: Int) -> AIMarkdownBlock {
        guard let first = listMarker(in: lines[index]) else { return .paragraph(lines[index]) }
        var items: [AIMarkdownListItem] = []

        func isSibling(_ marker: ListMarker) -> Bool {
            marker.isOrdered == first.isOrdered && marker.symbol == first.symbol &&
                marker.indentation < first.contentOffset
        }

        while index < lines.count {
            guard let marker = listMarker(in: lines[index]), isSibling(marker), !isRule(lines[index]) else { break }
            var content = [String(lines[index].dropFirst(min(marker.contentOffset, lines[index].count)))]
            index += 1
            while index < lines.count {
                let line = lines[index]
                if isBlank(line) {
                    guard let next = nextContentIndex(lines, after: index),
                          belongsToItem(lines[next], marker: marker) else { break }
                    content.append("")
                    index += 1
                    continue
                }
                guard let continuation = itemContent(of: line, marker: marker) else { break }
                content.append(continuation)
                index += 1
            }
            items.append(listItem(from: content, depth: depth))
            guard let next = nextContentIndex(lines, after: index - 1),
                  let following = listMarker(in: lines[next]), isSibling(following),
                  !isRule(lines[next]) else { break }
            index = next
        }
        return .list(AIMarkdownList(isOrdered: first.isOrdered, start: first.number, items: items))
    }

    private static func belongsToItem(_ line: String, marker: ListMarker) -> Bool {
        let spaces = indentation(of: line)
        return spaces >= marker.contentOffset || (spaces > marker.indentation && listMarker(in: line) != nil)
    }

    /// Returns a line's content when it continues the current list item.
    private static func itemContent(of line: String, marker: ListMarker) -> String? {
        let spaces = indentation(of: line)
        if spaces >= marker.contentOffset { return removingIndentation(line, upTo: marker.contentOffset) }
        // Models often under-indent nested lists, such as two spaces under "1. ".
        if spaces > marker.indentation, listMarker(in: line) != nil { return removingIndentation(line, upTo: spaces) }
        if listMarker(in: line) != nil || interruptsParagraph(line) { return nil }
        return line.trimmingCharacters(in: .whitespaces) // A lazy continuation.
    }

    private static func listItem(from content: [String], depth: Int) -> AIMarkdownListItem {
        var lines = content
        var isChecked: Bool?
        if let first = lines.first {
            let lowered = first.prefix(4).lowercased()
            if lowered == "[ ] " || first == "[ ]" {
                isChecked = false
            } else if lowered == "[x] " || lowered == "[x]" {
                isChecked = true
            }
            if isChecked != nil { lines[0] = String(first.dropFirst(min(4, first.count))) }
        }
        return AIMarkdownListItem(isChecked: isChecked, blocks: parse(lines, depth: depth + 1))
    }

    private static func parseTable(_ lines: [String], _ index: inout Int) -> AIMarkdownBlock {
        let headers = cells(in: lines[index])
        let alignments = cells(in: lines[index + 1]).map { cell -> AIMarkdownTable.Alignment in
            switch (cell.hasPrefix(":"), cell.hasSuffix(":")) {
            case (true, true): .center
            case (false, true): .trailing
            default: .leading
            }
        }
        index += 2
        var rows: [[String]] = []
        while index < lines.count, !isBlank(lines[index]), lines[index].contains("|") {
            var row = cells(in: lines[index])
            row = Array(row.prefix(headers.count))
            row.append(contentsOf: repeatElement("", count: headers.count - row.count))
            rows.append(row)
            index += 1
        }
        return .table(AIMarkdownTable(headers: headers, alignments: alignments, rows: rows))
    }

    // MARK: Line classification

    private struct ListMarker {
        var indentation: Int
        var isOrdered: Bool
        var number: Int
        /// The bullet character, or the "." or ")" after a number.
        var symbol: Character
        var contentOffset: Int
    }

    private static func listMarker(in line: String) -> ListMarker? {
        let spaces = indentation(of: line)
        let rest = line.drop(while: { $0 == " " || $0 == "\t" })
        guard let first = rest.first else { return nil }
        let width: Int
        var isOrdered = false
        var number = 1
        var symbol = first
        if first == "-" || first == "*" || first == "+" {
            width = 1
        } else {
            let digits = rest.prefix(while: { $0.isASCII && $0.isNumber })
            guard (1...9).contains(digits.count), let value = Int(digits),
                  let delimiter = rest.dropFirst(digits.count).first,
                  delimiter == "." || delimiter == ")" else { return nil }
            width = digits.count + 1
            isOrdered = true
            number = value
            symbol = delimiter
        }
        let after = rest.dropFirst(width)
        guard after.isEmpty || after.first == " " || after.first == "\t" else { return nil }
        let gap = after.prefix(while: { $0 == " " }).count
        let padding = (1...4).contains(gap) ? gap : 1
        return ListMarker(indentation: spaces, isOrdered: isOrdered, number: number, symbol: symbol,
                          contentOffset: spaces + width + padding)
    }

    private static func heading(in line: String) -> (level: Int, text: String)? {
        guard indentation(of: line) <= 3 else { return nil }
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        let level = trimmed.prefix(while: { $0 == "#" }).count
        guard (1...6).contains(level) else { return nil }
        let rest = trimmed.dropFirst(level)
        guard rest.isEmpty || rest.first == " " || rest.first == "\t" else { return nil }
        var text = rest.trimmingCharacters(in: .whitespaces)
        // A closing "##" run is decoration when a space separates it from the title.
        let withoutClosing = text.reversed().drop(while: { $0 == "#" })
        if withoutClosing.first == " " || withoutClosing.isEmpty {
            text = String(withoutClosing.reversed()).trimmingCharacters(in: .whitespaces)
        }
        return (level, text)
    }

    private static func isRule(_ line: String) -> Bool {
        guard indentation(of: line) <= 3 else { return false }
        let characters = line.filter { $0 != " " && $0 != "\t" }
        guard characters.count >= 3, let first = characters.first, "-*_".contains(first) else { return false }
        return characters.allSatisfy { $0 == first }
    }

    private static func setextLevel(_ line: String) -> Int? {
        guard indentation(of: line) <= 3 else { return nil }
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        if !trimmed.isEmpty, trimmed.allSatisfy({ $0 == "=" }) { return 1 }
        if trimmed.count >= 2, trimmed.allSatisfy({ $0 == "-" }) { return 2 }
        return nil
    }

    private static func quoteContent(of line: String) -> String? {
        guard indentation(of: line) <= 3 else { return nil }
        let trimmed = line.drop(while: { $0 == " " })
        guard trimmed.first == ">" else { return nil }
        let rest = trimmed.dropFirst()
        return String(rest.first == " " ? rest.dropFirst() : rest)
    }

    /// Whether a line ends a paragraph without needing a blank line first.
    private static func interruptsParagraph(_ line: String) -> Bool {
        guard indentation(of: line) <= 3 else { return false }
        if AIMarkdownCodeParser.openingFenceInfo(in: line) != nil || heading(in: line) != nil ||
            isRule(line) || quoteContent(of: line) != nil { return true }
        guard let marker = listMarker(in: line) else { return false }
        let hasContent = line.count > marker.contentOffset
        return hasContent && (!marker.isOrdered || marker.number == 1)
    }

    private static func isTableStart(_ lines: [String], at index: Int) -> Bool {
        guard index + 1 < lines.count, lines[index].contains("|") else { return false }
        let delimiter = cells(in: lines[index + 1])
        guard !delimiter.isEmpty, delimiter.count == cells(in: lines[index]).count else { return false }
        return delimiter.allSatisfy { cell in
            let dashes = cell.drop(while: { $0 == ":" }).reversed().drop(while: { $0 == ":" })
            return !dashes.isEmpty && dashes.allSatisfy { $0 == "-" }
        }
    }

    /// Splits a table row, keeping escaped pipes and pipes inside code spans.
    private static func cells(in line: String) -> [String] {
        var text = Substring(line.trimmingCharacters(in: .whitespaces))
        if text.first == "|" { text = text.dropFirst() }
        if text.last == "|", !text.hasSuffix("\\|") { text = text.dropLast() }
        var result: [String] = []
        var current = ""
        var isEscaped = false
        var isInCode = false
        for character in text {
            if isEscaped {
                if character != "|" { current.append("\\") }
                current.append(character)
                isEscaped = false
            } else if character == "\\" {
                isEscaped = true
            } else if character == "|", !isInCode {
                result.append(current.trimmingCharacters(in: .whitespaces))
                current = ""
            } else {
                if character == "`" { isInCode.toggle() }
                current.append(character)
            }
        }
        if isEscaped { current.append("\\") }
        result.append(current.trimmingCharacters(in: .whitespaces))
        return result
    }

    // MARK: Whitespace

    private static func isBlank(_ line: String) -> Bool {
        line.allSatisfy(\.isWhitespace)
    }

    private static func indentation(of line: String) -> Int {
        var width = 0
        for character in line {
            if character == " " { width += 1 } else if character == "\t" { width += 4 } else { break }
        }
        return width
    }

    private static func removingIndentation(_ line: String, upTo limit: Int) -> String {
        var remaining = limit
        var result = Substring(line)
        while remaining > 0, let first = result.first, first == " " || first == "\t" {
            remaining -= first == "\t" ? 4 : 1
            result = result.dropFirst()
        }
        return String(result)
    }

    private static func nextContentIndex(_ lines: [String], after index: Int) -> Int? {
        var next = index + 1
        while next < lines.count, isBlank(lines[next]) { next += 1 }
        return next < lines.count ? next : nil
    }
}
