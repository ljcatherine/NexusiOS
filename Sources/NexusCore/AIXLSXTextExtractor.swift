import Foundation
#if canImport(FoundationXML)
import FoundationXML
#endif
import ZIPFoundation

/// Reads bounded textual cell values from ordinary `.xlsx` workbooks.
/// It never evaluates formulas or extracts archive entries to the filesystem.
public enum AIXLSXTextExtractor {
    public static let maximumSourceBytes = 10 * 1_024 * 1_024
    public static let maximumArchiveEntries = 256
    public static let maximumXMLPartBytes = 4 * 1_024 * 1_024
    public static let maximumTotalXMLBytes = 16 * 1_024 * 1_024
    public static let maximumSheets = 20
    public static let maximumCells = 10_000

    public static func extract(_ data: Data, maximumOutputBytes: Int) throws -> String {
        guard !data.isEmpty, data.count <= maximumSourceBytes,
              (1...AIKnowledgeDocument.maximumDocumentBytes).contains(maximumOutputBytes) else {
            throw AIConnectionError.invalidContextAttachment
        }
        let archive = try Archive(data: data, accessMode: .read)
        let entries = Array(archive)
        guard entries.count <= maximumArchiveEntries else { throw AIConnectionError.invalidContextAttachment }
        var byPath: [String: Entry] = [:]
        for entry in entries {
            guard byPath[entry.path] == nil else { throw AIConnectionError.invalidContextAttachment }
            byPath[entry.path] = entry
        }

        var totalXMLBytes = 0
        let workbook = try parsePart("xl/workbook.xml", from: archive, entries: byPath, totalXMLBytes: &totalXMLBytes)
        let relationships = try parsePart("xl/_rels/workbook.xml.rels", from: archive, entries: byPath, totalXMLBytes: &totalXMLBytes)
        let sharedStrings = try readSharedStrings(archive: archive, entries: byPath, totalXMLBytes: &totalXMLBytes)
        var relationshipTargets: [String: String] = [:]
        for item in relationships.descendants(named: "Relationship") {
            guard item.attributes["Type"]?.hasSuffix("/worksheet") == true else { continue }
            guard let id = item.attributes["Id"],
                  item.attributes["TargetMode"]?.lowercased() != "external",
                  let target = safeWorksheetPath(item.attributes["Target"] ?? ""),
                  relationshipTargets[id] == nil else {
                throw AIConnectionError.invalidContextAttachment
            }
            relationshipTargets[id] = target
        }
        let sheets = workbook.descendants(named: "sheet")
        guard !sheets.isEmpty, sheets.count <= maximumSheets else { throw AIConnectionError.invalidContextAttachment }

        var output = "Spreadsheet data (cell values only; formulas are not evaluated):\n"
        var cellCount = 0
        for sheet in sheets {
            guard let name = sheet.attributes["name"], !name.isEmpty,
                  let relationshipID = sheet.attributes["r:id"],
                  let path = relationshipTargets[relationshipID] else {
                throw AIConnectionError.invalidContextAttachment
            }
            let worksheet = try parsePart(path, from: archive, entries: byPath, totalXMLBytes: &totalXMLBytes)
            try append("\nSheet: \(safeText(name))\n", to: &output, maximumBytes: maximumOutputBytes)
            for row in worksheet.descendants(named: "row") {
                var rendered: [String] = []
                for cell in row.children where cell.name == "c" {
                    cellCount += 1
                    guard cellCount <= maximumCells,
                          let reference = cell.attributes["r"], reference.utf8.count <= 16 else {
                        throw AIConnectionError.invalidContextAttachment
                    }
                    let value: String
                    if cell.children.contains(where: { $0.name == "f" }) {
                        value = "[formula omitted; not evaluated]"
                    } else {
                        let raw = cell.children.first(where: { $0.name == "v" })?.text ??
                            (cell.attributes["t"] == "inlineStr" ? cell.descendants(named: "t").map(\.text).joined() : "")
                        if cell.attributes["t"] == "s" {
                            guard let index = Int(raw), sharedStrings.indices.contains(index) else {
                                throw AIConnectionError.invalidContextAttachment
                            }
                            value = sharedStrings[index]
                        } else if cell.attributes["t"] == "b" {
                            value = raw == "1" ? "true" : (raw == "0" ? "false" : "")
                        } else {
                            value = raw
                        }
                    }
                    guard !value.isEmpty else { continue }
                    rendered.append("\(reference)=\(safeText(value))")
                }
                if !rendered.isEmpty {
                    try append(rendered.joined(separator: " | ") + "\n", to: &output, maximumBytes: maximumOutputBytes)
                }
            }
        }
        guard output.utf8.count > "Spreadsheet data (cell values only; formulas are not evaluated):\n".utf8.count else {
            throw AIConnectionError.invalidContextAttachment
        }
        return output
    }

    private static func parsePart(_ path: String, from archive: Archive, entries: [String: Entry],
                                  totalXMLBytes: inout Int) throws -> XMLNode {
        guard let entry = entries[path], entry.type == .file,
              entry.uncompressedSize > 0, entry.uncompressedSize <= UInt64(maximumXMLPartBytes),
              entry.compressedSize > 0, entry.compressedSize <= UInt64.max / 1_000,
              entry.uncompressedSize <= entry.compressedSize * 1_000,
              totalXMLBytes + Int(entry.uncompressedSize) <= maximumTotalXMLBytes else {
            throw AIConnectionError.invalidContextAttachment
        }
        totalXMLBytes += Int(entry.uncompressedSize)
        var data = Data()
        _ = try archive.extract(entry, consumer: { chunk in
            guard data.count + chunk.count <= maximumXMLPartBytes else { throw AIConnectionError.invalidContextAttachment }
            data.append(chunk)
        })
        guard data.count == Int(entry.uncompressedSize) else { throw AIConnectionError.invalidContextAttachment }
        guard !containsDTDOrEntityDeclaration(data) else { throw AIConnectionError.invalidContextAttachment }
        let parser = XMLParser(data: data)
        guard let root = XMLTreeParser.parse(parser) else { throw AIConnectionError.invalidContextAttachment }
        return root
    }

    private static func readSharedStrings(archive: Archive, entries: [String: Entry],
                                          totalXMLBytes: inout Int) throws -> [String] {
        guard entries["xl/sharedStrings.xml"] != nil else { return [] }
        let root = try parsePart("xl/sharedStrings.xml", from: archive, entries: entries, totalXMLBytes: &totalXMLBytes)
        let strings = root.descendants(named: "si").map { safeText($0.descendants(named: "t").map(\.text).joined()) }
        guard strings.count <= 200_000 else { throw AIConnectionError.invalidContextAttachment }
        return strings
    }

    private static func safeWorksheetPath(_ target: String) -> String? {
        guard !target.isEmpty, !target.contains("\\") else { return nil }
        var components = target.hasPrefix("/") ? [] : ["xl"]
        for component in target.split(separator: "/").map(String.init) {
            if component == "." || component.isEmpty { continue }
            guard component != ".." else { return nil }
            components.append(component)
        }
        let path = components.joined(separator: "/")
        guard path.hasPrefix("xl/worksheets/"), path.hasSuffix(".xml") else { return nil }
        return path
    }

    private static func safeText(_ text: String) -> String {
        text.replacingOccurrences(of: "\r", with: " ")
            .replacingOccurrences(of: "\n", with: " ")
            .replacingOccurrences(of: "\t", with: " ")
    }

    private static func containsDTDOrEntityDeclaration(_ data: Data) -> Bool {
        let xml: String?
        if data.starts(with: [0xFF, 0xFE]) {
            xml = String(data: data.dropFirst(2), encoding: .utf16LittleEndian)
        } else if data.starts(with: [0xFE, 0xFF]) {
            xml = String(data: data.dropFirst(2), encoding: .utf16BigEndian)
        } else {
            xml = String(data: data, encoding: .utf8)
        }
        guard let xml else { return true }
        let normalized = xml.lowercased()
        return normalized.contains("<!doctype") || normalized.contains("<!entity")
    }

    private static func append(_ text: String, to output: inout String, maximumBytes: Int) throws {
        guard output.utf8.count + text.utf8.count <= maximumBytes else { throw AIConnectionError.invalidContextAttachment }
        output += text
    }
}

private struct XMLNode {
    let name: String
    let attributes: [String: String]
    var text: String
    var children: [XMLNode]

    func descendants(named name: String) -> [XMLNode] {
        children.flatMap { child in (child.name == name ? [child] : []) + child.descendants(named: name) }
    }
}

private final class XMLTreeParser: NSObject, XMLParserDelegate {
    private struct Frame {
        let name: String
        let attributes: [String: String]
        var text = ""
        var children: [XMLNode] = []
    }
    private var stack: [Frame] = []
    private var root: XMLNode?
    private var failed = false

    static func parse(_ parser: XMLParser) -> XMLNode? {
        let delegate = XMLTreeParser()
        parser.delegate = delegate
        parser.shouldResolveExternalEntities = false
        parser.shouldProcessNamespaces = false
        return parser.parse() && !delegate.failed ? delegate.root : nil
    }

    func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?,
                qualifiedName qName: String?, attributes attributeDict: [String: String] = [:]) {
        guard stack.count < 64 else { failed = true; parser.abortParsing(); return }
        stack.append(Frame(name: elementName, attributes: attributeDict))
    }

    func parser(_ parser: XMLParser, foundCharacters string: String) {
        guard !stack.isEmpty else { return }
        stack[stack.count - 1].text += string
        if stack[stack.count - 1].text.utf8.count > AIXLSXTextExtractor.maximumXMLPartBytes {
            failed = true
            parser.abortParsing()
        }
    }

    func parser(_ parser: XMLParser, foundInternalEntityDeclarationWithName name: String,
                value: String?) {
        failed = true
        parser.abortParsing()
    }

    func parser(_ parser: XMLParser, foundExternalEntityDeclarationWithName name: String,
                publicID: String?, systemID: String?) {
        failed = true
        parser.abortParsing()
    }

    func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName qName: String?) {
        guard let frame = stack.popLast(), frame.name == elementName else {
            failed = true
            parser.abortParsing()
            return
        }
        let node = XMLNode(name: frame.name, attributes: frame.attributes, text: frame.text, children: frame.children)
        if stack.isEmpty { root = node }
        else {
            stack[stack.count - 1].children.append(node)
        }
    }

    func parser(_ parser: XMLParser, parseErrorOccurred parseError: Error) { failed = true }
    func parser(_ parser: XMLParser, validationErrorOccurred validationError: Error) { failed = true }
}
