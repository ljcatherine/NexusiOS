import XCTest
@testable import NexusCore

final class AIMarkdownTests: XCTestCase {
    private func parse(_ text: String) -> [AIMarkdownBlock] { AIMarkdownParser.blocks(in: text) }

    func testReportedReplyRendersHeadingAndQuotesInsteadOfRawMarkers() {
        let blocks = parse("""
        Here is the text.

        ### James 4:8–5:3

        **4:8**
        > "Draw near to God."

        **4:9**
        > "Mourn and weep."
        """)
        XCTAssertEqual(blocks, [
            .paragraph("Here is the text."),
            .heading(level: 3, text: "James 4:8–5:3"),
            .paragraph("**4:8**"),
            .quote([.paragraph("\"Draw near to God.\"")]),
            .paragraph("**4:9**"),
            .quote([.paragraph("\"Mourn and weep.\"")])
        ])
    }

    func testHeadingLevelsAndClosingHashes() {
        XCTAssertEqual(parse("# One\n###### Six ##"),
                       [.heading(level: 1, text: "One"), .heading(level: 6, text: "Six")])
        XCTAssertEqual(parse("Title\n===\nOther\n---"),
                       [.heading(level: 1, text: "Title"), .heading(level: 2, text: "Other")])
    }

    func testTextThatOnlyResemblesHeadingStaysParagraph() {
        XCTAssertEqual(parse("#hashtag"), [.paragraph("#hashtag")])
        XCTAssertEqual(parse("####### seven"), [.paragraph("####### seven")])
    }

    func testRules() {
        XCTAssertEqual(parse("***"), [.rule])
        XCTAssertEqual(parse("- - -"), [.rule])
        XCTAssertEqual(parse("Above\n\n---\n\nBelow"), [.paragraph("Above"), .rule, .paragraph("Below")])
    }

    func testNestedQuoteAndLazyContinuation() {
        XCTAssertEqual(parse("> outer\n>> inner"),
                       [.quote([.paragraph("outer"), .quote([.paragraph("inner")])])])
        XCTAssertEqual(parse("> first\nsecond"), [.quote([.paragraph("first\nsecond")])])
    }

    func testBulletListsWithNesting() {
        XCTAssertEqual(parse("- a\n- b\n  - c"), [.list(AIMarkdownList(isOrdered: false, items: [
            AIMarkdownListItem(blocks: [.paragraph("a")]),
            AIMarkdownListItem(blocks: [.paragraph("b"), .list(AIMarkdownList(isOrdered: false, items: [
                AIMarkdownListItem(blocks: [.paragraph("c")])
            ]))])
        ]))])
    }

    func testOrderedListKeepsStartAndUnderIndentedNestedList() {
        XCTAssertEqual(parse("3. a\n  - b\n4. c"), [.list(AIMarkdownList(isOrdered: true, start: 3, items: [
            AIMarkdownListItem(blocks: [.paragraph("a"), .list(AIMarkdownList(isOrdered: false, items: [
                AIMarkdownListItem(blocks: [.paragraph("b")])
            ]))]),
            AIMarkdownListItem(blocks: [.paragraph("c")])
        ]))])
    }

    func testBlankLineBetweenItemsStaysOneList() {
        guard case .list(let list)? = parse("1. a\n\n2. b\n\n3. c").first else {
            return XCTFail("Expected a list")
        }
        XCTAssertEqual(list.items.count, 3)
    }

    func testListEndsBeforeFollowingParagraph() {
        let blocks = parse("- a\n\nAfter")
        XCTAssertEqual(blocks.count, 2)
        XCTAssertEqual(blocks.last, .paragraph("After"))
    }

    func testTaskList() {
        XCTAssertEqual(parse("- [ ] open\n- [x] done"), [.list(AIMarkdownList(isOrdered: false, items: [
            AIMarkdownListItem(isChecked: false, blocks: [.paragraph("open")]),
            AIMarkdownListItem(isChecked: true, blocks: [.paragraph("done")])
        ]))])
    }

    func testCodeInsideListAndFenceContentStaysLiteral() {
        let blocks = parse("- item\n\n  ```swift\n  # not a heading\n  ```")
        guard case .list(let list)? = blocks.first else { return XCTFail("Expected a list") }
        XCTAssertEqual(list.items[0].blocks,
                       [.paragraph("item"), .code(language: "swift", source: "# not a heading")])
        XCTAssertEqual(parse("~~~\n> raw\n~~~"), [.code(language: nil, source: "> raw")])
    }

    func testIndentedCode() {
        XCTAssertEqual(parse("    let a = 1\n    let b = 2\n\nText"),
                       [.code(language: nil, source: "let a = 1\nlet b = 2"), .paragraph("Text")])
    }

    func testTableWithAlignmentEscapesAndShortRows() {
        XCTAssertEqual(parse("| A | B | C |\n|:--|:-:|--:|\n| 1 | `x|y` | a\\|b |\n| 2 |"), [
            .table(AIMarkdownTable(headers: ["A", "B", "C"], alignments: [.leading, .center, .trailing], rows: [
                ["1", "`x|y`", "a|b"],
                ["2", "", ""]
            ]))
        ])
    }

    func testPipeWithoutDelimiterRowIsNotATable() {
        XCTAssertEqual(parse("a | b\nnext"), [.paragraph("a | b\nnext")])
    }

    func testParagraphEndsAtBlockWithoutBlankLine() {
        XCTAssertEqual(parse("Intro\n- item").count, 2)
        XCTAssertEqual(parse("Intro\n# Title").count, 2)
        XCTAssertEqual(parse("Intro\n> quote").count, 2)
    }

    func testNumberMidParagraphDoesNotStartList() {
        XCTAssertEqual(parse("In the year\n1984. It was cold."), [.paragraph("In the year\n1984. It was cold.")])
    }

    func testWindowsLineEndings() {
        XCTAssertEqual(parse("# A\r\n\r\nB"), [.heading(level: 1, text: "A"), .paragraph("B")])
    }

    func testEveryStreamedPrefixParsesAndEarlierBlocksStayStable() {
        let reply = "# Title\n\nIntro **bold**\n\n> quote\n\n- a\n  - b\n\n| A |\n|---|\n| 1 |\n\n```swift\nlet a = 1\n```\nEnd"
        for end in reply.indices {
            _ = parse(String(reply[..<end]))
        }
        let partial = parse(String(reply.prefix(30)))
        let complete = parse(reply)
        XCTAssertEqual(partial.first, complete.first)
        XCTAssertEqual(partial.dropFirst().first, complete.dropFirst().first)
    }

    func testExtremeNestingStopsWithoutOverflow() {
        let blocks = parse(String(repeating: ">", count: 5_000) + " deep")
        XCTAssertEqual(blocks.count, 1)
    }

    func testBlankInput() {
        XCTAssertEqual(parse(""), [])
        XCTAssertEqual(parse("  \n\n"), [])
    }
}
