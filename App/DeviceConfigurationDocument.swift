import SwiftUI
import UniformTypeIdentifiers

struct DeviceConfigurationDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.json] }

    var data: Data

    init(data: Data = Data()) {
        self.data = data
    }

    init(configuration: ReadConfiguration) throws {
        guard let data = configuration.file.regularFileContents else {
            throw DeviceConfigurationDocumentError.emptyFile
        }
        self.data = data
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: data)
    }
}

private enum DeviceConfigurationDocumentError: LocalizedError {
    case emptyFile

    var errorDescription: String? {
        "The selected configuration file is empty."
    }
}
