import SwiftUI
import Observation
import UniformTypeIdentifiers
import NexusCore
import NexusSSH

struct FilesView: View {
    @Bindable var store: AppStore
    @State private var browserSide: FilesBrowserSide = .remote
    @State private var selectedDeviceID: UUID?
    @State private var path = "."
    @State private var entries: [RemoteFileEntry] = []
    @State private var searchQuery = ""
    @State private var showsHiddenFiles = false
    @State private var sortOrder: FilesSortOrder = .name
    @State private var localPath: URL?
    @State private var localEntries: [URL] = []
    @State private var sourceEndpoint: Endpoint?
    @State private var isLoading = false
    @State private var error: String?
    @State private var transferNotice: String?
    @State private var pendingTrust: PendingHostMetricsTrust?
    @State private var importingFile = false
    @State private var pickedFiles: [URL] = []
    @State private var uploadCandidates: [URL] = []
    @State private var overwriteEntries: [String: RemoteFileEntry] = [:]
    @State private var overwriteRemote = false
    @State private var uploadDirectoryCandidate: URL?
    @State private var downloadDirectoryCandidate: RemoteFileEntry?
    @State private var isConfirmingDirectoryUpload = false
    @State private var isConfirmingDirectoryDownload = false
    @State private var isSelectingRemoteFiles = false
    @State private var selectedRemoteFilePaths: Set<String> = []
    @State private var uploadBlockedCount = 0
    @State private var transferProgress = SFTPTransferProgress()
    @State private var transferTask: Task<Void, Never>?
    @State private var isTransferring = false
    @State private var transferDescription = ""
    @State private var downloadArtifact: DownloadArtifact?
    @State private var textDraft: RemoteTextDraft?
    @State private var textDraftDeviceID: UUID?
    @State private var textDraftUsername: String?
    @State private var textDraftAuthentication: AuthenticationKind?
    @State private var textDraftEndpointAuthority: String?
    @State private var isTextEditorPresented = false
    @State private var operationGeneration = UUID()
    @State private var newFolderName = ""
    @State private var isCreatingFolder = false
    @State private var renameEntry: RemoteFileEntry?
    @State private var renameName = ""
    @State private var isRenaming = false
    @State private var permissionsEntry: RemoteFileEntry?
    @State private var deleteEntry: RemoteFileEntry?
    @State private var localRenameURL: URL?
    @State private var localDeleteURL: URL?

    private var selectedDevice: Device? {
        store.devices.first { $0.id == selectedDeviceID }
    }
    private var transport: SFTPTransport { store.fileTransport }
    private var localRoot: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appending(path: "Nexus Files", directoryHint: .isDirectory)
    }
    private var currentLocalDirectory: URL { localPath ?? localRoot }
    private var visibleEntries: [RemoteFileEntry] {
        let matching = entries.filter { (showsHiddenFiles || !$0.name.hasPrefix(".")) &&
            (searchQuery.isEmpty || $0.name.localizedCaseInsensitiveContains(searchQuery)) }
        return matching.sorted { lhs, rhs in
            if lhs.isDirectory != rhs.isDirectory { return lhs.isDirectory }
            switch sortOrder {
            case .name: return lhs.name.localizedStandardCompare(rhs.name) == .orderedAscending
            case .size: return (lhs.size ?? 0) == (rhs.size ?? 0)
                ? lhs.name.localizedStandardCompare(rhs.name) == .orderedAscending
                : (lhs.size ?? 0) > (rhs.size ?? 0)
            case .modified: return (lhs.modifiedAt ?? .distantPast) == (rhs.modifiedAt ?? .distantPast)
                ? lhs.name.localizedStandardCompare(rhs.name) == .orderedAscending
                : (lhs.modifiedAt ?? .distantPast) > (rhs.modifiedAt ?? .distantPast)
            }
        }
    }
    private var selectedRemoteFiles: [RemoteFileEntry] {
        entries.filter { selectedRemoteFilePaths.contains($0.path) && !$0.isDirectory }
    }
    private var visibleLocalEntries: [URL] {
        localEntries.filter { (showsHiddenFiles || !$0.lastPathComponent.hasPrefix(".")) &&
            (searchQuery.isEmpty || $0.lastPathComponent.localizedCaseInsensitiveContains(searchQuery)) }
            .sorted { lhs, rhs in
                let lhsDirectory = isLocalDirectory(lhs)
                let rhsDirectory = isLocalDirectory(rhs)
                if lhsDirectory != rhsDirectory { return lhsDirectory }
                switch sortOrder {
                case .name:
                    return lhs.lastPathComponent.localizedStandardCompare(rhs.lastPathComponent) == .orderedAscending
                case .size:
                    let lhsSize = (try? lhs.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
                    let rhsSize = (try? rhs.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
                    return lhsSize == rhsSize
                        ? lhs.lastPathComponent.localizedStandardCompare(rhs.lastPathComponent) == .orderedAscending
                        : lhsSize > rhsSize
                case .modified:
                    let lhsDate = (try? lhs.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
                    let rhsDate = (try? rhs.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
                    return lhsDate == rhsDate
                        ? lhs.lastPathComponent.localizedStandardCompare(rhs.lastPathComponent) == .orderedAscending
                        : lhsDate > rhsDate
                }
            }
    }
    private var localRelativePath: String {
        let relative = currentLocalDirectory.path.replacingOccurrences(of: localRoot.path, with: "")
        return relative.isEmpty ? "Nexus Files" : "Nexus Files\(relative)"
    }
    private var breadcrumbs: [(label: String, path: String)] {
        guard path != "." else { return [("Home", ".")] }
        let absolute = path.hasPrefix("/")
        let components = path.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        var result: [(label: String, path: String)] = absolute ? [("/", "/")] : [(".", ".")]
        var current = absolute ? "/" : "."
        for component in components {
            if absolute {
                current = current == "/" ? "/\(component)" : "\(current)/\(component)"
            } else {
                current = current == "." ? component : "\(current)/\(component)"
            }
            result.append((component, current))
        }
        return result
    }

    var body: some View {
        Group {
            if store.devices.isEmpty && browserSide == .remote {
                ContentUnavailableView {
                    Label("No devices yet", systemImage: "folder.badge.questionmark")
                } description: {
                    Text("Add an SSH device to browse remote files, or open the local browser.")
                } actions: {
                    Button("Browse On My iPhone") { browserSide = .local }
                        .buttonStyle(.borderedProminent)
                }
            } else {
                NexusList {
                    Section {
                        Picker("Browser location", selection: $browserSide) {
                            ForEach(FilesBrowserSide.allCases) { side in
                                Text(side.title).tag(side)
                            }
                        }
                        .pickerStyle(.segmented)
                        .accessibilityIdentifier("files.browser-side")
                        .disabled(isLoading || isTransferring)

                        if browserSide == .remote {
                            HStack(spacing: 8) {
                                Image(systemName: "folder").foregroundStyle(.tint)
                                ScrollView(.horizontal, showsIndicators: false) {
                                    HStack(spacing: 6) {
                                        ForEach(Array(breadcrumbs.enumerated()), id: \.offset) { item in
                                            let index = item.offset
                                            let crumb = item.element
                                            if index > 0 {
                                                Image(systemName: "chevron.right")
                                                    .font(.caption2).foregroundStyle(.tertiary)
                                                    .accessibilityHidden(true)
                                            }
                                            Button(crumb.label) { load(path: crumb.path) }
                                                .font(.footnote.monospaced())
                                                .buttonStyle(.plain)
                                                .foregroundStyle(crumb.path == path ? Color.primary : Color.accentColor)
                                                .disabled(isLoading || crumb.path == path)
                                                .accessibilityLabel(crumb.path == path
                                                    ? "Current folder \(crumb.label)"
                                                    : "Open folder \(crumb.label)")
                                        }
                                    }
                                }
                                Spacer(minLength: 0)
                                if isLoading { ProgressView().controlSize(.small) }
                                Button("Refresh", systemImage: "arrow.clockwise") { load(path: path) }
                                    .labelStyle(.iconOnly)
                                    .frame(minWidth: 44, minHeight: 44)
                                    .disabled(isLoading || isTransferring)
                                    .accessibilityLabel("Refresh remote files")
                            }
                        } else {
                            HStack(spacing: 8) {
                                Image(systemName: "iphone.gen3").foregroundStyle(.tint)
                                Text(localRelativePath).font(.footnote.monospaced()).lineLimit(1)
                                Spacer()
                                Button("Parent Folder", systemImage: "chevron.up") {
                                    let parent = currentLocalDirectory.deletingLastPathComponent().standardizedFileURL
                                    guard isInsideLocalRoot(parent) else { return }
                                    localPath = parent
                                    refreshLocalFiles()
                                }
                                .labelStyle(.iconOnly)
                                .frame(minWidth: 44, minHeight: 44)
                                .disabled(currentLocalDirectory.standardizedFileURL == localRoot.standardizedFileURL)
                                .accessibilityLabel("Open parent local folder")
                                Button("Local root", systemImage: "house") {
                                    localPath = localRoot
                                    refreshLocalFiles()
                                }
                                .labelStyle(.iconOnly)
                                .frame(minWidth: 44, minHeight: 44)
                                .accessibilityLabel("Open local Nexus Files folder")
                            }
                        }
                        if browserSide == .remote, let sourceEndpoint {
                            Text("SSH · \(sourceEndpoint.authority)")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        HStack {
                            Label(browserSide == .remote ? "Remote server" : "Local device",
                                  systemImage: browserSide == .remote ? "externaldrive.connected.to.line.below" : "iphone")
                            Spacer()
                            Text(browserSide == .remote ? "\(visibleEntries.count) items" : "\(visibleLocalEntries.count) items")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        .font(.caption.weight(.medium))
                        if isTransferring {
                            HStack(spacing: 10) {
                                if let progress = transferProgress.fraction {
                                    ProgressView(value: progress)
                                    Text("\(transferProgress.itemLabel ?? transferDescription) · \(Int(progress * 100))%")
                                        .font(.caption).foregroundStyle(.secondary)
                                } else {
                                    ProgressView()
                                    Text(transferDescription.isEmpty ? "Preparing transfer…" : transferDescription)
                                        .font(.caption).foregroundStyle(.secondary)
                                }
                                Button("Cancel", role: .cancel) { transferTask?.cancel() }
                                    .controlSize(.small)
                                    .accessibilityLabel("Cancel file transfer")
                            }
                        }
                        if !uploadCandidates.isEmpty && !isTransferring {
                            VStack(alignment: .leading, spacing: 8) {
                                Label("\(uploadCandidates.count) file(s) ready to upload",
                                      systemImage: "tray.and.arrow.up.fill")
                                    .font(.subheadline.weight(.medium))
                                HStack {
                                    Button("Start Upload") {
                                        if overwriteEntries.isEmpty {
                                            beginUploadBatch(overwriteEntries: [:])
                                        } else {
                                            overwriteRemote = true
                                        }
                                    }
                                    .buttonStyle(.borderedProminent)
                                    Button("Discard", role: .cancel) {
                                        uploadCandidates = []
                                        overwriteEntries = [:]
                                        uploadBlockedCount = 0
                                    }
                                    .buttonStyle(.bordered)
                                }
                            }
                            .accessibilityElement(children: .contain)
                        }
                        if let uploadDirectoryCandidate, !isTransferring {
                            VStack(alignment: .leading, spacing: 8) {
                                Label("Folder ready: \(uploadDirectoryCandidate.lastPathComponent)",
                                      systemImage: "folder.badge.arrow.up")
                                    .font(.subheadline.weight(.medium))
                                HStack {
                                    Button("Upload Folder") { isConfirmingDirectoryUpload = true }
                                        .buttonStyle(.borderedProminent)
                                    Button("Discard", role: .cancel) {
                                        self.uploadDirectoryCandidate = nil
                                    }
                                    .buttonStyle(.bordered)
                                }
                            }
                        }
                        if let downloadDirectoryCandidate, !isTransferring {
                            VStack(alignment: .leading, spacing: 8) {
                                Label("Folder ready: \(downloadDirectoryCandidate.name)",
                                      systemImage: "folder.badge.arrow.down")
                                    .font(.subheadline.weight(.medium))
                                HStack {
                                    Button("Download Folder") { isConfirmingDirectoryDownload = true }
                                        .buttonStyle(.borderedProminent)
                                    Button("Discard", role: .cancel) {
                                        self.downloadDirectoryCandidate = nil
                                    }
                                    .buttonStyle(.bordered)
                                }
                            }
                        }
                    }

                    Section(browserSide == .remote ? "Remote files" : "Local files") {
                        if browserSide == .remote && selectedDevice == nil {
                            ContentUnavailableView("Choose a device", systemImage: "externaldrive",
                                description: Text("Select an SSH device above to browse its remote files."))
                        } else if browserSide == .remote && isLoading && entries.isEmpty {
                            HStack { ProgressView(); Text("Loading directory…").foregroundStyle(.secondary) }
                        } else if browserSide == .remote, let error, entries.isEmpty {
                            ContentUnavailableView {
                                Label("Could not open directory", systemImage: "network.slash")
                            } description: {
                                Text(error)
                            } actions: {
                                Button("Retry") { load(path: path) }
                                    .buttonStyle(.borderedProminent)
                                    .disabled(isLoading || isTransferring)
                            }
                        } else if browserSide == .remote && visibleEntries.isEmpty {
                            ContentUnavailableView(searchQuery.isEmpty ? "This folder is empty" : "No matching files",
                                systemImage: "folder",
                                description: Text("Upload files, create a folder, or change the search."))
                        } else if browserSide == .local && visibleLocalEntries.isEmpty {
                            ContentUnavailableView(searchQuery.isEmpty ? "Local folder is empty" : "No matching files",
                                systemImage: "folder",
                                description: Text("Add files from Files, or download them from a remote server."))
                        } else if browserSide == .local {
                            ForEach(visibleLocalEntries, id: \.standardizedFileURL) { url in
                                localFileRow(url)
                            }
                        } else {
                            ForEach(visibleEntries) { entry in
                                fileRow(entry)
                            }
                        }
                    }

                    if let textDraft, !isTextEditorPresented {
                        Section("Unfinished edit") {
                            Button("Resume editing \(textDraft.name)", systemImage: "doc.text") {
                                isTextEditorPresented = true
                            }
                        }
                    }

                    if let error, !entries.isEmpty {
                        Section {
                            Label(error, systemImage: "exclamationmark.triangle.fill")
                                .font(.footnote).foregroundStyle(.orange)
                        }
                    }
                    if let transferNotice {
                        Section {
                            Label(transferNotice, systemImage: "checkmark.circle.fill")
                                .font(.footnote).foregroundStyle(.secondary)
                        }
                    }
                }
                .toolbar {
                    ToolbarItem(placement: .principal) {
                        Picker("Device", selection: $selectedDeviceID) {
                            Text("Choose device").tag(Optional<UUID>.none)
                            ForEach(store.devices) { device in
                                Text(device.name).tag(Optional(device.id))
                            }
                        }
                        .pickerStyle(.menu)
                        .disabled(isLoading || isTransferring)
                    }
                    ToolbarItem(placement: .topBarTrailing) {
                        Menu {
                            if browserSide == .remote {
                                if isSelectingRemoteFiles {
                                    Button("Download \(selectedRemoteFiles.count) Selected",
                                           systemImage: "arrow.down.to.line") {
                                        download(selectedRemoteFiles)
                                    }
                                    .disabled(selectedRemoteFiles.isEmpty || isLoading || isTransferring)
                                    Button("Clear Selection", systemImage: "xmark.circle") {
                                        selectedRemoteFilePaths.removeAll()
                                    }
                                    Button("Done Selecting", systemImage: "checkmark") {
                                        isSelectingRemoteFiles = false
                                        selectedRemoteFilePaths.removeAll()
                                    }
                                    Divider()
                                } else {
                                    Button("Select Files to Download", systemImage: "checklist") {
                                        isSelectingRemoteFiles = true
                                        selectedRemoteFilePaths.removeAll()
                                    }
                                }
                                Button("New Folder", systemImage: "folder.badge.plus") {
                                    newFolderName = ""; isCreatingFolder = true
                                }
                                Button(showsHiddenFiles ? "Hide Hidden Files" : "Show Hidden Files",
                                       systemImage: showsHiddenFiles ? "eye.slash" : "eye") {
                                    showsHiddenFiles.toggle()
                                }
                                Menu("Sort By", systemImage: "arrow.up.arrow.down") {
                                    ForEach(FilesSortOrder.allCases) { order in
                                        Button {
                                            sortOrder = order
                                        } label: {
                                            if sortOrder == order { Label(order.title, systemImage: "checkmark") }
                                            else { Text(order.title) }
                                        }
                                    }
                                }
                            } else {
                                Button("New Local Folder", systemImage: "folder.badge.plus") {
                                    newFolderName = ""; isCreatingFolder = true
                                }
                                Button(showsHiddenFiles ? "Hide Hidden Files" : "Show Hidden Files",
                                       systemImage: showsHiddenFiles ? "eye.slash" : "eye") {
                                    showsHiddenFiles.toggle()
                                }
                                Menu("Sort By", systemImage: "arrow.up.arrow.down") {
                                    ForEach(FilesSortOrder.allCases) { order in
                                        Button {
                                            sortOrder = order
                                        } label: {
                                            if sortOrder == order { Label(order.title, systemImage: "checkmark") }
                                            else { Text(order.title) }
                                        }
                                    }
                                }
                            }
                            Divider()
                            Button(browserSide == .remote ? "Upload from Files" : "Add to Local Files",
                                   systemImage: "square.and.arrow.up") { importingFile = true }
                                .disabled(isLoading || isTransferring ||
                                          (browserSide == .remote && selectedDevice == nil))
                        } label: {
                            Image(systemName: "ellipsis.circle")
                                .frame(minWidth: 44, minHeight: 44)
                        }
                        .accessibilityLabel("File browser actions")
                    }
                }
                .searchable(text: $searchQuery, prompt: browserSide == .remote ? "Search remote files" : "Search local files")
                .sheet(isPresented: $importingFile, onDismiss: {
                    let urls = pickedFiles
                    pickedFiles = []
                    guard !urls.isEmpty else { return }
                    if browserSide == .local { importToLocalFiles(urls) }
                    else { prepareUpload(urls) }
                }) {
                    SFTPDocumentPicker(onPick: { urls in
                        pickedFiles = urls
                        importingFile = false
                    }, onCancel: { importingFile = false })
                    .ignoresSafeArea()
                }
                .confirmationDialog(overwriteEntries.count == 1
                    ? "A file with this name already exists"
                    : "Some destination files already exist", isPresented: $overwriteRemote,
                    titleVisibility: .visible) {
                    Button(overwriteEntries.count == 1 ? "Replace remote file" : "Replace existing files",
                           role: .destructive) { beginUploadBatch(overwriteEntries: overwriteEntries) }
                    Button("Skip existing names") {
                        beginUploadBatch(overwriteEntries: [:], skipNames: Set(overwriteEntries.keys))
                    }
                    Button("Cancel", role: .cancel) {
                        uploadCandidates = []; overwriteEntries = [:]; uploadBlockedCount = 0
                    }
                } message: {
                    Text("Replacing \(overwriteEntries.count) matching remote file(s) in \(path). Other matching folders or symbolic links will be skipped.")
                }
                .confirmationDialog("Upload folder recursively?", isPresented: $isConfirmingDirectoryUpload,
                                    titleVisibility: .visible) {
                    Button("Upload as New Remote Folder", role: .destructive) { beginUploadDirectory() }
                    Button("Cancel", role: .cancel) { uploadDirectoryCandidate = nil }
                } message: {
                    Text("Nexus creates a new folder in \(path), skips symbolic links and special files, and never overwrites an existing destination. If cancelled or interrupted, completed remote items may remain in that folder.")
                }
                .confirmationDialog("Download folder recursively?", isPresented: $isConfirmingDirectoryDownload,
                                    titleVisibility: .visible) {
                    Button("Download Folder") { beginDownloadDirectory() }
                    Button("Cancel", role: .cancel) { downloadDirectoryCandidate = nil }
                } message: {
                    Text("The remote folder and its regular files will be copied into the current Nexus Files folder. Symbolic links and special files are skipped. An incomplete local folder is removed if the transfer fails.")
                }
                .confirmationDialog(deleteEntry.map { "Delete \($0.name)?" } ??
                    localDeleteURL.map { "Delete \($0.lastPathComponent)?" } ?? "Delete file?",
                    isPresented: Binding(get: { deleteEntry != nil || localDeleteURL != nil }, set: {
                        if !$0 { deleteEntry = nil; localDeleteURL = nil }
                    }), titleVisibility: .visible) {
                    if let deleteEntry {
                        Button(deleteEntry.isDirectory && !deleteEntry.isSymbolicLink
                            ? "Remove Empty Folder" : "Delete Remote File", role: .destructive) {
                            deleteRemote(deleteEntry)
                        }
                    } else if let localDeleteURL {
                        Button("Delete Local Item", role: .destructive) { deleteLocal(localDeleteURL) }
                    }
                    Button("Cancel", role: .cancel) { deleteEntry = nil; localDeleteURL = nil }
                } message: {
                    if let deleteEntry, deleteEntry.isDirectory && !deleteEntry.isSymbolicLink {
                        Text("Only an empty remote folder can be removed. Nexus will not recursively delete its contents.")
                    } else if deleteEntry != nil {
                        Text("This removes the item from the remote server and cannot be undone.")
                    } else {
                        Text("This deletes the item from this app’s local Nexus Files folder.")
                    }
                }
                .alert("Create Folder", isPresented: $isCreatingFolder) {
                    TextField("Folder name", text: $newFolderName)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                    Button("Create") { createFolder() }
                    Button("Cancel", role: .cancel) {}
                } message: {
                    Text(browserSide == .remote
                         ? "Create one folder in the current remote directory."
                         : "Create one folder in the current local directory.")
                }
                .alert("Rename Item", isPresented: $isRenaming) {
                    TextField("New name", text: $renameName)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                    Button("Rename") { renameItem() }
                    Button("Cancel", role: .cancel) { renameEntry = nil; localRenameURL = nil }
                } message: {
                    Text("Rename only changes this item’s name in its current folder. Existing destinations are not replaced.")
                }
                .sheet(item: $downloadArtifact) { artifact in
                    NavigationStack {
                        VStack(spacing: 16) {
                            Image(systemName: "checkmark.circle.fill").font(.largeTitle).foregroundStyle(.green)
                            Text("Download ready").font(.headline)
                            Text(artifact.url.lastPathComponent).font(.footnote).foregroundStyle(.secondary)
                            ShareLink(item: artifact.url) { Label("Save or share file", systemImage: "square.and.arrow.up") }
                                .buttonStyle(.borderedProminent)
                        }
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                        .padding()
                        .navigationTitle("Download")
                        .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { downloadArtifact = nil } } }
                    }
                }
                .sheet(isPresented: $isTextEditorPresented) {
                    if let textDraft {
                        RemoteTextEditor(draft: textDraft, onSave: saveText)
                    }
                }
                .alert(pendingTrust?.challenge.changed == true ? "Host key changed" :
                    (pendingTrust == nil ? "Files" : "Verify SSH host"), isPresented: Binding(
                        get: { pendingTrust != nil || (error != nil && !isLoading) },
                        set: { if !$0 { if pendingTrust != nil { rejectHostTrust() } else { error = nil } }
                    })) {
                    if let challenge = pendingTrust?.challenge {
                        if challenge.changed {
                            Button("OK", role: .cancel) { rejectHostTrust() }
                        } else {
                            Button("Trust and connect") { approveHost() }
                            Button("Cancel", role: .cancel) { rejectHostTrust() }
                        }
                    } else {
                        Button("OK") { error = nil }
                    }
                } message: {
                    if let pendingTrust {
                        let challenge = pendingTrust.challenge
                        Text("\(pendingTrust.device.name) · \(challenge.endpoint.authority)\n\(challenge.fingerprint)\n\(challenge.changed ? "Connection blocked. Verify the new key through a trusted channel and recover it in the terminal." : "Compare this SHA256 fingerprint through a trusted channel before approving it.")")
                    } else { Text(error ?? "") }
                }
                .onAppear { prepareLocalFiles() }
                .onChange(of: browserSide) { _, side in
                    searchQuery = ""
                    if side == .local {
                        isSelectingRemoteFiles = false
                        selectedRemoteFilePaths.removeAll()
                    }
                    if side == .local { refreshLocalFiles() }
                }
                .onChange(of: selectedDeviceID) { _, newValue in
                    operationGeneration = UUID()
                    let generation = operationGeneration
                    uploadDirectoryCandidate = nil
                    downloadDirectoryCandidate = nil
                    isConfirmingDirectoryUpload = false
                    isConfirmingDirectoryDownload = false
                    path = "."; entries = []; sourceEndpoint = nil; error = nil
                    selectedRemoteFilePaths.removeAll()
                    isSelectingRemoteFiles = false
                    pendingTrust = nil
                    isLoading = true
                    Task {
                        await transport.disconnect()
                        guard operationGeneration == generation else { return }
                        isLoading = false
                        if newValue != nil { load(path: ".") }
                    }
                }
                .onChange(of: store.devices) { oldDevices, devices in
                    guard let selectedID = selectedDeviceID else { return }
                    guard let updatedDevice = devices.first(where: { $0.id == selectedID }) else {
                        operationGeneration = UUID()
                        transferTask?.cancel()
                        isLoading = false
                        isTransferring = false
                        selectedDeviceID = nil
                        return
                    }
                    guard let previousDevice = oldDevices.first(where: { $0.id == selectedID }),
                          previousDevice != updatedDevice else { return }

                    if let sourceEndpoint,
                       let retainedEndpoint = updatedDevice.endpoints.first(where: {
                           $0.authority == sourceEndpoint.authority
                       }),
                       previousDevice.username == updatedDevice.username,
                       previousDevice.authentication == updatedDevice.authentication {
                        self.sourceEndpoint = retainedEndpoint
                        return
                    }

                    operationGeneration = UUID()
                    let generation = operationGeneration
                    transferTask?.cancel()
                    path = "."; entries = []; sourceEndpoint = nil; error = nil
                    pendingTrust = nil
                    isLoading = true
                    isTransferring = false
                    Task {
                        await transport.disconnect()
                        guard operationGeneration == generation else { return }
                        isLoading = false
                        load(path: ".")
                    }
                }
                .onDisappear {
                    operationGeneration = UUID()
                    transferTask?.cancel()
                    isLoading = false
                    isTransferring = false
                    Task { await transport.disconnect() }
                }
            }
        }
        .sheet(item: $permissionsEntry) { entry in
            RemotePermissionsEditor(entry: entry) { mode in
                await applyPermissions(mode, to: entry)
            }
        }
        .navigationTitle("Files")
        .scrollContentBackground(.hidden)
        .nexusScreenBackground()
        .tint(NexusPalette.blue)
    }

    @ViewBuilder
    private func fileRow(_ entry: RemoteFileEntry) -> some View {
        HStack(spacing: 8) {
            Button {
                if isSelectingRemoteFiles && !entry.isDirectory {
                    if selectedRemoteFilePaths.contains(entry.path) {
                        selectedRemoteFilePaths.remove(entry.path)
                    } else {
                        selectedRemoteFilePaths.insert(entry.path)
                    }
                } else if entry.isDirectory { load(path: entry.operationPath) }
                else if let size = entry.size, size <= 1_048_576 { openText(entry) }
                else { download(entry) }
            } label: {
                HStack(spacing: 12) {
                if isSelectingRemoteFiles && !entry.isDirectory {
                    Image(systemName: selectedRemoteFilePaths.contains(entry.path)
                        ? "checkmark.circle.fill" : "circle")
                        .foregroundStyle(selectedRemoteFilePaths.contains(entry.path) ? Color.accentColor : Color.secondary)
                        .frame(width: 24)
                }
                Image(systemName: entry.isDirectory ? "folder.fill" : (entry.isSymbolicLink ? "arrow.turn.up.right" : "doc"))
                    .foregroundStyle(entry.isDirectory ? Color.accentColor : Color.secondary)
                    .frame(width: 24)
                VStack(alignment: .leading, spacing: 3) {
                    Text(entry.name).lineLimit(1)
                    Text(entry.isDirectory
                        ? (entry.isSymbolicLink ? "Folder link" : "Folder")
                        : (entry.isSymbolicLink ? "Symbolic link · \(fileDetails(entry))" : fileDetails(entry)))
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                if entry.isDirectory { Image(systemName: "chevron.right").font(.caption).foregroundStyle(.tertiary) }
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .disabled(isLoading || isTransferring || (isSelectingRemoteFiles && entry.isDirectory))

            Menu {
                if entry.isDirectory && !entry.isSymbolicLink {
                    Button("Download Folder…", systemImage: "folder.badge.arrow.down") {
                        downloadDirectoryCandidate = entry
                        isConfirmingDirectoryDownload = true
                    }
                } else if !entry.isDirectory {
                    Button(isSelectingRemoteFiles ? "Toggle Download Selection" : "Download",
                           systemImage: isSelectingRemoteFiles ? "checkmark.circle" : "arrow.down.to.line") {
                        if isSelectingRemoteFiles {
                            if selectedRemoteFilePaths.contains(entry.path) {
                                selectedRemoteFilePaths.remove(entry.path)
                            } else {
                                selectedRemoteFilePaths.insert(entry.path)
                            }
                        } else {
                            download(entry)
                        }
                    }
                    if let size = entry.size, size <= 1_048_576 {
                        Button("Preview or Edit", systemImage: "doc.text.magnifyingglass") { openText(entry) }
                    }
                }
                Button("Rename", systemImage: "pencil") {
                    renameEntry = entry; renameName = entry.name; isRenaming = true
                }
                if !entry.isSymbolicLink, entry.permissions != nil {
                    Button("Permissions…", systemImage: "lock.doc") {
                        permissionsEntry = entry
                    }
                }
                Button("Delete", systemImage: "trash", role: .destructive) { deleteEntry = entry }
            } label: {
                Image(systemName: "ellipsis")
                    .frame(width: 40, height: 44)
            }
            .disabled(isLoading || isTransferring)
            .accessibilityLabel("Actions for \(entry.name)")
        }
        .padding(.vertical, 2)
    }

    @ViewBuilder
    private func localFileRow(_ url: URL) -> some View {
        let directory = isLocalDirectory(url)
        HStack(spacing: 8) {
            Button {
                if directory {
                    localPath = url
                    refreshLocalFiles()
                }
            } label: {
                HStack(spacing: 12) {
                    Image(systemName: directory ? "folder.fill" : "doc")
                        .foregroundStyle(directory ? Color.accentColor : Color.secondary)
                        .frame(width: 24)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(url.lastPathComponent).lineLimit(1)
                        Text(localFileDetails(url, directory: directory))
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    if directory { Image(systemName: "chevron.right").font(.caption).foregroundStyle(.tertiary) }
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            Menu {
                if selectedDevice != nil {
                    if directory {
                        Button("Upload Folder…", systemImage: "folder.badge.arrow.up") {
                            uploadDirectoryCandidate = url
                            isConfirmingDirectoryUpload = true
                        }
                    } else {
                        Button("Upload to Remote Folder", systemImage: "arrow.up.to.line") { prepareUpload(url) }
                    }
                }
                ShareLink(item: url) { Label("Share or Save to Files", systemImage: "square.and.arrow.up") }
                Button("Rename", systemImage: "pencil") {
                    localRenameURL = url; renameName = url.lastPathComponent; isRenaming = true
                }
                Button("Delete", systemImage: "trash", role: .destructive) { localDeleteURL = url }
            } label: {
                Image(systemName: "ellipsis").frame(width: 40, height: 44)
            }
            .accessibilityLabel("Actions for local item \(url.lastPathComponent)")
        }
        .padding(.vertical, 2)
    }

    @MainActor private func load(path requestedPath: String) {
        guard let device = selectedDevice, !isLoading, !isTransferring else { return }
        if requestedPath != path { selectedRemoteFilePaths.removeAll() }
        let generation = operationGeneration
        isLoading = true; error = nil
        Task {
            defer { if operationGeneration == generation { isLoading = false } }
            do {
                var candidates = device.orderedEndpoints
                if let sourceEndpoint {
                    candidates = [sourceEndpoint] + candidates.filter { $0.id != sourceEndpoint.id }
                }
                guard !candidates.isEmpty else { throw SSHFailure.connectionFailed }
                var lastError: Error?
                for endpoint in candidates {
                    guard operationGeneration == generation else { return }
                    do {
                        try await transport.connect(device: device, endpoint: endpoint,
                            secrets: store.secrets, timeout: store.timeout)
                        guard operationGeneration == generation else { return }
                        let resolved = try await transport.resolvePath(requestedPath)
                        guard operationGeneration == generation else { return }
                        let listing = try await transport.listDirectory(at: resolved)
                        guard operationGeneration == generation else { return }
                        path = resolved; entries = listing; sourceEndpoint = endpoint
                        return
                    } catch let challenge as HostKeyChallenge {
                        guard operationGeneration == generation else { return }
                        entries = []; path = requestedPath
                        pendingTrust = PendingHostMetricsTrust(device: device, challenge: challenge)
                        return
                    } catch {
                        guard operationGeneration == generation else { return }
                        lastError = error
                        if let failure = error as? SSHFailure, case .connectionFailed = failure { continue }
                        throw error
                    }
                }
                throw lastError ?? SSHFailure.connectionFailed
            } catch {
                guard operationGeneration == generation else { return }
                self.error = error.localizedDescription
            }
        }
    }

    @MainActor private func approveHost() {
        guard let pendingTrust, !pendingTrust.challenge.changed else { return }
        do {
            try HostKeyVerifier.approve(pendingTrust.challenge, secrets: store.secrets)
            sourceEndpoint = pendingTrust.challenge.endpoint
            self.pendingTrust = nil
            load(path: path)
        } catch let caughtError { self.error = caughtError.localizedDescription }
    }

    @MainActor private func rejectHostTrust() {
        if pendingTrust != nil { error = "Host key was not approved. No SFTP session was opened." }
        pendingTrust = nil
    }

    @MainActor private func openText(_ entry: RemoteFileEntry) {
        guard !isLoading, !isTransferring, let device = selectedDevice else { return }
        let generation = operationGeneration
        isLoading = true
        error = nil
        Task {
            defer { if operationGeneration == generation { isLoading = false } }
            do {
                try await ensureConnected(device: device)
                let (contents, size, modifiedAt) = try await transport.readTextFile(at: entry.operationPath)
                guard operationGeneration == generation else { return }
                textDraft = RemoteTextDraft(path: entry.operationPath, name: entry.name, contents: contents,
                    originalContents: contents, originalSize: size, originalModifiedAt: modifiedAt)
                textDraftDeviceID = device.id
                textDraftUsername = device.username
                textDraftAuthentication = device.authentication
                textDraftEndpointAuthority = sourceEndpoint?.authority
                isTextEditorPresented = true
            } catch let challenge as HostKeyChallenge {
                guard operationGeneration == generation else { return }
                pendingTrust = PendingHostMetricsTrust(device: device, challenge: challenge)
            } catch {
                guard operationGeneration == generation else { return }
                self.error = error.localizedDescription
            }
        }
    }

    @MainActor private func saveText(_ draft: RemoteTextDraft,
                                    completion: @escaping @MainActor (RemoteTextSaveResult) -> Void) {
        guard !isLoading, let device = selectedDevice,
              device.id == textDraftDeviceID,
              device.username == textDraftUsername,
              device.authentication == textDraftAuthentication,
              let draftAuthority = textDraftEndpointAuthority,
              let endpoint = device.orderedEndpoints.first(where: { $0.authority == draftAuthority }) else {
            completion(.failed("The device or connection used for this draft has changed. Reopen the file from its original device before saving."))
            return
        }
        sourceEndpoint = endpoint
        let generation = operationGeneration
        isLoading = true
        error = nil
        Task {
            defer { if operationGeneration == generation { isLoading = false } }
            do {
                try await ensureConnected(device: device)
                try await transport.saveTextFile(draft.contents, at: draft.path,
                    expectedSize: draft.originalSize, expectedModifiedAt: draft.originalModifiedAt)
                guard operationGeneration == generation else { return }
                textDraft = nil
                textDraftDeviceID = nil
                textDraftUsername = nil
                textDraftAuthentication = nil
                textDraftEndpointAuthority = nil
                isTextEditorPresented = false
                completion(.saved)
                do {
                    let listing = try await transport.listDirectory(at: path)
                    guard operationGeneration == generation else { return }
                    entries = listing
                } catch {
                    guard operationGeneration == generation else { return }
                    self.error = "The file was saved, but the directory could not be refreshed: \(error.localizedDescription)"
                }
            } catch let challenge as HostKeyChallenge {
                guard operationGeneration == generation else { return }
                pendingTrust = PendingHostMetricsTrust(device: device, challenge: challenge)
                textDraft = draft
                isTextEditorPresented = false
                completion(.verificationRequired)
            } catch {
                guard operationGeneration == generation else { return }
                completion(.failed(error.localizedDescription))
            }
        }
    }

    @MainActor private func prepareUpload(_ url: URL) { prepareUpload([url]) }

    @MainActor private func prepareUpload(_ urls: [URL]) {
        guard selectedDevice != nil, !isLoading, !isTransferring else { return }
        guard !urls.isEmpty else { return }
        error = nil
        transferNotice = nil
        var seenNames = Set<String>()
        var duplicateCount = 0
        let uniqueURLs = urls.filter { url in
            if seenNames.insert(url.lastPathComponent).inserted { return true }
            duplicateCount += 1
            return false
        }
        let blockedNames = Set(uniqueURLs.compactMap { url -> String? in
            guard let existing = entries.first(where: { $0.name == url.lastPathComponent }),
                  existing.isSymbolicLink || existing.isDirectory else { return nil }
            return url.lastPathComponent
        })
        uploadBlockedCount = duplicateCount + blockedNames.count
        uploadCandidates = uniqueURLs.filter { !blockedNames.contains($0.lastPathComponent) }
        overwriteEntries = Dictionary(uniqueKeysWithValues: uploadCandidates.compactMap { url in
            guard let existing = entries.first(where: { $0.name == url.lastPathComponent }),
                  !existing.isSymbolicLink, !existing.isDirectory else { return nil }
            return (url.lastPathComponent, existing)
        })
        if uploadBlockedCount > 0 {
            transferNotice = "Skipped \(uploadBlockedCount) item(s) because of duplicate names or a remote folder/symbolic link."
        }
        guard !uploadCandidates.isEmpty else {
            uploadBlockedCount = 0
            return
        }
        if !overwriteEntries.isEmpty {
            overwriteRemote = true
        } else {
            beginUploadBatch(overwriteEntries: [:])
        }
    }

    @MainActor private func createFolder() {
        let name = newFolderName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard isValidBrowserName(name) else {
            error = "Enter one folder name without path separators or control characters."
            return
        }
        if browserSide == .local {
            do {
                let target = currentLocalDirectory.appending(path: name, directoryHint: .isDirectory)
                try FileManager.default.createDirectory(at: target, withIntermediateDirectories: false)
                refreshLocalFiles()
            } catch { self.error = error.localizedDescription }
            return
        }
        guard let device = selectedDevice, !isLoading, !isTransferring else { return }
        let parentPath = path
        let generation = operationGeneration
        isLoading = true; error = nil; transferNotice = nil
        Task {
            defer { if operationGeneration == generation { isLoading = false } }
            do {
                try await ensureConnected(device: device)
                let target = parentPath == "/" ? "/\(name)" : "\(parentPath)/\(name)"
                try await transport.createDirectory(at: target)
                guard operationGeneration == generation else { return }
                entries = try await transport.listDirectory(at: parentPath)
            } catch let challenge as HostKeyChallenge {
                guard operationGeneration == generation else { return }
                pendingTrust = PendingHostMetricsTrust(device: device, challenge: challenge)
            } catch {
                guard operationGeneration == generation else { return }
                self.error = error.localizedDescription
            }
        }
    }

    @MainActor private func renameItem() {
        let name = renameName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard isValidBrowserName(name) else {
            error = "Enter one item name without path separators or control characters."
            return
        }
        if let url = localRenameURL {
            do {
                let destination = url.deletingLastPathComponent().appending(path: name)
                guard isInsideLocalRoot(url), isInsideLocalRoot(destination) else {
                    throw CocoaError(.fileWriteNoPermission)
                }
                guard !FileManager.default.fileExists(atPath: destination.path) else {
                    error = "An item with that name already exists locally."
                    return
                }
                try FileManager.default.moveItem(at: url, to: destination)
                localRenameURL = nil
                refreshLocalFiles()
            } catch { self.error = error.localizedDescription }
            return
        }
        guard let entry = renameEntry, let device = selectedDevice,
              !isLoading, !isTransferring else { return }
        let generation = operationGeneration
        isLoading = true; error = nil; transferNotice = nil
        Task {
            defer { if operationGeneration == generation { isLoading = false } }
            do {
                try await ensureConnected(device: device)
                try await transport.rename(at: entry.path, to: name)
                guard operationGeneration == generation else { return }
                entries = try await transport.listDirectory(at: path)
                renameEntry = nil
            } catch let challenge as HostKeyChallenge {
                guard operationGeneration == generation else { return }
                pendingTrust = PendingHostMetricsTrust(device: device, challenge: challenge)
            } catch {
                guard operationGeneration == generation else { return }
                self.error = error.localizedDescription
            }
        }
    }

    @MainActor private func deleteRemote(_ entry: RemoteFileEntry) {
        guard let device = selectedDevice, !isLoading, !isTransferring else { return }
        deleteEntry = nil
        let generation = operationGeneration
        isLoading = true; error = nil
        Task {
            defer { if operationGeneration == generation { isLoading = false } }
            do {
                try await ensureConnected(device: device)
                try await transport.delete(entry)
                guard operationGeneration == generation else { return }
                entries = try await transport.listDirectory(at: path)
            } catch let challenge as HostKeyChallenge {
                guard operationGeneration == generation else { return }
                pendingTrust = PendingHostMetricsTrust(device: device, challenge: challenge)
            } catch {
                guard operationGeneration == generation else { return }
                self.error = error.localizedDescription
            }
        }
    }

    @MainActor private func applyPermissions(_ mode: UInt32, to entry: RemoteFileEntry) async -> Bool {
        guard let device = selectedDevice, !isLoading, !isTransferring else { return false }
        let generation = operationGeneration
        let parentPath = path
        isLoading = true; error = nil; transferNotice = nil
        defer { if operationGeneration == generation { isLoading = false } }
        do {
            try await ensureConnected(device: device)
            try await transport.setPermissions(at: entry.path, accessMode: mode)
            guard operationGeneration == generation else { return false }
            entries = try await transport.listDirectory(at: parentPath)
            transferNotice = "Permissions updated to \(String(format: "%03o", mode)) for \(entry.name)."
            return true
        } catch let challenge as HostKeyChallenge {
            guard operationGeneration == generation else { return false }
            pendingTrust = PendingHostMetricsTrust(device: device, challenge: challenge)
            return false
        } catch {
            guard operationGeneration == generation else { return false }
            self.error = error.localizedDescription
            return false
        }
    }

    @MainActor private func deleteLocal(_ url: URL) {
        localDeleteURL = nil
        guard isInsideLocalRoot(url) else {
            error = "Nexus can only delete items inside its local Nexus Files folder."
            return
        }
        do {
            try FileManager.default.removeItem(at: url)
            refreshLocalFiles()
        } catch { self.error = error.localizedDescription }
    }

    @MainActor private func prepareLocalFiles() {
        do {
            try FileManager.default.createDirectory(at: localRoot, withIntermediateDirectories: true)
            #if os(iOS)
            try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete],
                ofItemAtPath: localRoot.path)
            #endif
            var root = localRoot
            var resourceValues = URLResourceValues()
            resourceValues.isExcludedFromBackup = true
            try root.setResourceValues(resourceValues)
            if localPath == nil { localPath = localRoot }
            refreshLocalFiles()
        } catch { self.error = error.localizedDescription }
    }

    @MainActor private func refreshLocalFiles() {
        do {
            localEntries = try FileManager.default.contentsOfDirectory(at: currentLocalDirectory,
                includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey, .fileSizeKey, .contentModificationDateKey],
                options: [])
        } catch { self.error = error.localizedDescription }
    }

    @MainActor private func importToLocalFiles(_ urls: [URL]) {
        do {
            try FileManager.default.createDirectory(at: currentLocalDirectory, withIntermediateDirectories: true)
            for source in urls {
                let hasAccess = source.startAccessingSecurityScopedResource()
                defer { if hasAccess { source.stopAccessingSecurityScopedResource() } }
                let target = uniqueLocalURL(for: source.lastPathComponent, in: currentLocalDirectory)
                try FileManager.default.copyItem(at: source, to: target)
                #if os(iOS)
                try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete],
                    ofItemAtPath: target.path)
                #endif
            }
            refreshLocalFiles()
        } catch { self.error = error.localizedDescription }
    }

    private func uniqueLocalURL(for name: String, in directory: URL) -> URL {
        let candidate = directory.appending(path: name)
        guard FileManager.default.fileExists(atPath: candidate.path) else { return candidate }
        let source = URL(fileURLWithPath: name)
        let base = source.deletingPathExtension().lastPathComponent
        let ext = source.pathExtension
        var index = 2
        while true {
            let suffix = ext.isEmpty ? " (\(index))" : " (\(index)).\(ext)"
            let next = directory.appending(path: base + suffix)
            if !FileManager.default.fileExists(atPath: next.path) { return next }
            index += 1
        }
    }

    private func isLocalDirectory(_ url: URL) -> Bool {
        guard let values = try? url.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey]) else { return false }
        return values.isDirectory == true && values.isSymbolicLink != true
    }

    private func isInsideLocalRoot(_ url: URL) -> Bool {
        let root = localRoot.standardizedFileURL.path + "/"
        return url.standardizedFileURL.path.hasPrefix(root)
    }

    private func isValidBrowserName(_ name: String) -> Bool {
        !name.isEmpty && name != "." && name != ".." && name.utf8.count <= 255 &&
            !name.contains("/") && !name.contains("\\") &&
            !name.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
    }

    private func localFileDetails(_ url: URL, directory: Bool) -> String {
        if directory { return "Folder" }
        let values = try? url.resourceValues(forKeys: [.fileSizeKey, .contentModificationDateKey])
        let size = values?.fileSize.map { ByteCountFormatter.string(fromByteCount: Int64($0), countStyle: .file) } ?? "Size unavailable"
        guard let modified = values?.contentModificationDate else { return size }
        return "\(size) · Modified \(modified.formatted(date: .abbreviated, time: .shortened))"
    }

    @MainActor private func beginUploadDirectory() {
        guard let localURL = uploadDirectoryCandidate, let device = selectedDevice,
              !isLoading, !isTransferring else { return }
        let generation = operationGeneration
        let destination = path == "/" ? "/\(localURL.lastPathComponent)" : "\(path)/\(localURL.lastPathComponent)"
        uploadDirectoryCandidate = nil
        isConfirmingDirectoryUpload = false
        isLoading = true; isTransferring = true; error = nil; transferNotice = nil
        transferDescription = "Preparing folder upload"
        transferProgress.set(nil, label: nil)
        transferTask = Task {
            defer {
                if operationGeneration == generation {
                    isLoading = false
                    isTransferring = false
                    transferDescription = ""
                    transferProgress.set(nil, label: nil)
                    transferTask = nil
                }
            }
            let hasAccess = localURL.startAccessingSecurityScopedResource()
            defer { if hasAccess { localURL.stopAccessingSecurityScopedResource() } }
            do {
                try await ensureConnected(device: device)
                let summary = try await transport.uploadDirectory(localURL: localURL, to: destination) { relativePath, sent, total in
                    guard let total, total > 0 else { return }
                    await transferProgress.set(min(1, Double(sent) / Double(total)),
                        label: "Uploading \(relativePath)")
                }
                guard operationGeneration == generation else { return }
                entries = try await transport.listDirectory(at: path)
                let skippedText = summary.skippedItems == 0 ? "" : ", skipped \(summary.skippedItems) links/special items"
                transferNotice = "Uploaded folder \(localURL.lastPathComponent): \(summary.filesTransferred) file(s), \(summary.directoriesCreated) subfolder(s)\(skippedText)."
            } catch let challenge as HostKeyChallenge {
                guard operationGeneration == generation else { return }
                uploadDirectoryCandidate = localURL
                pendingTrust = PendingHostMetricsTrust(device: device, challenge: challenge)
            } catch is CancellationError {
                guard operationGeneration == generation else { return }
                error = "Folder upload cancelled. Completed items may remain in the new remote folder \(destination)."
            } catch {
                guard operationGeneration == generation else { return }
                self.error = "Folder upload stopped. Completed remote items may remain in \(destination): \(error.localizedDescription)"
            }
        }
    }

    @MainActor private func beginDownloadDirectory() {
        guard let entry = downloadDirectoryCandidate, entry.isDirectory, !entry.isSymbolicLink,
              let device = selectedDevice, !isLoading, !isTransferring else { return }
        let generation = operationGeneration
        let directory = currentLocalDirectory
        let destination = uniqueLocalURL(for: entry.name, in: directory)
        downloadDirectoryCandidate = nil
        isConfirmingDirectoryDownload = false
        isLoading = true; isTransferring = true; error = nil; transferNotice = nil
        transferDescription = "Preparing folder download"
        transferProgress.set(nil, label: nil)
        transferTask = Task {
            defer {
                if operationGeneration == generation {
                    isLoading = false
                    isTransferring = false
                    transferDescription = ""
                    transferProgress.set(nil, label: nil)
                    transferTask = nil
                }
            }
            do {
                try await ensureConnected(device: device)
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
                let summary = try await transport.downloadDirectory(remotePath: entry.path, to: destination) { relativePath, received, total in
                    guard let total, total > 0 else { return }
                    await transferProgress.set(min(1, Double(received) / Double(total)),
                        label: "Downloading \(relativePath)")
                }
                guard operationGeneration == generation else { return }
                localPath = directory
                refreshLocalFiles()
                browserSide = .local
                let skippedText = summary.skippedItems == 0 ? "" : ", skipped \(summary.skippedItems) links/special items"
                transferNotice = "Downloaded folder \(entry.name): \(summary.filesTransferred) file(s), \(summary.directoriesCreated) subfolder(s)\(skippedText)."
            } catch let challenge as HostKeyChallenge {
                guard operationGeneration == generation else { return }
                downloadDirectoryCandidate = entry
                pendingTrust = PendingHostMetricsTrust(device: device, challenge: challenge)
            } catch is CancellationError {
                guard operationGeneration == generation else { return }
                self.error = "Folder download cancelled. The incomplete local folder was removed."
            } catch {
                guard operationGeneration == generation else { return }
                self.error = error.localizedDescription
            }
        }
    }

    @MainActor private func beginUploadBatch(overwriteEntries: [String: RemoteFileEntry],
                                             skipNames: Set<String> = []) {
        let candidates = uploadCandidates
        guard !candidates.isEmpty, let device = selectedDevice,
              !isLoading, !isTransferring else { return }
        let generation = operationGeneration
        let blockedCount = uploadBlockedCount
        uploadBlockedCount = 0
        uploadCandidates = []
        self.overwriteEntries = [:]
        overwriteRemote = false
        isLoading = true; error = nil
        isTransferring = true
        transferProgress.fraction = 0
        var completed = 0
        var skipped = 0
        transferTask = Task {
            defer {
                if operationGeneration == generation {
                    isLoading = false
                    isTransferring = false
                    transferProgress.fraction = nil
                    transferDescription = ""
                    transferTask = nil
                }
            }
            do {
                try await ensureConnected(device: device)
                for (index, localURL) in candidates.enumerated() {
                    try Task.checkCancellation()
                    let name = localURL.lastPathComponent
                    if skipNames.contains(name) {
                        skipped += 1
                        continue
                    }
                    transferDescription = "Uploading \(index + 1) of \(candidates.count): \(name)"
                    transferProgress.fraction = 0
                    let hasAccess = localURL.startAccessingSecurityScopedResource()
                    defer { if hasAccess { localURL.stopAccessingSecurityScopedResource() } }
                    let remote = path == "/" ? "/\(name)" : "\(path)/\(name)"
                    let existing = overwriteEntries[name]
                    do {
                        try await transport.upload(localURL: localURL, to: remote,
                            overwrite: existing != nil,
                            expectedExistingSize: existing?.size,
                            expectedExistingModifiedAt: existing?.modifiedAt) { transferred, total in
                            guard let total, total > 0 else { return }
                            await transferProgress.set(min(1, Double(transferred) / Double(total)))
                        }
                    }
                    completed += 1
                }
                guard operationGeneration == generation else { return }
                entries = try await transport.listDirectory(at: path)
                if skipped + blockedCount > 0 {
                    transferNotice = "Uploaded \(completed) file(s); skipped \(skipped + blockedCount) item(s)."
                } else {
                    transferNotice = "Uploaded \(completed) file(s)."
                }
            } catch let challenge as HostKeyChallenge {
                guard operationGeneration == generation else { return }
                uploadCandidates = candidates
                self.overwriteEntries = overwriteEntries
                uploadBlockedCount = blockedCount
                pendingTrust = PendingHostMetricsTrust(device: device, challenge: challenge)
            } catch is CancellationError {
                guard operationGeneration == generation else { return }
                self.error = "Upload batch cancelled after \(completed) file(s). Incomplete temporary data was removed where possible."
            } catch {
                guard operationGeneration == generation else { return }
                self.error = "Upload stopped after \(completed) of \(candidates.count) file(s): \(error.localizedDescription)"
            }
        }
    }

    @MainActor private func download(_ entry: RemoteFileEntry) {
        download([entry])
    }

    @MainActor private func download(_ requestedEntries: [RemoteFileEntry]) {
        guard !isLoading, !isTransferring, let device = selectedDevice else { return }
        let files = requestedEntries.filter { !$0.isDirectory }
        guard !files.isEmpty else { return }
        let generation = operationGeneration
        let directory = currentLocalDirectory
        isLoading = true; error = nil; transferNotice = nil
        isTransferring = true
        transferProgress.fraction = 0
        var completedURLs: [URL] = []
        var completed = 0
        transferDescription = "Preparing \(files.count) download(s)"
        transferTask = Task {
            defer {
                if operationGeneration == generation {
                    isLoading = false
                    isTransferring = false
                    transferProgress.fraction = nil
                    transferDescription = ""
                    transferTask = nil
                }
            }
            do {
                try await ensureConnected(device: device)
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
                for (index, entry) in files.enumerated() {
                    try Task.checkCancellation()
                    transferDescription = "Downloading \(index + 1) of \(files.count): \(entry.name)"
                    transferProgress.fraction = 0
                    let url = uniqueLocalURL(for: entry.name, in: directory)
                    try await transport.download(remotePath: entry.operationPath, to: url) { transferred, total in
                        guard let total, total > 0 else { return }
                        await transferProgress.set(min(1, Double(transferred) / Double(total)))
                    }
                    guard operationGeneration == generation else {
                        try? FileManager.default.removeItem(at: url)
                        return
                    }
                    completedURLs.append(url)
                    completed += 1
                }
                guard operationGeneration == generation else { return }
                localPath = directory
                refreshLocalFiles()
                browserSide = .local
                selectedRemoteFilePaths.removeAll()
                isSelectingRemoteFiles = false
                if completedURLs.count == 1, let url = completedURLs.first {
                    downloadArtifact = DownloadArtifact(url: url)
                } else {
                    transferNotice = "Downloaded \(completed) file(s) to Nexus Files."
                }
            } catch let challenge as HostKeyChallenge {
                guard operationGeneration == generation else { return }
                pendingTrust = PendingHostMetricsTrust(device: device, challenge: challenge)
            } catch is CancellationError {
                guard operationGeneration == generation else { return }
                if !completedURLs.isEmpty {
                    localPath = directory
                    refreshLocalFiles()
                    browserSide = .local
                }
                self.error = "Download batch cancelled after \(completed) file(s). The incomplete file was removed."
            } catch {
                guard operationGeneration == generation else { return }
                if !completedURLs.isEmpty {
                    localPath = directory
                    refreshLocalFiles()
                    browserSide = .local
                }
                self.error = "Download stopped after \(completed) of \(files.count) file(s): \(error.localizedDescription)"
            }
        }
    }

    @MainActor private func ensureConnected(device: Device) async throws {
        guard let endpoint = sourceEndpoint ?? device.orderedEndpoints.first else {
            throw SSHFailure.connectionFailed
        }
        try await transport.connect(device: device, endpoint: endpoint,
            secrets: store.secrets, timeout: store.timeout)
    }

    private func fileDetails(_ entry: RemoteFileEntry) -> String {
        let size = entry.size.map { ByteCountFormatter.string(fromByteCount: Int64(clamping: $0), countStyle: .file) } ?? "Size unavailable"
        let mode = entry.permissions.map { String(format: "%03o", $0 & 0o777) }
        var details = [size]
        if let mode { details.append("Permissions \(mode)") }
        if let modifiedAt = entry.modifiedAt {
            details.append("Modified \(modifiedAt.formatted(date: .abbreviated, time: .shortened))")
        }
        return details.joined(separator: " · ")
    }
}

private enum FilesBrowserSide: String, CaseIterable, Identifiable {
    case remote
    case local
    var id: String { rawValue }
    var title: String { self == .remote ? "Remote" : "Local" }
}

private enum FilesSortOrder: String, CaseIterable, Identifiable {
    case name
    case size
    case modified
    var id: String { rawValue }
    var title: String {
        switch self {
        case .name: "Name"
        case .size: "Largest First"
        case .modified: "Recently Modified"
        }
    }
}

private struct DownloadArtifact: Identifiable {
    let id = UUID()
    let url: URL
}

private enum RemoteTextSaveResult {
    case saved
    case failed(String)
    case verificationRequired
}

@MainActor @Observable
private final class SFTPTransferProgress {
    var fraction: Double?
    var itemLabel: String?
    func set(_ fraction: Double?, label: String? = nil) {
        self.fraction = fraction
        itemLabel = label
    }
}

private struct RemotePermissionsEditor: View {
    @Environment(\.dismiss) private var dismiss
    let entry: RemoteFileEntry
    let onApply: @MainActor (UInt32) async -> Bool
    @State private var mode: UInt32
    @State private var isConfirming = false
    @State private var isApplying = false

    init(entry: RemoteFileEntry, onApply: @escaping @MainActor (UInt32) async -> Bool) {
        self.entry = entry
        self.onApply = onApply
        _mode = State(initialValue: (entry.permissions ?? 0) & 0o777)
    }

    var body: some View {
        NavigationStack {
            NexusForm {
                Section("Owner") {
                    permissionToggle("Read", bit: 0o400)
                    permissionToggle("Write", bit: 0o200)
                    permissionToggle("Execute", bit: 0o100)
                }
                Section("Group") {
                    permissionToggle("Read", bit: 0o040)
                    permissionToggle("Write", bit: 0o020)
                    permissionToggle("Execute", bit: 0o010)
                }
                Section("Others") {
                    permissionToggle("Read", bit: 0o004)
                    permissionToggle("Write", bit: 0o002)
                    permissionToggle("Execute", bit: 0o001)
                }
                Section("Review") {
                    LabeledContent("New numeric mode", value: String(format: "%03o", mode))
                    Text(entry.path).font(.caption.monospaced()).textSelection(.enabled)
                    Text("Only read, write, and execute bits change. Existing special mode bits are preserved. The server may deny this operation. SFTP v3 cannot make the link check and permission change atomic against concurrent server-side changes.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Remote Permissions")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }.disabled(isApplying)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button {
                        isConfirming = true
                    } label: {
                        if isApplying { ProgressView() } else { Text("Apply") }
                    }
                    .disabled(isApplying || entry.isSymbolicLink)
                }
            }
            .confirmationDialog("Apply permissions \(String(format: "%03o", mode))?",
                isPresented: $isConfirming, titleVisibility: .visible) {
                Button("Change Remote Permissions", role: .destructive) {
                    isApplying = true
                    Task {
                        let applied = await onApply(mode)
                        isApplying = false
                        if applied { dismiss() }
                    }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("This changes access for \(entry.name) at the displayed remote path. Verify the target before applying.")
            }
        }
    }

    private func permissionToggle(_ title: String, bit: UInt32) -> some View {
        Toggle(title, isOn: Binding(
            get: { mode & bit != 0 },
            set: { enabled in
                if enabled { mode |= bit } else { mode &= ~bit }
            }
        ))
    }
}

private struct RemoteTextEditor: View {
    @Environment(\.dismiss) private var dismiss
    @State var draft: RemoteTextDraft
    @State private var showSaveConfirmation = false
    @State private var showDiscardConfirmation = false
    @State private var isSaving = false
    @State private var saveError: String?
    let onSave: @MainActor (RemoteTextDraft,
                            @escaping @MainActor (RemoteTextSaveResult) -> Void) -> Void

    var body: some View {
        NavigationStack {
            TextEditor(text: $draft.contents)
                .font(.system(.body, design: .monospaced))
                .accessibilityLabel("Text contents of \(draft.name)")
                .disabled(isSaving)
                .navigationTitle(draft.name)
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") {
                            if draft.contents == draft.originalContents { dismiss() }
                            else { showDiscardConfirmation = true }
                        }
                        .disabled(isSaving)
                    }
                    ToolbarItem(placement: .confirmationAction) {
                        Button {
                            showSaveConfirmation = true
                        } label: {
                            if isSaving { ProgressView().accessibilityLabel("Saving remote file") }
                            else { Text("Save") }
                        }
                            .disabled(isSaving)
                    }
                }
                .interactiveDismissDisabled(isSaving || draft.contents != draft.originalContents)
                .confirmationDialog(showSaveConfirmation ? "Save changes to the remote file?" : "Discard text edits?",
                    isPresented: Binding(get: { showSaveConfirmation || showDiscardConfirmation }, set: { shown in
                        if !shown { showSaveConfirmation = false; showDiscardConfirmation = false }
                    }), titleVisibility: .visible) {
                        if showSaveConfirmation {
                            Button("Save remote file", role: .destructive) {
                                isSaving = true
                                onSave(draft) { result in
                                    isSaving = false
                                    switch result {
                                    case .saved:
                                        dismiss()
                                    case .failed(let message):
                                        saveError = message
                                    case .verificationRequired:
                                        break
                                    }
                                }
                            }
                            Button("Cancel", role: .cancel) {}
                        } else {
                            Button("Discard edits", role: .destructive) { dismiss() }
                            Button("Keep editing", role: .cancel) {}
                        }
                    } message: {
                        if showSaveConfirmation {
                            Text("Nexus checks the remote file size and modification time before replacing it and keeps a temporary backup during the write.")
                        } else { Text("Your unsaved text changes will be lost.") }
                    }
                .alert("Could not save remote file", isPresented: Binding(
                    get: { saveError != nil }, set: { if !$0 { saveError = nil } }
                )) {
                    Button("OK", role: .cancel) { saveError = nil }
                } message: {
                    Text(saveError ?? "")
                }
        }
    }
}
