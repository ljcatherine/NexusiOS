import NexusCore

enum RemoteCommandTimeout {
    static func wrap(_ command: String, timeout: Int, maximum: Int, errorPrefix: String) -> String {
        let seconds = max(3, min(timeout, maximum))
        return "if command -v timeout >/dev/null 2>&1; then timeout -s TERM -k 2s \(seconds)s sh -c \(Shell.quote(command)); result=$?; if [ \"$result\" -eq 143 ]; then exit 124; else exit \"$result\"; fi; else printf '\(errorPrefix)\\ttimeout_unavailable\\n'; exit 125; fi"
    }
}
