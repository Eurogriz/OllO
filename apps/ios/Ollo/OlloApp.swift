import SwiftUI

@main
struct OlloApp: App {
    private let host: SessionHost?

    init() {
        host = try? SessionHost.open()
    }

    var body: some Scene {
        WindowGroup {
            if let host {
                ContentView(host: host)
                    .preferredColorScheme(.dark)
            } else {
                Text(wrapUnavailable)
                    .foregroundStyle(.secondary)
                    .padding(28)
                    .preferredColorScheme(.dark)
            }
        }
    }

    private var wrapUnavailable: String {
        Locale.preferredLanguages.first?.hasPrefix("ru") == true
            ? "Это устройство не может развернуть хранилище протокола."
            : "This device cannot unwrap the protocol store."
    }
}
