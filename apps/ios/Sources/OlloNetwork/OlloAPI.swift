import Foundation

public enum OlloAPI {
    public static let production = URL(string: "https://api.ollo.example")!
    public static let local = URL(string: "http://127.0.0.1:8080")!

    public static var baseURL: URL {
        #if DEBUG
        local
        #else
        production
        #endif
    }
}
