import SwiftUI
import OlloCrypto

enum Dest { case auth, chats, chat, settings }

struct ChatRow: Identifiable, Equatable {
    var id: String
    var title: String
    var preview: String
}

struct ContentView: View {
    let host: SessionHost
    @State private var dest: Dest
    @State private var authError = ""
    @State private var threads: [ChatRow]
    @State private var active: ChatRow?

    init(host: SessionHost) {
        self.host = host
        if (try? host.launch()) == .signedIn {
            _dest = State(initialValue: .chats)
            let rows = (try? host.loadInbox())?.visible().map {
                ChatRow(id: $0.id, title: $0.title, preview: $0.preview)
            } ?? []
            _threads = State(initialValue: rows)
        } else {
            _dest = State(initialValue: .auth)
            _threads = State(initialValue: [])
        }
    }

    var body: some View {
        ZStack {
            Color(red: 0.03, green: 0.04, blue: 0.05).ignoresSafeArea()
            switch dest {
            case .auth:
                VStack(alignment: .leading, spacing: 14) {
                    Text("OllO").font(.system(size: 40, weight: .heavy)).foregroundStyle(Color(red: 0.24, green: 0.88, blue: 0.70))
                    Text(tagline).foregroundStyle(.secondary)
                    Text(addressHint).foregroundStyle(.secondary).font(.footnote)
                    if !authError.isEmpty {
                        Text(authError).foregroundStyle(.red)
                    }
                    Button(continueLabel) {
                        Task {
                            do {
                                try await host.signIn()
                                reloadInbox()
                                dest = .chats
                            } catch is UnboundCryptoEngine.EngineError {
                                authError = engineUnbound
                            } catch {
                                authError = signInFailed
                            }
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    Text(engineUnbound).foregroundStyle(.secondary).font(.footnote)
                }.padding(28)
            case .chats:
                VStack(alignment: .leading) {
                    HStack {
                        Text("OllO").font(.title.bold()).foregroundStyle(.white)
                        Spacer()
                        Button("⚙") { dest = .settings }
                    }.padding()
                    if threads.isEmpty {
                        Text(emptyInbox)
                            .foregroundStyle(.secondary)
                            .padding()
                    } else {
                        ForEach(threads) { row in
                            Button(row.title) { active = row; dest = .chat }
                                .foregroundStyle(.white)
                                .padding()
                        }
                    }
                    Spacer()
                }
            case .chat:
                VStack {
                    HStack {
                        Button("← \(active?.title ?? "")") { dest = .chats }.foregroundStyle(.white)
                        Spacer()
                        Text("🔒")
                    }.padding()
                    Spacer()
                    Text(e2eeHint).foregroundStyle(.secondary)
                    Spacer()
                }
            case .settings:
                VStack(alignment: .leading, spacing: 12) {
                    Button("← \(settingsTitle)") { dest = .chats }.foregroundStyle(.white)
                    Text(settingsBody).foregroundStyle(.secondary)
                    Button(wipeLocal) {
                        host.wipe()
                        threads = []
                        active = nil
                        dest = .auth
                    }
                    Spacer()
                }.padding()
            }
        }
    }

    private func reloadInbox() {
        threads = (try? host.loadInbox())?.visible().map {
            ChatRow(id: $0.id, title: $0.title, preview: $0.preview)
        } ?? []
    }

    private var russian: Bool {
        Locale.preferredLanguages.first?.hasPrefix("ru") == true
    }

    private var tagline: String {
        russian
            ? "Защищённые сообщения. Сервер не читает переписку."
            : "Private messages. The server cannot read them."
    }

    private var continueLabel: String { russian ? "Создать аккаунт" : "Create account" }

    private var addressHint: String {
        russian
            ? "Приватный ключ остаётся на устройстве. Публичный ключ — ваш адрес."
            : "The private key stays on this device. The public key is your address."
    }

    private var emptyInbox: String {
        russian
            ? "Чатов пока нет. Найдите пользователя по адресу ollo:user:… или username. На устройстве нет демо-переписок."
            : "No chats yet. Search an ollo:user:… address or username after you sign in. Nothing is seeded on this device."
    }

    private var e2eeHint: String {
        russian ? "Сообщения шифруются на устройстве" : "Messages are encrypted on this device."
    }

    private var settingsTitle: String { russian ? "Настройки" : "Settings" }

    private var settingsBody: String {
        russian
            ? "Устройства, код безопасности, PIN, исчезающие сообщения."
            : "Devices, safety number, registration lock, disappearing messages."
    }

    private var wipeLocal: String {
        russian ? "Стереть локальные секреты" : "Wipe local secrets"
    }

    private var engineUnbound: String {
        russian
            ? "Вход требует привязанный движок libsignal. Эта сборка не создаёт фальшивую сессию."
            : "Sign-in needs a bound libsignal engine. This build will not fake a session."
    }

    private var signInFailed: String {
        russian ? "Вход не удался." : "Sign-in failed."
    }
}
