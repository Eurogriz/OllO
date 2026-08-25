import SwiftUI

enum Dest { case auth, chats, chat, settings }

struct ChatRow: Identifiable, Equatable {
    var id: String
    var title: String
    var preview: String
}

struct ContentView: View {
    @State private var dest: Dest = .auth
    @State private var phone = "+7"
    @State private var otp = ""
    @State private var threads: [ChatRow] = []
    @State private var active: ChatRow?

    var body: some View {
        ZStack {
            Color(red: 0.03, green: 0.04, blue: 0.05).ignoresSafeArea()
            switch dest {
            case .auth:
                VStack(alignment: .leading, spacing: 14) {
                    Text("OllO").font(.system(size: 40, weight: .heavy)).foregroundStyle(Color(red: 0.24, green: 0.88, blue: 0.70))
                    Text(tagline).foregroundStyle(.secondary)
                    TextField("E.164", text: $phone).textFieldStyle(.roundedBorder)
                    TextField("OTP", text: $otp).textFieldStyle(.roundedBorder)
                    Button(continueLabel) { dest = .chats }
                        .buttonStyle(.borderedProminent)
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
                        threads = []
                        active = nil
                        dest = .auth
                    }
                    Spacer()
                }.padding()
            }
        }
    }

    private var russian: Bool {
        Locale.preferredLanguages.first?.hasPrefix("ru") == true
    }

    private var tagline: String {
        russian
            ? "Защищённые сообщения. Сервер не читает переписку."
            : "Private messages. The server cannot read them."
    }

    private var continueLabel: String { russian ? "Продолжить" : "Continue" }

    private var emptyInbox: String {
        russian
            ? "Чатов пока нет. Найдите пользователя по username после входа. На устройстве нет демо-переписок."
            : "No chats yet. Search a username after you sign in. Nothing is seeded on this device."
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
}
