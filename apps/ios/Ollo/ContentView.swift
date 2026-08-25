import SwiftUI

enum Dest { case auth, chats, chat, settings }

struct ContentView: View {
    @State private var dest: Dest = .auth
    @State private var phone = "+7"
    @State private var otp = ""
    @State private var active = "Алиса"

    var body: some View {
        ZStack {
            Color(red: 0.03, green: 0.04, blue: 0.05).ignoresSafeArea()
            switch dest {
            case .auth:
                VStack(alignment: .leading, spacing: 14) {
                    Text("OllO").font(.system(size: 40, weight: .heavy)).foregroundStyle(Color(red: 0.24, green: 0.88, blue: 0.70))
                    Text("Защищённые сообщения. Сервер не читает переписку.").foregroundStyle(.secondary)
                    TextField("Телефон", text: $phone).textFieldStyle(.roundedBorder)
                    TextField("OTP", text: $otp).textFieldStyle(.roundedBorder)
                    Button("Продолжить") { dest = .chats }
                        .buttonStyle(.borderedProminent)
                }.padding(28)
            case .chats:
                VStack(alignment: .leading) {
                    HStack {
                        Text("OllO").font(.title.bold()).foregroundStyle(.white)
                        Spacer()
                        Button("⚙") { dest = .settings }
                    }.padding()
                    Button("Алиса") { active = "Алиса"; dest = .chat }
                        .foregroundStyle(.white)
                        .padding()
                    Spacer()
                }
            case .chat:
                VStack {
                    HStack {
                        Button("← \(active)") { dest = .chats }.foregroundStyle(.white)
                        Spacer()
                        Text("🔒")
                    }.padding()
                    Spacer()
                    Text("Сообщения шифруются на устройстве").foregroundStyle(.secondary)
                    Spacer()
                }
            case .settings:
                VStack(alignment: .leading, spacing: 12) {
                    Button("← Настройки") { dest = .chats }.foregroundStyle(.white)
                    Text("Устройства, код безопасности, PIN, исчезающие сообщения.")
                        .foregroundStyle(.secondary)
                    Spacer()
                }.padding()
            }
        }
    }
}
