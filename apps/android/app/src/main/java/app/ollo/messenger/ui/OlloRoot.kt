package app.ollo.messenger.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.ollo.crypto.ChatThread
import app.ollo.crypto.ThreadIndex
import app.ollo.messenger.R

private val Bg = Color(0xFF070A0E)
private val Elev = Color(0xFF141B24)
private val Accent = Color(0xFF3EE0B2)
private val TextC = Color(0xFFEEF3F8)
private val Mute = Color(0xFF8B9BB0)

private enum class Dest { Splash, Auth, Chats, Chat, Settings }

@Composable
fun OlloRoot() {
    var dest by remember { mutableStateOf(Dest.Auth) }
    var phone by remember { mutableStateOf("+7") }
    var otp by remember { mutableStateOf("") }
    val inbox = remember { ThreadIndex() }
    var threads by remember { mutableStateOf(inbox.visible()) }
    var active by remember { mutableStateOf<ChatThread?>(null) }
    Box(Modifier.fillMaxSize().background(Bg)) {
        when (dest) {
            Dest.Splash, Dest.Auth -> AuthScreen(
                phone = phone,
                otp = otp,
                onPhone = { phone = it },
                onOtp = { otp = it },
                onContinue = { dest = Dest.Chats },
            )
            Dest.Chats -> ChatList(
                threads = threads,
                onOpen = {
                    active = it
                    dest = Dest.Chat
                },
                onSettings = { dest = Dest.Settings },
            )
            Dest.Chat -> ChatScreen(
                title = active?.title.orEmpty(),
                onBack = { dest = Dest.Chats },
            )
            Dest.Settings -> SettingsScreen(
                onBack = { dest = Dest.Chats },
                onWipe = {
                    inbox.wipe()
                    threads = inbox.visible()
                    active = null
                    dest = Dest.Auth
                },
            )
        }
    }
}

@Composable
private fun AuthScreen(
    phone: String,
    otp: String,
    onPhone: (String) -> Unit,
    onOtp: (String) -> Unit,
    onContinue: () -> Unit,
) {
    Column(
        Modifier.fillMaxSize().padding(28.dp),
        verticalArrangement = Arrangement.Center,
    ) {
        Box(
            Modifier.size(48.dp).clip(RoundedCornerShape(14.dp)).background(Accent),
            contentAlignment = Alignment.Center,
        ) { Text("O", color = Color(0xFF06241B), fontWeight = FontWeight.Black, fontSize = 22.sp) }
        Text("OllO", color = Accent, fontSize = 40.sp, fontWeight = FontWeight.ExtraBold)
        Text(stringResource(R.string.tagline), color = Mute, modifier = Modifier.padding(top = 6.dp, bottom = 24.dp))
        OlloField(phone, onPhone, "E.164")
        OlloField(otp, onOtp, "OTP", KeyboardType.Number)
        Button(
            onClick = onContinue,
            colors = ButtonDefaults.buttonColors(containerColor = Accent, contentColor = Color(0xFF06241B)),
            modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
        ) { Text(stringResource(R.string.continue_label), fontWeight = FontWeight.Bold) }
    }
}

@Composable
private fun ChatList(
    threads: List<ChatThread>,
    onOpen: (ChatThread) -> Unit,
    onSettings: () -> Unit,
) {
    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text("OllO", color = TextC, fontWeight = FontWeight.ExtraBold, fontSize = 22.sp)
            Text("⚙", color = Accent, modifier = Modifier.clickable(onClick = onSettings))
        }
        if (threads.isEmpty()) {
            Text(
                stringResource(R.string.empty_inbox),
                color = Mute,
                modifier = Modifier.padding(24.dp),
            )
        } else {
            LazyColumn {
                items(threads, key = { it.id }) { thread ->
                    Row(
                        Modifier.fillMaxWidth().clickable { onOpen(thread) }.padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Box(
                            Modifier.size(44.dp).clip(RoundedCornerShape(14.dp)).background(Color(0xFF223044)),
                            contentAlignment = Alignment.Center,
                        ) { Text(thread.title.take(1), color = TextC, fontWeight = FontWeight.Bold) }
                        Column(Modifier.padding(start = 12.dp)) {
                            Text(thread.title, color = TextC, fontWeight = FontWeight.Bold)
                            if (thread.preview.isNotEmpty()) {
                                Text(thread.preview, color = Mute, fontSize = 13.sp)
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ChatScreen(title: String, onBack: () -> Unit) {
    var draft by remember { mutableStateOf("") }
    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier.fillMaxWidth().padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text("← $title", color = TextC, fontWeight = FontWeight.Bold, modifier = Modifier.clickable(onClick = onBack))
            Text("🔒", color = Accent)
        }
        Box(Modifier.weight(1f).fillMaxWidth().padding(16.dp), contentAlignment = Alignment.BottomEnd) {
            Text(stringResource(R.string.e2ee_hint), color = Mute)
        }
        OlloField(draft, { draft = it }, stringResource(R.string.message_hint))
    }
}

@Composable
private fun SettingsScreen(onBack: () -> Unit, onWipe: () -> Unit) {
    Column(Modifier.fillMaxSize().padding(20.dp)) {
        Text(
            "← ${stringResource(R.string.settings)}",
            color = TextC,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.clickable(onClick = onBack),
        )
        Text(
            stringResource(R.string.settings_body),
            color = Mute,
            modifier = Modifier.padding(top = 16.dp),
        )
        Button(
            onClick = onWipe,
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF3A1A1A), contentColor = Color(0xFFFFC9C9)),
            modifier = Modifier.fillMaxWidth().padding(top = 24.dp),
        ) { Text(stringResource(R.string.wipe_local), fontWeight = FontWeight.Bold) }
    }
}

@Composable
private fun OlloField(
    value: String,
    onChange: (String) -> Unit,
    label: String,
    type: KeyboardType = KeyboardType.Text,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = { Text(label) },
        keyboardOptions = KeyboardOptions(keyboardType = type),
        colors = TextFieldDefaults.colors(
            focusedTextColor = TextC,
            unfocusedTextColor = TextC,
            focusedContainerColor = Elev,
            unfocusedContainerColor = Elev,
        ),
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
    )
}
