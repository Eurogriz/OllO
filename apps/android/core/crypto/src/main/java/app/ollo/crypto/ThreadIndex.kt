package app.ollo.crypto

/**
 * Local chat list. Never seeded with demo contacts. Previews are whatever
 * the device already decrypted — the server never supplies them.
 */
data class ChatThread(
    val id: String,
    val title: String,
    val preview: String = "",
    val peerUserId: String? = null,
    val groupId: String? = null,
    val archived: Boolean = false,
    val muted: Boolean = false,
)

class ThreadIndex {
    private val threads = linkedMapOf<String, ChatThread>()

    fun visible(): List<ChatThread> = threads.values.filter { !it.archived }

    fun upsert(thread: ChatThread) {
        threads[thread.id] = thread
    }

    fun archive(id: String, archived: Boolean = true) {
        val t = threads[id] ?: return
        threads[id] = t.copy(archived = archived)
    }

    fun wipe() {
        threads.clear()
    }

    fun isEmpty(): Boolean = visible().isEmpty()
}
