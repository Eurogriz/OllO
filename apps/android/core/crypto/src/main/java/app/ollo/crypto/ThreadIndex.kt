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
) {
    fun encode(): ByteArray {
        val flags = ((if (archived) 1 else 0) or (if (muted) 2 else 0)).toByte()
        return BlobMap.encode(
            linkedMapOf(
                "title" to title.toByteArray(Charsets.UTF_8),
                "preview" to preview.toByteArray(Charsets.UTF_8),
                "peer" to (peerUserId ?: "").toByteArray(Charsets.UTF_8),
                "group" to (groupId ?: "").toByteArray(Charsets.UTF_8),
                "flags" to byteArrayOf(flags),
            ),
        )
    }

    companion object {
        fun decode(id: String, raw: ByteArray): ChatThread {
            val m = BlobMap.decode(raw)
            val flags = m["flags"]?.firstOrNull()?.toInt() ?: 0
            return ChatThread(
                id = id,
                title = m["title"]?.toString(Charsets.UTF_8) ?: id,
                preview = m["preview"]?.toString(Charsets.UTF_8) ?: "",
                peerUserId = m["peer"]?.toString(Charsets.UTF_8)?.ifEmpty { null },
                groupId = m["group"]?.toString(Charsets.UTF_8)?.ifEmpty { null },
                archived = flags and 1 != 0,
                muted = flags and 2 != 0,
            )
        }
    }
}

class ThreadIndex {
    private val threads = linkedMapOf<String, ChatThread>()

    fun visible(): List<ChatThread> = threads.values.filter { !it.archived }

    fun snapshot(): List<ChatThread> = threads.values.toList()

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

    fun encode(): ByteArray = BlobMap.encode(threads.mapValues { it.value.encode() })

    companion object {
        fun decode(bytes: ByteArray): ThreadIndex {
            val index = ThreadIndex()
            for ((id, raw) in BlobMap.decode(bytes)) {
                index.upsert(ChatThread.decode(id, raw))
            }
            return index
        }
    }
}
