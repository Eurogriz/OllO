package app.ollo.messenger.state

/**
 * Offline-first message state machine.
 * pending → encrypted → uploading? → sent → delivered → read
 *                                   ↘ failed → retrying → …
 */
enum class MessageStatus {
    Draft,
    Pending,
    Encrypted,
    Uploading,
    Sent,
    Delivered,
    Read,
    Failed,
    Retrying,
}

data class OutboundMessage(
    val clientId: String,
    val threadId: String,
    val status: MessageStatus,
    val attempts: Int,
    val lastError: String?,
) {
    fun nextOnError(): OutboundMessage = copy(
        status = if (attempts + 1 >= 8) MessageStatus.Failed else MessageStatus.Retrying,
        attempts = attempts + 1,
        lastError = "send_failed",
    )
}
