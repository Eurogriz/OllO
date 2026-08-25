package app.ollo.messenger.state

import app.ollo.crypto.EnvelopePlanner

/**
 * Offline-first message state machine.
 * pending → encrypted → uploading? → sent → delivered → read
 *                                   ↘ failed → retrying → …
 *
 * Transitions come from [EnvelopePlanner] so Android matches web/iOS.
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
    fun nextOnError(): OutboundMessage {
        val next = EnvelopePlanner.onSendFailure(
            EnvelopePlanner.OutboxItem(
                id = clientId,
                status = EnvelopePlanner.Status.Pending,
                attempts = attempts,
            ),
        )
        return copy(
            status = if (next.status == EnvelopePlanner.Status.Failed) {
                MessageStatus.Failed
            } else {
                MessageStatus.Retrying
            },
            attempts = next.attempts,
            lastError = "send_failed",
        )
    }
}
