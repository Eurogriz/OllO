package app.ollo.database

import android.content.Context
import net.zetetic.database.sqlcipher.SQLiteDatabase
import java.io.File

/**
 * SQLCipher database. The passphrase comes from Android Keystore via the app
 * layer and is never written to disk in plaintext. The file lives in
 * noBackupFilesDir so cloud backup cannot extract the ciphertext DB.
 */
class SecureDb(context: Context, passphrase: ByteArray) {
    private val db: SQLiteDatabase

    init {
        System.loadLibrary("sqlcipher")
        val file = File(context.noBackupFilesDir, "ollo.db")
        db = SQLiteDatabase.openOrCreateDatabase(file.absolutePath, passphrase, null, null)
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS messages (
              client_id TEXT PRIMARY KEY,
              thread_id TEXT NOT NULL,
              sender_id TEXT NOT NULL,
              sent_at INTEGER NOT NULL,
              status TEXT NOT NULL,
              body BLOB NOT NULL
            )
            """.trimIndent(),
        )
        db.execSQL("CREATE INDEX IF NOT EXISTS messages_thread ON messages(thread_id, sent_at)")
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS outbound_queue (
              id TEXT PRIMARY KEY,
              payload BLOB NOT NULL,
              attempts INTEGER NOT NULL,
              next_attempt_at INTEGER NOT NULL
            )
            """.trimIndent(),
        )
    }

    fun insertMessage(
        clientId: String,
        threadId: String,
        senderId: String,
        sentAt: Long,
        status: String,
        body: ByteArray,
    ) {
        db.execSQL(
            "INSERT OR REPLACE INTO messages(client_id, thread_id, sender_id, sent_at, status, body) VALUES(?,?,?,?,?,?)",
            arrayOf(clientId, threadId, senderId, sentAt, status, body),
        )
    }

    fun enqueueOutbound(id: String, payload: ByteArray) {
        db.execSQL(
            "INSERT OR REPLACE INTO outbound_queue(id, payload, attempts, next_attempt_at) VALUES(?,?,0,?)",
            arrayOf(id, payload, System.currentTimeMillis()),
        )
    }

    fun close() = db.close()
}
