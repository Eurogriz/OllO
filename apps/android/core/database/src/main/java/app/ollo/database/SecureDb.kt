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
    private val file: File = File(context.noBackupFilesDir, "ollo.db")
    private val db: SQLiteDatabase

    init {
        System.loadLibrary("sqlcipher")
        db = SQLiteDatabase.openOrCreateDatabase(file.absolutePath, passphrase, null, null)
        db.execSQL("PRAGMA cipher_memory_security = ON")
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS kv (
              k TEXT PRIMARY KEY,
              v BLOB NOT NULL
            )
            """.trimIndent(),
        )
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS messages (
              client_id TEXT PRIMARY KEY,
              thread_id TEXT NOT NULL,
              sender_id TEXT NOT NULL,
              sent_at INTEGER NOT NULL,
              status TEXT NOT NULL,
              expires_at INTEGER,
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
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS sessions (
              id TEXT PRIMARY KEY,
              peer_user_id TEXT NOT NULL,
              peer_device_id TEXT NOT NULL,
              blob BLOB NOT NULL
            )
            """.trimIndent(),
        )
    }

    fun putKv(key: String, value: ByteArray) {
        db.execSQL("INSERT OR REPLACE INTO kv(k, v) VALUES(?,?)", arrayOf(key, value))
    }

    fun getKv(key: String): ByteArray? {
        val c = db.rawQuery("SELECT v FROM kv WHERE k = ?", arrayOf(key))
        return c.use {
            if (!it.moveToFirst()) null else it.getBlob(0)
        }
    }

    fun insertMessage(
        clientId: String,
        threadId: String,
        senderId: String,
        sentAt: Long,
        status: String,
        body: ByteArray,
        expiresAt: Long? = null,
    ) {
        db.execSQL(
            "INSERT OR REPLACE INTO messages(client_id, thread_id, sender_id, sent_at, status, expires_at, body) VALUES(?,?,?,?,?,?,?)",
            arrayOf(clientId, threadId, senderId, sentAt, status, expiresAt, body),
        )
    }

    fun expireMessages(now: Long): Int {
        db.execSQL("DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at <= ?", arrayOf(now))
        return 0
    }

    fun enqueueOutbound(id: String, payload: ByteArray, nextAttemptAt: Long = System.currentTimeMillis()) {
        db.execSQL(
            "INSERT OR REPLACE INTO outbound_queue(id, payload, attempts, next_attempt_at) VALUES(?,?,0,?)",
            arrayOf(id, payload, nextAttemptAt),
        )
    }

    /**
     * Destroy local secrets. Call on logout / device revoke / remote wipe.
     * SQLCipher pages stay encrypted; we still delete the file so a later
     * passphrase cannot reopen leftover rows.
     */
    fun wipe() {
        db.execSQL("DELETE FROM kv")
        db.execSQL("DELETE FROM messages")
        db.execSQL("DELETE FROM outbound_queue")
        db.execSQL("DELETE FROM sessions")
        db.close()
        if (file.exists()) {
            file.writeBytes(ByteArray(file.length().toInt().coerceAtMost(4096)))
            file.delete()
        }
    }

    fun close() = db.close()
}
