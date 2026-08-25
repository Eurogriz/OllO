package app.ollo.messenger

import android.app.Application
import android.os.Build
import android.view.WindowManager
import dagger.hilt.android.HiltAndroidApp

@HiltAndroidApp
class OlloApp : Application() {
    override fun onCreate() {
        super.onCreate()
        // Recents thumbnail is hidden per-activity via FLAG_SECURE.
        if (Build.VERSION.SDK_INT >= 33) {
            // Notification runtime permission requested in UI when needed.
        }
    }
}
