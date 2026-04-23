package com.therealaleph.mhrv

import android.app.Application
import android.util.Log

/**
 * Application-level setup. The only job here right now is to catch
 * uncaught JVM exceptions and route them through logcat under the
 * `mhrv-crash` tag BEFORE the process dies. Without this the crashes
 * appear as opaque "App closed unexpectedly" with no line number in
 * `adb logcat` — we re-raise the exception afterwards so the default
 * handler still prints its stack trace and Android still shows the
 * dialog, but at least the chain-of-events is searchable.
 *
 * Registering the handler in `Application.onCreate()` (rather than
 * `Activity.onCreate()`) catches crashes on ALL process threads,
 * including the tun2proxy worker and the log-drain coroutine —
 * important because those don't have an activity in scope.
 */
class MhrvApp : Application() {
    override fun onCreate() {
        super.onCreate()
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            Log.e(
                CRASH_TAG,
                "uncaught on thread=${thread.name} (id=${thread.id}): ${throwable.message}",
                throwable,
            )
            // Let the default handler still terminate the process and
            // show the system "app closed" dialog — we just wanted to
            // get a log line out the door first.
            previous?.uncaughtException(thread, throwable)
        }
    }

    companion object {
        private const val CRASH_TAG = "mhrv-crash"
    }
}
