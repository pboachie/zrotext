// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

/** M0 transport probe. No message grant, SMS call, or persistent credential exists. */
class GatewayService : Service() {
    private val scheduler = Executors.newSingleThreadScheduledExecutor()
    private val client = OkHttpClient.Builder()
        .pingInterval(30, TimeUnit.SECONDS)
        .build()
    private var socket: WebSocket? = null
    private var heartbeat: ScheduledFuture<*>? = null
    private var refusedStart = false
    @Volatile private var generation = 0

    override fun onCreate() {
        super.onCreate()
        processActive = true
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL, "Gateway session", NotificationManager.IMPORTANCE_LOW)
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        generation += 1
        val currentGeneration = generation
        if (intent?.action == ACTION_PAUSE) {
            refusedStart = false
            stopSelf()
            return START_NOT_STICKY
        }
        // A startForegroundService launch must be promoted even when its extras
        // are invalid. Android otherwise terminates the entire app process.
        val checking = notification("Checking gateway settings")
        if (Build.VERSION.SDK_INT >= 29) {
            startForeground(NOTIFICATION_ID, checking, ServiceInfo.FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING)
        } else {
            startForeground(NOTIFICATION_ID, checking)
        }
        val url = intent?.getStringExtra(EXTRA_URL)
        val token = intent?.getStringExtra(EXTRA_TOKEN)
        if (url == null || token.isNullOrBlank() || !GatewayInputValidation.testEndpoint(url)) {
            GatewayStatus.value = "Set a WSS endpoint and test token"
            refusedStart = true
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }
        refusedStart = false
        GatewayStatus.value = "Connecting"
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, notification("Connecting"))
        socket?.close(1000, "replaced")
        heartbeat?.cancel(false)
        val request = Request.Builder().url(url).header("Authorization", "Bearer $token").build()
        socket = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                if (generation != currentGeneration) {
                    webSocket.close(1000, "replaced")
                    return
                }
                GatewayStatus.value = "Connected for heartbeat test"
                getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, notification("Connected"))
                heartbeat = scheduler.scheduleAtFixedRate({
                    if (generation == currentGeneration)
                        webSocket.send("{\"v\":1,\"type\":\"heartbeat\"}")
                }, 0, 30, TimeUnit.SECONDS)
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                if (generation != currentGeneration) return
                if (text == "{\"v\":1,\"type\":\"heartbeat_ack\"}") {
                    GatewayStatus.heartbeats += 1
                }
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                if (generation != currentGeneration) return
                heartbeat?.cancel(false)
                GatewayStatus.value = "Disconnected ($code)"
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                if (generation != currentGeneration) return
                heartbeat?.cancel(false)
                GatewayStatus.value = "Connection failed; reopen gateway mode"
            }
        })
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        processActive = false
        generation += 1
        heartbeat?.cancel(false)
        socket?.close(1000, "paused")
        client.dispatcher.executorService.shutdown()
        scheduler.shutdownNow()
        if (!refusedStart) GatewayStatus.value = "Paused"
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun notification(state: String): Notification {
        val pause = PendingIntent.getService(
            this, 0, Intent(this, GatewayService::class.java).setAction(ACTION_PAUSE),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL)
            .setSmallIcon(android.R.drawable.stat_notify_chat)
            .setContentTitle("ZROtext gateway test")
            .setContentText(state)
            .setOngoing(true)
            .addAction(0, "Pause", pause)
            .build()
    }

    companion object {
        @Volatile internal var processActive = false
        const val ACTION_PAUSE = "org.zrotext.gateway.PAUSE"
        const val EXTRA_URL = "url"
        const val EXTRA_TOKEN = "token"
        private const val CHANNEL = "gateway"
        private const val NOTIFICATION_ID = 1001
    }
}
