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

    override fun onCreate() {
        super.onCreate()
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL, "Gateway session", NotificationManager.IMPORTANCE_LOW)
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_PAUSE) {
            stopSelf()
            return START_NOT_STICKY
        }
        val url = intent?.getStringExtra(EXTRA_URL)
        val token = intent?.getStringExtra(EXTRA_TOKEN)
        if (url == null || token.isNullOrBlank() || !url.startsWith("wss://")) {
            GatewayStatus.value = "Set a WSS endpoint and test token"
            stopSelf()
            return START_NOT_STICKY
        }
        val notification = notification("Connecting")
        if (Build.VERSION.SDK_INT >= 29) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
        socket?.close(1000, "replaced")
        heartbeat?.cancel(false)
        val request = Request.Builder().url(url).header("Authorization", "Bearer $token").build()
        socket = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                GatewayStatus.value = "Connected for heartbeat test"
                getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, notification("Connected"))
                heartbeat = scheduler.scheduleAtFixedRate({
                    webSocket.send("{\"v\":1,\"type\":\"heartbeat\"}")
                }, 0, 30, TimeUnit.SECONDS)
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                if (text == "{\"v\":1,\"type\":\"heartbeat_ack\"}") {
                    GatewayStatus.heartbeats += 1
                }
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                heartbeat?.cancel(false)
                GatewayStatus.value = "Disconnected ($code)"
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                heartbeat?.cancel(false)
                GatewayStatus.value = "Connection failed; reopen gateway mode"
            }
        })
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        heartbeat?.cancel(false)
        socket?.close(1000, "paused")
        client.dispatcher.executorService.shutdown()
        scheduler.shutdownNow()
        GatewayStatus.value = "Paused"
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
        const val ACTION_PAUSE = "org.zrotext.gateway.PAUSE"
        const val EXTRA_URL = "url"
        const val EXTRA_TOKEN = "token"
        private const val CHANNEL = "gateway"
        private const val NOTIFICATION_ID = 1001
    }
}
