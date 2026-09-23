// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.IBinder
import android.os.SystemClock
import android.telephony.SubscriptionManager
import android.util.Base64
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.json.JSONObject
import java.io.IOException
import java.net.URI
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLException
import kotlin.random.Random

object AuthenticatedGatewayStatus {
    var value by mutableStateOf("Paused")
    var heartbeats by mutableIntStateOf(0)
}

/** Authenticated heartbeat and one manually armed, private synthetic-alpha attempt. */
class AuthenticatedGatewayService : Service() {
    private val scheduler = Executors.newSingleThreadScheduledExecutor()
    private val client = OkHttpClient.Builder().pingInterval(30, TimeUnit.SECONDS).build()
    private var socket: WebSocket? = null
    private var heartbeat: ScheduledFuture<*>? = null
    private var watchdog: ScheduledFuture<*>? = null
    private var handshakeDeadline: ScheduledFuture<*>? = null
    private var eventPump: ScheduledFuture<*>? = null
    private var retry: ScheduledFuture<*>? = null
    private val reconnect = DeviceReconnectPolicy { Random.nextDouble() }
    private var endpoint: String? = null
    private var approvedDevice: UUID? = null
    private lateinit var connectivity: ConnectivityManager
    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) = refreshNetwork()
        override fun onLost(network: Network) = refreshNetwork()
        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) = refreshNetwork()
    }
    @Volatile private var generation = 0
    @Volatile private var lastAckAtNanos = 0L
    @Volatile private var awaitingEventId: String? = null
    @Volatile private var activeGrant: AlphaGrantValidator.Grant? = null

    override fun onCreate() {
        super.onCreate()
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL, "Authenticated device heartbeat", NotificationManager.IMPORTANCE_LOW)
        )
        connectivity = getSystemService(ConnectivityManager::class.java)
        connectivity.registerDefaultNetworkCallback(networkCallback)
    }

    @Synchronized
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_PAUSE) {
            halt()
            AuthenticatedGatewayStatus.value = "Paused"
            stopSelf()
            return START_NOT_STICKY
        }
        val url = intent?.getStringExtra(EXTRA_URL).orEmpty()
        val deviceId = try {
            val value = intent?.getStringExtra(EXTRA_DEVICE_ID).orEmpty()
            UUID.fromString(value).takeIf { it.toString() == value }
        } catch (_: IllegalArgumentException) {
            null
        }
        if (!validUrl(url) || deviceId == null) {
            halt()
            AuthenticatedGatewayStatus.value = "Set a WSS device stream and approved device ID"
            stopSelf()
            return START_NOT_STICKY
        }
        val armRequested = intent?.hasExtra(EXTRA_ALPHA_RECIPIENT) == true
        val armStartedAtNanos = System.nanoTime()
        val armRecipient = intent?.getStringExtra(EXTRA_ALPHA_RECIPIENT).orEmpty()
        val armSubscriptionId = intent?.getIntExtra(
            EXTRA_ALPHA_SUBSCRIPTION_ID, SubscriptionManager.INVALID_SUBSCRIPTION_ID
        ) ?: SubscriptionManager.INVALID_SUBSCRIPTION_ID
        if (armRequested) {
            val selected = getSharedPreferences("gateway_selection", MODE_PRIVATE)
                .getInt("subscription_id", SubscriptionManager.INVALID_SUBSCRIPTION_ID)
            val active = activeSubscriptionIds()
            if (!armRecipient.matches(Regex("^\\+[1-9][0-9]{1,14}$")) ||
                selected != armSubscriptionId ||
                !SimSelection.isActive(armSubscriptionId, active) ||
                getSharedPreferences("alpha_pilot", MODE_PRIVATE).getBoolean("attempt_used", false)) {
                halt()
                AuthenticatedGatewayStatus.value = "Alpha arm refused: check recipient, SIM and unused test attempt"
                stopSelf()
                return START_NOT_STICKY
            }
        }
        val notification = notification("Connecting")
        if (Build.VERSION.SDK_INT >= 29) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
        endpoint = url
        approvedDevice = deviceId
        retry?.cancel(false)
        when (reconnect.start(hasNetwork())) {
            DeviceReconnectPolicy.Action.Connect -> openConnection(
                url, deviceId, armRequested, armRecipient, armSubscriptionId, armStartedAtNanos)
            DeviceReconnectPolicy.Action.WaitForNetwork ->
                AuthenticatedGatewayStatus.value = "Waiting for network"
            else -> error("Unexpected reconnect start")
        }
        return START_NOT_STICKY
    }

    @Synchronized
    private fun openConnection(
        url: String, deviceId: UUID, armRequested: Boolean = false,
        armRecipient: String = "", armSubscriptionId: Int = SubscriptionManager.INVALID_SUBSCRIPTION_ID,
        armStartedAtNanos: Long = 0L
    ) {
        generation += 1
        val currentGeneration = generation
        cancelTimers()
        socket?.cancel()
        socket = null
        retry?.cancel(false)
        awaitingEventId = null
        activeGrant = null
        val keys = DeviceSigningKeyStore(applicationContext)
        val machine = DeviceStreamMachine(deviceId) { account, device, challenge, nonce ->
            keys.signDeviceChallenge(account, device, challenge, nonce)
        }
        var grantSeen = false
        socket = client.newWebSocket(Request.Builder().url(url).build(), object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                if (generation != currentGeneration) return
                val hello = JSONObject().put("v", 1).put("type", "hello")
                    .put("device_id", machine.helloDeviceId().toString())
                if (!webSocket.send(hello.toString()))
                    return disconnect(currentGeneration, DeviceReconnectPolicy.Loss.TRANSPORT)
                AuthenticatedGatewayStatus.value = "Waiting for device challenge"
                deadline(webSocket, currentGeneration)
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                if (generation != currentGeneration) return
                try {
                    check(text.toByteArray(Charsets.UTF_8).size <= MAX_FRAME_BYTES)
                    val frame = JSONObject(text)
                    check(frame.opt("v") is Number && frame.getInt("v") == 1)
                    check(frame.opt("type") is String)
                    when (frame.getString("type")) {
                        "challenge" -> {
                            requireFields(frame, setOf("v", "type", "challenge_id", "account_id", "device_id", "nonce"))
                            val proof = machine.challenge(
                                uuid(frame, "challenge_id"), uuid(frame, "account_id"),
                                uuid(frame, "device_id"), decodeNonce(frame.getString("nonce"))
                            )
                            handshakeDeadline?.cancel(false)
                            val reply = JSONObject().put("v", 1).put("type", "proof")
                                .put("challenge_id", proof.challengeId.toString())
                                .put("account_id", proof.accountId.toString())
                                .put("device_id", proof.deviceId.toString())
                                .put("nonce", encode(proof.nonce))
                                .put("signature_der", encode(proof.signatureDer))
                            if (!webSocket.send(reply.toString()))
                                return disconnect(currentGeneration, DeviceReconnectPolicy.Loss.TRANSPORT)
                            AuthenticatedGatewayStatus.value = "Proving enrolled device key"
                            deadline(webSocket, currentGeneration)
                        }
                        "session" -> {
                            requireFields(frame, setOf("v", "type", "connection_epoch", "heartbeat_seconds"))
                            check(frame.opt("connection_epoch") is Number && frame.opt("heartbeat_seconds") is Number)
                            val epoch = frame.getLong("connection_epoch")
                            val seconds = frame.getInt("heartbeat_seconds")
                            machine.session(epoch, seconds)
                            synchronized(this@AuthenticatedGatewayService) {
                                if (generation != currentGeneration) return
                                reconnect.authenticated(SystemClock.elapsedRealtime())
                            }
                            handshakeDeadline?.cancel(false)
                            if (armRequested) {
                                val digest = encode(MessageDigest.getInstance("SHA-256")
                                    .digest(armRecipient.toByteArray(Charsets.UTF_8)))
                                val ready = JSONObject().put("v", 1).put("type", "alpha_ready")
                                    .put("connection_epoch", epoch).put("recipient_digest", digest)
                                if (!webSocket.send(ready.toString()))
                                    return disconnect(currentGeneration, DeviceReconnectPolicy.Loss.TRANSPORT)
                            }
                            AuthenticatedGatewayStatus.value =
                                if (armRequested) "Armed for one synthetic grant" else "Authenticated heartbeat only"
                            AuthenticatedGatewayStatus.heartbeats = 0
                            getSystemService(NotificationManager::class.java)
                                .notify(NOTIFICATION_ID, notification(
                                    if (armRequested) "Armed one-send alpha test" else "Authenticated heartbeat"))
                            lastAckAtNanos = System.nanoTime()
                            heartbeat = scheduler.scheduleAtFixedRate({
                                if (generation == currentGeneration) {
                                    try {
                                        machine.heartbeatEpoch()
                                        if (!webSocket.send("{\"v\":1,\"type\":\"heartbeat\"}")) {
                                            disconnect(currentGeneration, DeviceReconnectPolicy.Loss.TRANSPORT)
                                        }
                                    } catch (_: IllegalStateException) {
                                        fail(webSocket, currentGeneration)
                                    }
                                }
                            }, 0, seconds.toLong(), TimeUnit.SECONDS)
                            watchdog = scheduler.scheduleAtFixedRate({
                                if (generation == currentGeneration &&
                                    System.nanoTime() - lastAckAtNanos > TimeUnit.SECONDS.toNanos(90)) {
                                    disconnect(currentGeneration, DeviceReconnectPolicy.Loss.TRANSPORT)
                                }
                            }, 15, 15, TimeUnit.SECONDS)
                            eventPump = scheduler.scheduleAtFixedRate({
                                if (generation == currentGeneration) {
                                    pumpAlphaEvents(webSocket, machine, currentGeneration)
                                }
                            }, 0, 3, TimeUnit.SECONDS)
                        }
                        "heartbeat_ack" -> {
                            requireFields(frame, setOf("v", "type", "connection_epoch"))
                            check(frame.opt("connection_epoch") is Number)
                            AuthenticatedGatewayStatus.heartbeats = machine.heartbeatAck(frame.getLong("connection_epoch"))
                            lastAckAtNanos = System.nanoTime()
                        }
                        "synthetic_grant" -> {
                            check(armRequested && !grantSeen && machine.phase == DeviceStreamMachine.Phase.ACTIVE)
                            check(System.nanoTime() - armStartedAtNanos <= TimeUnit.MINUTES.toNanos(5))
                            check(!getSharedPreferences("alpha_pilot", MODE_PRIVATE)
                                .getBoolean("attempt_used", false))
                            check(getSharedPreferences("gateway_selection", MODE_PRIVATE)
                                .getInt("subscription_id", SubscriptionManager.INVALID_SUBSCRIPTION_ID)
                                == armSubscriptionId)
                            val active = activeSubscriptionIds()
                            val grant = AlphaGrantValidator.validate(frame, deviceId, machine.heartbeatEpoch(),
                                armRecipient, armSubscriptionId, active, System.currentTimeMillis())
                            check(getSharedPreferences("alpha_pilot", MODE_PRIVATE).edit()
                                .putBoolean("attempt_used", true).commit())
                            grantSeen = true
                            activeGrant = grant
                            JournalRuntime.io.execute {
                                try {
                                    if (generation != currentGeneration) return@execute
                                    SmsJournalDatabase.get(applicationContext).attempts().reserveAlpha(
                                        grant.attemptId.toString(), grant.messageId.toString(),
                                        grant.subscriptionId, 1, UUID.randomUUID().toString(),
                                        System.currentTimeMillis())
                                    AuthenticatedGatewayStatus.value = "Grant reserved; waiting for writer ack"
                                    pumpAlphaEvents(webSocket, machine, currentGeneration)
                                } catch (_: Exception) {
                                    fail(webSocket, currentGeneration)
                                }
                            }
                        }
                        "radio_event_ack" -> {
                            requireFields(frame, setOf("v", "type", "event_id", "state", "submit_permitted"))
                            check(frame.opt("state") is String && frame.opt("submit_permitted") is Boolean)
                            handleAlphaAck(webSocket, machine, currentGeneration,
                                uuid(frame, "event_id").toString(), frame.getString("state"),
                                frame.getBoolean("submit_permitted"))
                        }
                        else -> error("Unexpected device frame")
                    }
                } catch (_: Exception) {
                    fail(webSocket, currentGeneration)
                }
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                val authenticated = machine.phase == DeviceStreamMachine.Phase.ACTIVE
                machine.close()
                disconnect(currentGeneration, if (authenticated && code in listOf(1000, 1001, 1012, 1013))
                    DeviceReconnectPolicy.Loss.ACTIVE_CLOSE else DeviceReconnectPolicy.Loss.AUTH_REJECTED)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                machine.close()
                val trustedTransport = generateSequence(t as Throwable?) { it.cause }
                    .none { it is SSLException || it is java.security.cert.CertificateException }
                val transport = t is IOException && trustedTransport &&
                    (response == null || response.code >= 500)
                disconnect(currentGeneration, if (transport) DeviceReconnectPolicy.Loss.TRANSPORT
                    else DeviceReconnectPolicy.Loss.AUTH_REJECTED)
            }
        })
    }

    private fun pumpAlphaEvents(webSocket: WebSocket, machine: DeviceStreamMachine, currentGeneration: Int) {
        JournalRuntime.io.execute {
            if (generation != currentGeneration) return@execute
            try {
                val epoch = machine.heartbeatEpoch()
                val event = SmsJournalDatabase.get(applicationContext).attempts().nextAlphaEvent()
                    ?: return@execute
                if (awaitingEventId != null && awaitingEventId != event.eventId) return@execute
                val frame = JSONObject().put("v", 1).put("type", "radio_event")
                    .put("connection_epoch", epoch).put("event_id", event.eventId)
                    .put("message_id", event.messageId).put("attempt_id", event.attemptId)
                    .put("evidence", event.evidence).put("observed_at_ms", event.observedAtMs)
                if (event.segmentIndex != null && event.segmentCount != null) {
                    frame.put("segment_index", event.segmentIndex)
                        .put("segment_count", event.segmentCount)
                }
                awaitingEventId = event.eventId
                if (!webSocket.send(frame.toString()))
                    disconnect(currentGeneration, DeviceReconnectPolicy.Loss.TRANSPORT)
            } catch (_: Exception) {
                fail(webSocket, currentGeneration)
            }
        }
    }

    private fun handleAlphaAck(
        webSocket: WebSocket, machine: DeviceStreamMachine, currentGeneration: Int,
        eventId: String, state: String, permitted: Boolean
    ) {
        JournalRuntime.io.execute {
            if (generation != currentGeneration) return@execute
            try {
                val dao = SmsJournalDatabase.get(applicationContext).attempts()
                val event = dao.getAlphaEvent(eventId) ?: error("Unknown alpha event")
                if (awaitingEventId != eventId) {
                    check(event.acknowledgedAtMs != null)
                    return@execute // A duplicate ack cannot repeat a radio call.
                }
                check(event.acknowledgedAtMs == null)
                if (event.evidence == "durable_submit_intent") {
                    check(!permitted || state == "submitting")
                    val grant = activeGrant
                    val matching = grant != null && grant.attemptId.toString() == event.attemptId &&
                        grant.messageId.toString() == event.messageId &&
                        grant.connectionEpoch == machine.heartbeatEpoch() &&
                        generation == currentGeneration && System.currentTimeMillis() < grant.expiresAtMs &&
                        getSharedPreferences("gateway_selection", MODE_PRIVATE)
                            .getInt("subscription_id", SubscriptionManager.INVALID_SUBSCRIPTION_ID) == grant.subscriptionId
                    val authorized = dao.acknowledgeAlphaIntent(eventId, permitted && matching,
                        System.currentTimeMillis())
                    awaitingEventId = null
                    if (authorized && grant != null) {
                        AuthenticatedGatewayStatus.value = "Writer authorized one radio attempt"
                        SmsAttemptAdapter.sendAuthorized(applicationContext, grant,
                            { generation == currentGeneration &&
                                runCatching { machine.heartbeatEpoch() }.isSuccess }) { result ->
                            if (generation == currentGeneration) {
                                AuthenticatedGatewayStatus.value = when (result) {
                                    SmsAttemptAdapter.StartResult.CALL_RETURNED ->
                                        "Radio call returned; waiting for sent callback"
                                    SmsAttemptAdapter.StartResult.UNKNOWN ->
                                        "Radio outcome unknown; no retry"
                                    else -> "Radio not called; no retry"
                                }
                            }
                        }
                    }
                } else {
                    check(!permitted)
                    check(dao.acknowledgeAlphaEvent(eventId, System.currentTimeMillis()) == 1)
                    awaitingEventId = null
                }
            } catch (_: Exception) {
                fail(webSocket, currentGeneration)
            }
        }
    }

    private fun deadline(webSocket: WebSocket, currentGeneration: Int) {
        handshakeDeadline?.cancel(false)
        handshakeDeadline = scheduler.schedule({
            disconnect(currentGeneration, DeviceReconnectPolicy.Loss.TRANSPORT)
        }, 10, TimeUnit.SECONDS)
    }

    private fun fail(webSocket: WebSocket, currentGeneration: Int) {
        disconnect(currentGeneration, DeviceReconnectPolicy.Loss.PROTOCOL_REJECTED)
    }

    @Synchronized
    private fun disconnect(currentGeneration: Int, reason: DeviceReconnectPolicy.Loss) {
        if (generation != currentGeneration) return
        generation += 1 // Fence queued callbacks, grants and radio authorization before any retry.
        cancelTimers()
        socket?.cancel()
        socket = null
        activeGrant = null
        awaitingEventId = null
        when (val action = reconnect.lost(reason, SystemClock.elapsedRealtime())) {
            is DeviceReconnectPolicy.Action.RetryAfter -> {
                AuthenticatedGatewayStatus.value = "Disconnected; retrying device proof"
                getSystemService(NotificationManager::class.java)
                    .notify(NOTIFICATION_ID, notification("Reconnecting after transport loss"))
                retry?.cancel(false)
                retry = scheduler.schedule({
                    synchronized(this) {
                        if (reconnect.retryDue() == DeviceReconnectPolicy.Action.Connect) {
                            val url = endpoint
                            val device = approvedDevice
                            if (url != null && device != null) openConnection(url, device)
                        }
                    }
                }, action.milliseconds, TimeUnit.MILLISECONDS)
            }
            DeviceReconnectPolicy.Action.WaitForNetwork -> {
                AuthenticatedGatewayStatus.value = "Disconnected; waiting for network"
                getSystemService(NotificationManager::class.java)
                    .notify(NOTIFICATION_ID, notification("Waiting for network"))
            }
            DeviceReconnectPolicy.Action.Stop -> {
                AuthenticatedGatewayStatus.value = "Device proof or protocol rejected; restart manually"
                stopSelf()
            }
            else -> Unit
        }
    }

    private fun hasNetwork(): Boolean {
        val active = connectivity.activeNetwork ?: return false
        return connectivity.getNetworkCapabilities(active)
            ?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true
    }

    private fun refreshNetwork() {
        synchronized(this) {
            if (endpoint == null || approvedDevice == null) return
            when (reconnect.networkChanged(hasNetwork())) {
                DeviceReconnectPolicy.Action.WaitForNetwork -> {
                    generation += 1
                    cancelTimers()
                    retry?.cancel(false)
                    socket?.cancel()
                    socket = null
                    activeGrant = null
                    awaitingEventId = null
                    AuthenticatedGatewayStatus.value = "Disconnected; waiting for network"
                    getSystemService(NotificationManager::class.java)
                        .notify(NOTIFICATION_ID, notification("Waiting for network"))
                }
                DeviceReconnectPolicy.Action.Connect -> {
                    retry?.cancel(false)
                    openConnection(checkNotNull(endpoint), checkNotNull(approvedDevice))
                }
                else -> Unit
            }
        }
    }

    private fun halt() {
        reconnect.pause()
        generation += 1
        cancelTimers()
        retry?.cancel(false)
        socket?.cancel()
        socket = null
        activeGrant = null
        awaitingEventId = null
    }

    private fun cancelTimers() {
        heartbeat?.cancel(false)
        watchdog?.cancel(false)
        handshakeDeadline?.cancel(false)
        eventPump?.cancel(false)
    }

    @Synchronized
    override fun onDestroy() {
        halt()
        connectivity.unregisterNetworkCallback(networkCallback)
        client.dispatcher.executorService.shutdown()
        scheduler.shutdownNow()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun notification(state: String): Notification {
        val pause = PendingIntent.getService(
            this, 0, Intent(this, AuthenticatedGatewayService::class.java).setAction(ACTION_PAUSE),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL)
            .setSmallIcon(android.R.drawable.stat_notify_chat)
            .setContentTitle("ZROtext device test")
            .setContentText(state)
            .setOngoing(true)
            .addAction(0, "Pause", pause)
            .build()
    }

    private fun validUrl(value: String): Boolean = try {
        val url = URI(value)
        url.scheme == "wss" && !url.host.isNullOrBlank() &&
            url.rawPath == "/v1/device-stream" && url.rawQuery == null &&
            url.rawFragment == null && url.rawUserInfo == null
    } catch (_: Exception) {
        false
    }

    private fun activeSubscriptionIds(): List<Int> {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_PHONE_STATE) !=
            PackageManager.PERMISSION_GRANTED) return emptyList()
        return try {
            getSystemService(SubscriptionManager::class.java).activeSubscriptionInfoList
                .orEmpty().map { it.subscriptionId }
        } catch (_: RuntimeException) { emptyList() }
    }

    private fun requireFields(frame: JSONObject, expected: Set<String>) {
        check(frame.keys().asSequence().toSet() == expected)
    }

    private fun uuid(frame: JSONObject, key: String): UUID {
        val value = frame.getString(key)
        check(value.length == 36)
        return UUID.fromString(value).also { check(it.toString() == value) }
    }

    private fun decodeNonce(value: String): ByteArray {
        check(value.matches(Regex("[A-Za-z0-9_-]{43}")))
        val decoded = Base64.decode(value, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        check(decoded.size == 32 && encode(decoded) == value)
        return decoded
    }

    private fun encode(value: ByteArray): String =
        Base64.encodeToString(value, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    companion object {
        const val ACTION_PAUSE = "org.zrotext.gateway.AUTH_PAUSE"
        const val EXTRA_URL = "url"
        const val EXTRA_DEVICE_ID = "device_id"
        const val EXTRA_ALPHA_RECIPIENT = "alpha_recipient"
        const val EXTRA_ALPHA_SUBSCRIPTION_ID = "alpha_subscription_id"
        private const val CHANNEL = "authenticated_gateway"
        private const val NOTIFICATION_ID = 1002
        private const val MAX_FRAME_BYTES = 4096
    }
}
