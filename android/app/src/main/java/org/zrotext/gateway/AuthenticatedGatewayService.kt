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
import android.util.Log
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
import okio.ByteString
import org.json.JSONObject
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import kotlin.random.Random

object AuthenticatedGatewayStatus {
    var value by mutableStateOf("Paused")
    var heartbeats by mutableIntStateOf(0)
    var authenticatedSessions by mutableIntStateOf(0)
}

/** Authenticated heartbeat and one manually armed, private synthetic-alpha attempt. */
class AuthenticatedGatewayService : Service() {
    private val scheduler = Executors.newSingleThreadScheduledExecutor()
    private val client = streamClient()
    private var socket: WebSocket? = null
    private var heartbeat: ScheduledFuture<*>? = null
    private var watchdog: ScheduledFuture<*>? = null
    private var handshakeDeadline: ScheduledFuture<*>? = null
    private var eventPump: ScheduledFuture<*>? = null
    private var grantExpiry: ScheduledFuture<*>? = null
    private var resend: ScheduledFuture<*>? = null
    private var retry: ScheduledFuture<*>? = null
    private val alphaPump = AlphaPumpGate()
    private val reconnect = DeviceReconnectPolicy { Random.nextDouble() }
    private val timingTrace = HeartbeatTimingTrace()
    private val networkServiceSampler by lazy { NetworkServiceSampler(applicationContext) }
    private val traceEpoch = AtomicLong(-1L)
    private var endpoint: String? = null
    private var approvedDevice: UUID? = null
    private var observedNetwork: Network? = null
    private lateinit var connectivity: ConnectivityManager
    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) = refreshNetwork()
        override fun onLost(network: Network) = refreshNetwork()
        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) = refreshNetwork()
    }
    @Volatile private var generation = 0
    @Volatile private var lastAckAtNanos = 0L
    /** Computed once per authenticated session; the inputs cannot change within it. */
    @Volatile private var sessionIdentity: EvidenceIdentity? = null
    @Volatile private var conversationConnection: ConversationSocketNegotiation? = null
    @Volatile private var sealedConnection: SealedExecutionConnection? = null
    private var conversationHost: AutoCloseable? = null
    @Volatile private var awaitingEventId: String? = null
    @Volatile private var awaitingEventSentAtNanos = 0L
    @Volatile private var awaitingInboundId: String? = null
    @Volatile private var inboundSentAtNanos = 0L
    @Volatile private var awaitingLineOptOutId: String? = null
    @Volatile private var lineOptOutSentAtNanos = 0L
    @Volatile private var lineOptOutPaused = false
    @Volatile private var quarantinedEvidenceNotice = false
    @Volatile private var activeGrant: AlphaGrantValidator.Grant? = null
    /** In memory only: a restarted app cannot install an activation it did not just prove. */
    @Volatile private var smsLineActivation: PreparedSmsLineActivation? = null
    /** The hub repeats sms_line_activated on later connections; this one is already installed. */
    @Volatile private var installedSmsLineChallenge: UUID? = null
    /** Provenance of the accepted cached activation, never inferred from current SIM selection. */
    @Volatile private var installedSmsLineIsEsim = false
    /** Optional, explicitly accepted SEALED line setup. No content worker or body consent. */
    @Volatile private var sealedLineActivation: SealedLineActivationProvider? = null

    override fun onCreate() {
        super.onCreate()
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL, "Authenticated device heartbeat", NotificationManager.IMPORTANCE_LOW)
        )
        connectivity = getSystemService(ConnectivityManager::class.java)
        connectivity.registerDefaultNetworkCallback(networkCallback)
        processActive = true
    }

    @Synchronized
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_PAUSE) {
            SealedLineActivationMount.disable()
            SimProfileContinuity.stop()
            ConversationProcessMount.runtime.pause(ConversationStopReason.USER_STOP)
            val rebootResumeCleared = HeartbeatResumeStore.clear(this)
            halt()
            if (rebootResumeCleared) {
                AuthenticatedGatewayStatus.value = "Paused"
                stopSelf()
            } else {
                AuthenticatedGatewayStatus.value = "Pause incomplete; tap Pause again before reboot"
                val warning = notification("Pause incomplete; tap Pause again")
                if (Build.VERSION.SDK_INT >= 29) {
                    startForeground(NOTIFICATION_ID, warning,
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING)
                } else {
                    startForeground(NOTIFICATION_ID, warning)
                }
            }
            return START_NOT_STICKY
        }
        // Every non-Pause request can arrive through startForegroundService,
        // including a boot request whose saved configuration has disappeared.
        // Promote before any validation path can stop the service.
        val checking = notification("Checking heartbeat configuration")
        if (Build.VERSION.SDK_INT >= 29) {
            startForeground(NOTIFICATION_ID, checking,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING)
        } else {
            startForeground(NOTIFICATION_ID, checking)
        }
        val bootResume = intent?.action == ACTION_BOOT_RESUME
        if (!bootResume && !HeartbeatResumeStore.clear(this)) {
            halt()
            AuthenticatedGatewayStatus.value = "Could not disable previous reboot resume; retry"
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }
        val saved = if (bootResume) HeartbeatResumeStore.read(this) else null
        val url = if (bootResume) saved?.url.orEmpty() else intent?.getStringExtra(EXTRA_URL).orEmpty()
        val deviceId = GatewayInputValidation.deviceId(if (bootResume) saved?.deviceId.toString()
            else intent?.getStringExtra(EXTRA_DEVICE_ID).orEmpty())
        if (!validUrl(url) || deviceId == null) {
            val rebootResumeCleared = HeartbeatResumeStore.clear(this)
            halt()
            AuthenticatedGatewayStatus.value = if (rebootResumeCleared)
                "Set a WSS device stream and approved device ID"
            else "Invalid heartbeat configuration; could not disable reboot resume. Retry Pause"
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }
        val armRequested = !bootResume && intent?.hasExtra(EXTRA_ALPHA_RECIPIENT) == true
        val inboundUploadRequested = !bootResume &&
            intent?.getBooleanExtra(EXTRA_INBOUND_UPLOAD, false) == true
        val lineOptOutUploadRequested = !bootResume &&
            intent?.getBooleanExtra(EXTRA_LINE_OPT_OUT_UPLOAD, false) == true
        val rebootOptInRequested = !bootResume &&
            intent?.getBooleanExtra(EXTRA_REBOOT_RESUME, false) == true
        if ((if (armRequested) 1 else 0) + (if (inboundUploadRequested) 1 else 0) +
            (if (lineOptOutUploadRequested) 1 else 0) > 1 ||
            (rebootOptInRequested && (armRequested || inboundUploadRequested ||
                lineOptOutUploadRequested))) {
            halt()
            AuthenticatedGatewayStatus.value = "Choose one pilot mode at a time"
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }
        timingTrace.start(intent?.getBooleanExtra(EXTRA_HEARTBEAT_TIMING_TRACE, false) == true)
        val armStartedAtNanos = System.nanoTime()
        val armRecipient = intent?.getStringExtra(EXTRA_ALPHA_RECIPIENT).orEmpty()
        val armSubscriptionId = intent?.getIntExtra(
            EXTRA_ALPHA_SUBSCRIPTION_ID, SubscriptionManager.INVALID_SUBSCRIPTION_ID
        ) ?: SubscriptionManager.INVALID_SUBSCRIPTION_ID
        if (armRequested) {
            if (getSharedPreferences("alpha_pilot", MODE_PRIVATE).getBoolean("attempt_used", false)) {
                halt()
                AuthenticatedGatewayStatus.value = "Alpha arm refused: one test attempt already used"
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return START_NOT_STICKY
            }
            val selected = getSharedPreferences("gateway_selection", MODE_PRIVATE)
                .getInt("subscription_id", SubscriptionManager.INVALID_SUBSCRIPTION_ID)
            val active = activeSubscriptionIds()
            if (!armRecipient.matches(Regex("^\\+[1-9][0-9]{1,14}$")) ||
                selected != armSubscriptionId ||
                !SimSelection.isActive(armSubscriptionId, active)) {
                halt()
                AuthenticatedGatewayStatus.value = "Alpha arm refused: check recipient, SIM and unused test attempt"
                stopForeground(STOP_FOREGROUND_REMOVE)
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
        if (!bootResume) {
            if (rebootOptInRequested) {
                if (!HeartbeatResumeStore.save(this, HeartbeatResumeStore.Config(url, deviceId)))
                    AuthenticatedGatewayStatus.value = "Heartbeat running; reboot resume unavailable"
            }
        }
        endpoint = url
        approvedDevice = deviceId
        observedNetwork = connectivity.activeNetwork
        retry?.cancel(false)
        val pilotMode = when {
            armRequested -> DeviceReconnectPolicy.PilotMode.ALPHA_ONCE
            inboundUploadRequested -> DeviceReconnectPolicy.PilotMode.INBOUND_UPLOAD
            lineOptOutUploadRequested -> DeviceReconnectPolicy.PilotMode.LINE_OPT_OUT_UPLOAD
            else -> DeviceReconnectPolicy.PilotMode.HEARTBEAT_ONLY
        }
        when (val action = reconnect.start(hasNetwork(observedNetwork), pilotMode)) {
            is DeviceReconnectPolicy.Action.Connect -> openConnection(
                url, deviceId, action.pilotMode == DeviceReconnectPolicy.PilotMode.ALPHA_ONCE,
                armRecipient, armSubscriptionId, armStartedAtNanos,
                action.pilotMode == DeviceReconnectPolicy.PilotMode.INBOUND_UPLOAD,
                action.pilotMode == DeviceReconnectPolicy.PilotMode.LINE_OPT_OUT_UPLOAD)
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
        armStartedAtNanos: Long = 0L, inboundUploadRequested: Boolean = false,
        lineOptOutUploadRequested: Boolean = false
    ) {
        generation += 1
        val currentGeneration = generation
        traceEpoch.set(-1L)
        cancelTimers()
        socket?.cancel()
        socket = null
        retry?.cancel(false)
        alphaPump.onConnectionReset()
        closeConversationConnection()
        sessionIdentity = null
        awaitingEventId = null
        awaitingEventSentAtNanos = 0L
        awaitingInboundId = null
        inboundSentAtNanos = 0L
        awaitingLineOptOutId = null
        lineOptOutSentAtNanos = 0L
        lineOptOutPaused = false
        activeGrant = null
        val keys = DeviceSigningKeyStore(applicationContext)
        val machine = DeviceStreamMachine(deviceId) { account, device, challenge, nonce ->
            keys.signDeviceChallenge(account, device, challenge, nonce)
        }
        var grantSeen = false
        val statusPublisher = DeviceStatusPublisher()
        val sealedLease = SealedExecutionMount.capture()
        var sealedSelected = false
        val offered = if (sealedLease != null) SealedSocketTime.PROTOCOL + ", " + DeviceStatusPublisher.OFFER
            else DeviceStatusPublisher.OFFER
        socket = client.newWebSocket(Request.Builder().url(url)
            .header("Sec-WebSocket-Protocol", offered).build(), object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                if (generation != currentGeneration) return
                val selected = response.header("Sec-WebSocket-Protocol")
                sealedSelected = sealedLease != null && selected == SealedSocketTime.PROTOCOL
                statusPublisher.selectProtocol(if (sealedSelected) "zrotext-device-status-v2" else selected)
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
                        "conversation_session" -> checkNotNull(conversationConnection).accept(frame)
                        "sealed_session" -> checkNotNull(sealedConnection).accept(frame)
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
                                traceEpoch.set(epoch)
                                timingTrace.mark(HeartbeatTraceEvent.SESSION, epoch)
                                reconnect.authenticated(SystemClock.elapsedRealtime())
                            }
                            handshakeDeadline?.cancel(false)
                            if (sealedSelected) {
                                val connection = SealedExecutionConnection(checkNotNull(sealedLease),
                                    machine.activeAccountId(), deviceId, epoch, url, client, webSocket, keys) {
                                    generation == currentGeneration && machine.phase == DeviceStreamMachine.Phase.ACTIVE &&
                                        runCatching { machine.heartbeatEpoch() == epoch }.getOrDefault(false)
                                }
                                sealedConnection = connection
                                if (!connection.start()) return disconnect(currentGeneration, DeviceReconnectPolicy.Loss.TRANSPORT)
                            }
                            if (armRequested) {
                                val digest = encode(MessageDigest.getInstance("SHA-256")
                                    .digest(armRecipient.toByteArray(Charsets.UTF_8)))
                                val ready = JSONObject().put("v", 1).put("type", "alpha_ready")
                                    .put("connection_epoch", epoch).put("recipient_digest", digest)
                                if (!webSocket.send(ready.toString()))
                                    return disconnect(currentGeneration, DeviceReconnectPolicy.Loss.TRANSPORT)
                            }
                            AuthenticatedGatewayStatus.value =
                                (when {
                                    armRequested -> "Armed for one synthetic grant"
                                    inboundUploadRequested -> "Inbound metadata pilot active"
                                    lineOptOutUploadRequested -> "Line opt-out upload pilot active"
                                    else -> "Authenticated heartbeat only"
                                }) + if (quarantinedEvidenceNotice)
                                    "; stale evidence quarantined" else ""
                            AuthenticatedGatewayStatus.heartbeats = 0
                            AuthenticatedGatewayStatus.authenticatedSessions += 1
                            getSystemService(NotificationManager::class.java)
                                .notify(NOTIFICATION_ID, notification(
                                    when {
                                        armRequested -> "Armed one-send alpha test"
                                        inboundUploadRequested -> "Inbound metadata pilot"
                                        lineOptOutUploadRequested -> "Line opt-out upload pilot"
                                        else -> "Authenticated heartbeat"
                                    }))
                            lastAckAtNanos = System.nanoTime()
                            heartbeat = scheduler.scheduleAtFixedRate({
                                if (generation == currentGeneration) {
                                    try {
                                        val heartbeatEpoch = machine.heartbeatEpoch()
                                        if (sealedConnection?.tick() == false)
                                            return@scheduleAtFixedRate disconnect(currentGeneration, DeviceReconnectPolicy.Loss.TRANSPORT)
                                        timingTrace.mark(HeartbeatTraceEvent.SEND_CALL, heartbeatEpoch)
                                        val queued = webSocket.send("{\"v\":1,\"type\":\"heartbeat\"}")
                                        timingTrace.mark(if (queued) HeartbeatTraceEvent.SEND_QUEUED
                                            else HeartbeatTraceEvent.SEND_REJECTED, heartbeatEpoch)
                                        if (!queued) {
                                            disconnect(currentGeneration, DeviceReconnectPolicy.Loss.TRANSPORT)
                                        } else {
                                            val version = statusPublisher.nextVersion(heartbeatEpoch, SystemClock.elapsedRealtime())
                                            fun sendStatus(network: NetworkService, activeSubscriptionIds: List<Int>?) {
                                                if (generation != currentGeneration) return
                                                val observed = DevicePreconditions.observe(
                                                    applicationContext, activeSubscriptionIds)
                                                val status = if (version == DeviceStatusPublisher.Version.V2)
                                                    observed.frameV2(heartbeatEpoch, network) else observed.frame(heartbeatEpoch)
                                                if (webSocket.send(status))
                                                    statusPublisher.reportSent(SystemClock.elapsedRealtime())
                                                else disconnect(currentGeneration, DeviceReconnectPolicy.Loss.TRANSPORT)
                                            }
                                            when (version) {
                                                DeviceStatusPublisher.Version.V1 -> networkServiceSampler.lookupOnly {
                                                    active -> sendStatus(NetworkService.UNAVAILABLE, active)
                                                }
                                                DeviceStatusPublisher.Version.V2 -> networkServiceSampler.sample(
                                                    { generation == currentGeneration }, ::sendStatus)
                                                null -> Unit
                                            }
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
                            synchronized(this@AuthenticatedGatewayService) {
                                if (generation != currentGeneration || socket !== webSocket) return
                                val identity = EvidenceIdentity.fromStream(machine.activeAccountId(), machine.activeDeviceId(), url)
                                sessionIdentity = identity
                                sealedLineActivation?.close()
                                sealedLineActivation = SealedLineActivationMount.open(applicationContext, keys,
                                    machine.activeAccountId(), machine.activeDeviceId(), epoch, {
                                        generation == currentGeneration && socket === webSocket && sessionIdentity == identity &&
                                            machine.phase == DeviceStreamMachine.Phase.ACTIVE &&
                                            runCatching { machine.heartbeatEpoch() == epoch }.getOrDefault(false)
                                    })
                                conversationHost = ConversationSocketComposition.registerAuthenticatedHost(webSocket, identity, epoch,
                                    scheduler, {
                                        check(generation == currentGeneration && socket === webSocket && sessionIdentity == identity &&
                                            machine.phase == DeviceStreamMachine.Phase.ACTIVE && machine.heartbeatEpoch() == epoch)
                                    }, { candidate, guard ->
                                        synchronized(this@AuthenticatedGatewayService) {
                                            guard()
                                            check(conversationConnection == null)
                                            conversationConnection = candidate // Publish before readiness can receive an early reply.
                                            candidate.startIfCurrent(guard)
                                            true
                                        }
                                    }, { candidate ->
                                        synchronized(this@AuthenticatedGatewayService) {
                                            if (conversationConnection === candidate) conversationConnection = null
                                        }
                                    })
                            }
                            if (inboundUploadRequested || lineOptOutUploadRequested) {
                                eventPump = scheduler.scheduleAtFixedRate({
                                    if (generation == currentGeneration) {
                                        if (inboundUploadRequested) {
                                            pumpInboundEvents(webSocket, machine, keys, url,
                                                currentGeneration)
                                        }
                                        if (lineOptOutUploadRequested) {
                                            pumpLineOptOutEvents(webSocket, machine, keys,
                                                currentGeneration)
                                        }
                                    }
                                }, 0, 3, TimeUnit.SECONDS)
                            } else {
                                // No periodic pump: an idle session must not touch the
                                // journal. Writers, grants, acks and the resend timer
                                // drive every query instead.
                                alphaPump.onSessionStart()
                                JournalWriteSignal.replace {
                                    if (generation == currentGeneration) {
                                        alphaPump.requestQuery()
                                        pumpAlphaEvents(webSocket, machine, url, currentGeneration)
                                    }
                                }
                                pumpAlphaEvents(webSocket, machine, url, currentGeneration)
                            }
                        }
                        "heartbeat_ack" -> {
                            requireFields(frame, setOf("v", "type", "connection_epoch"))
                            check(frame.opt("connection_epoch") is Number)
                            val ackEpoch = frame.getLong("connection_epoch")
                            AuthenticatedGatewayStatus.heartbeats = machine.heartbeatAck(ackEpoch)
                            if (generation == currentGeneration)
                                timingTrace.mark(HeartbeatTraceEvent.ACK, ackEpoch)
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
                            // Retirement must also run when a grant expires without an
                            // ack, so no reserved intent can survive as an orphan.
                            grantExpiry?.cancel(false)
                            grantExpiry = scheduler.schedule({
                                if (generation == currentGeneration) {
                                    alphaPump.onGrantExpiry()
                                    pumpAlphaEvents(webSocket, machine, url, currentGeneration)
                                }
                            }, maxOf(0L, grant.expiresAtMs - System.currentTimeMillis()),
                                TimeUnit.MILLISECONDS)
                            JournalRuntime.io.execute {
                                try {
                                    if (generation != currentGeneration) return@execute
                                    SmsJournalDatabase.get(applicationContext).attempts().reserveAlpha(
                                        grant.attemptId.toString(), grant.messageId.toString(),
                                        grant.subscriptionId, 1, UUID.randomUUID().toString(),
                                        System.currentTimeMillis(),
                                        InboundVault.token("sender-v1",
                                            grant.recipientE164.toByteArray(Charsets.US_ASCII)),
                                        sessionIdentity ?: EvidenceIdentity.fromStream(
                                            machine.activeAccountId(), deviceId, url))
                                    AuthenticatedGatewayStatus.value = "Grant reserved; waiting for writer ack"
                                    alphaPump.requestQuery()
                                    pumpAlphaEvents(webSocket, machine, url, currentGeneration)
                                } catch (_: Exception) {
                                    fail(webSocket, currentGeneration)
                                }
                            }
                        }
                        MmsSpikeGrantValidator.FRAME_TYPE -> {
                            // Debug builds only (#438); the release implementation rejects the frame.
                            check(machine.phase == DeviceStreamMachine.Phase.ACTIVE)
                            MmsSpikeGrants.onGrantFrame(applicationContext, frame, deviceId,
                                machine.heartbeatEpoch())
                        }
                        "radio_event_ack" -> {
                            requireFields(frame, setOf("v", "type", "event_id", "state", "submit_permitted"))
                            check(frame.opt("state") is String && frame.opt("submit_permitted") is Boolean)
                            check(machine.phase == DeviceStreamMachine.Phase.ACTIVE)
                            val event = uuid(frame, "event_id").toString()
                            val state = frame.getString("state")
                            val permitted = frame.getBoolean("submit_permitted")
                            val sealedRoute = sealedConnection?.radioAck(event, state, permitted)
                                ?: ConversationRadioAckRoute.NOT_OURS
                            val route = if (sealedRoute != ConversationRadioAckRoute.NOT_OURS) sealedRoute
                                else conversationConnection?.radioAck(event, state, permitted)
                                    ?: ConversationRadioAckRoute.NOT_OURS
                            // Known late/duplicate conversation ACKs never enter the alpha radio path.
                            if (route == ConversationRadioAckRoute.NOT_OURS)
                                handleAlphaAck(webSocket, machine, url, currentGeneration, event, state, permitted)
                        }
                        "inbound_event_ack" -> {
                            check(inboundUploadRequested && machine.phase == DeviceStreamMachine.Phase.ACTIVE)
                            val ackFields = setOf("v", "type", "event_id", "created", "queued_deliveries")
                            requireFields(frame, ackFields + if (frame.has("suppression_cleared"))
                                setOf("suppression_cleared") else emptySet())
                            check(frame.opt("created") is Boolean)
                            check(!frame.has("suppression_cleared") || frame.opt("suppression_cleared") is Boolean)
                            val deliveries = frame.opt("queued_deliveries")
                            check((deliveries is Int || deliveries is Long) &&
                                (deliveries as Number).toLong() >= 0)
                            handleInboundAck(webSocket, currentGeneration,
                                uuid(frame, "event_id").toString(), frame.optBoolean("suppression_cleared", false))
                        }
                        "sms_line_challenge" -> {
                            check(machine.phase == DeviceStreamMachine.Phase.ACTIVE)
                            handleSmsLineChallenge(webSocket, machine, keys, currentGeneration,
                                SmsLineActivationFrames.challenge(frame))
                        }
                        "sealed_line_challenge", "sealed_line_proof_ack", "sealed_line_activated", "sealed_line_install_ack" -> {
                            check(machine.phase == DeviceStreamMachine.Phase.ACTIVE)
                            handleSealedLineFrame(webSocket, machine, keys, currentGeneration,
                                SealedLineActivationFrames.incoming(frame))
                        }
                        "sms_line_proof_ack" -> {
                            check(machine.phase == DeviceStreamMachine.Phase.ACTIVE)
                            val ack = SmsLineActivationFrames.proofAck(frame)
                            val pending = smsLineActivation
                            if (!ack.accepted && pending?.challenge?.challengeId == ack.challengeId) {
                                smsLineActivation = null
                                AuthenticatedGatewayStatus.value = "SMS line proof refused"
                            }
                        }
                        "sms_line_activated" -> {
                            check(machine.phase == DeviceStreamMachine.Phase.ACTIVE)
                            // Capture the authenticated identity now: a reconnect before the
                            // io thread runs must not discard an approved activation.
                            handleSmsLineActivated(keys, machine.activeAccountId(),
                                machine.activeDeviceId(), SmsLineActivationFrames.activated(frame))
                        }
                        "line_opt_out_ack" -> {
                            check(lineOptOutUploadRequested &&
                                machine.phase == DeviceStreamMachine.Phase.ACTIVE)
                            handleLineOptOutAck(webSocket, currentGeneration,
                                LineOptOutUploadFrame.ackEventId(frame))
                        }
                        SealedExecutionGrantFrame.TYPE -> {
                            if (sealedSelected) checkNotNull(sealedConnection).grant(frame)
                            else SealedExecutionGrantFrame.dispositionWithoutNegotiation()
                        }
                        else -> error("Unexpected device frame")
                    }
                } catch (_: Exception) {
                    fail(webSocket, currentGeneration)
                }
            }

            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                if(generation!=currentGeneration)return
                if(conversationConnection?.binary(bytes.toByteArray())!=true)
                    disconnect(currentGeneration, DeviceReconnectPolicy.Loss.PROTOCOL_REJECTED)
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                if (generation != currentGeneration) return
                val authenticated = machine.phase == DeviceStreamMachine.Phase.ACTIVE
                Log.i("ZTReconnect", "stream closing code=$code authenticated=$authenticated")
                val loss = classifyEvidenceClose(code, authenticated)
                if (generation == currentGeneration)
                    timingTrace.mark(HeartbeatTraceEvent.SOCKET_CLOSING, traceEpoch.get(), loss)
                machine.close()
                disconnect(currentGeneration, loss)
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                if (generation != currentGeneration) return
                val authenticated = machine.phase == DeviceStreamMachine.Phase.ACTIVE
                Log.i("ZTReconnect", "stream closed code=$code authenticated=$authenticated")
                val loss = classifyEvidenceClose(code, authenticated)
                if (generation == currentGeneration)
                    timingTrace.mark(HeartbeatTraceEvent.SOCKET_CLOSED, traceEpoch.get(), loss)
                machine.close()
                disconnect(currentGeneration, loss)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                Log.i("ZTReconnect", "stream failed error=${t.javaClass.simpleName} " +
                    "cause=${t.cause?.javaClass?.simpleName} http=${response?.code}")
                val loss = DeviceDisconnectClassifier.failed(t, response?.code)
                if (generation == currentGeneration)
                    timingTrace.mark(HeartbeatTraceEvent.SOCKET_FAILURE, traceEpoch.get(), loss)
                machine.close()
                disconnect(currentGeneration, loss)
            }
        })
    }

    private fun pumpAlphaEvents(webSocket: WebSocket, machine: DeviceStreamMachine,
                                url: String, currentGeneration: Int) {
        JournalRuntime.io.execute {
            if (generation != currentGeneration) return@execute
            try {
                val work = alphaPump.takeWork() ?: return@execute
                val identity = sessionIdentity ?: return@execute
                val epoch = machine.heartbeatEpoch()
                val dao = SmsJournalDatabase.get(applicationContext).attempts()
                val grant = activeGrant
                if (work.retireOrphans && (grant == null || grant.connectionEpoch != epoch ||
                        System.currentTimeMillis() >= grant.expiresAtMs)) {
                    dao.retireOrphanedAlphaIntents(System.currentTimeMillis(),
                        ConversationRadioIntentOwnership.excluded(identity), ConversationRadioIntentOwnership::owns)
                }
                if (work.quarantineForeign &&
                    dao.quarantineForeignAlpha(identity.accountId, identity.deviceId,
                        identity.originHash, System.currentTimeMillis()) > 0) {
                    quarantinedEvidenceNotice = true
                    AuthenticatedGatewayStatus.value =
                        "Authenticated heartbeat; older device evidence quarantined"
                }
                val event = dao.nextAlphaEvent(identity.accountId, identity.deviceId,
                    identity.originHash, ConversationRadioIntentOwnership.excluded(identity)) ?: return@execute
                if (ConversationRadioIntentOwnership.owns(event)) return@execute
                if (awaitingEventId != null && awaitingEventId != event.eventId) {
                    // A contradictory callback can retract an unsent no-radio
                    // proof. Do not let its retired ID block the conflict event.
                    val awaiting = dao.getAlphaEvent(awaitingEventId!!)
                    if (awaiting != null && awaiting.acknowledgedAtMs == null) return@execute
                    awaitingEventId = null
                    awaitingEventSentAtNanos = 0L
                }
                if (awaitingEventId == event.eventId && awaitingEventSentAtNanos != 0L &&
                    System.nanoTime() - awaitingEventSentAtNanos < TimeUnit.SECONDS.toNanos(30))
                    return@execute
                val frame = JSONObject().put("v", 1).put("type", "radio_event")
                    .put("connection_epoch", epoch).put("event_id", event.eventId)
                    .put("message_id", event.messageId).put("attempt_id", event.attemptId)
                    .put("evidence", event.evidence).put("observed_at_ms", event.observedAtMs)
                if (event.segmentIndex != null && event.segmentCount != null) {
                    frame.put("segment_index", event.segmentIndex)
                        .put("segment_count", event.segmentCount)
                }
                // The permanent sealed-preparation SQL filter handles inserted rows even if
                // the process registry is lost; refresh the live owner after selection too.
                if (ConversationRadioIntentOwnership.owns(event) ||
                    (event.evidence == "durable_submit_intent" &&
                        event.eventId in ConversationRadioIntentOwnership.excluded(identity))) return@execute
                awaitingEventId = event.eventId
                awaitingEventSentAtNanos = System.nanoTime()
                if (!webSocket.send(frame.toString())) {
                    disconnect(currentGeneration, DeviceReconnectPolicy.Loss.TRANSPORT)
                } else {
                    armResendTimer(webSocket, machine, url, currentGeneration)
                }
            } catch (_: Exception) {
                fail(webSocket, currentGeneration)
            }
        }
    }

    /** Resends an unacknowledged event every 30 s; armed only while one is awaiting. */
    private fun armResendTimer(webSocket: WebSocket, machine: DeviceStreamMachine,
                               url: String, currentGeneration: Int) {
        resend?.cancel(false)
        var armed: ScheduledFuture<*>? = null
        armed = scheduler.scheduleAtFixedRate({
            val self = armed
            if (generation != currentGeneration || awaitingEventId == null) {
                self?.cancel(false)
                if (resend === self) resend = null
            } else {
                alphaPump.requestQuery()
                pumpAlphaEvents(webSocket, machine, url, currentGeneration)
            }
        }, 30, 30, TimeUnit.SECONDS)
        resend = armed
    }

    private fun pumpInboundEvents(webSocket: WebSocket, machine: DeviceStreamMachine,
                                  keys: DeviceSigningKeyStore, url: String, currentGeneration: Int) {
        JournalRuntime.io.execute {
            if (generation != currentGeneration) return@execute
            try {
                val epoch = machine.heartbeatEpoch()
                val accountId = machine.activeAccountId()
                val deviceId = machine.activeDeviceId()
                val identity = sessionIdentity ?: return@execute
                val dao = SmsJournalDatabase.get(applicationContext).attempts()
                if (dao.quarantineForeignInbound(identity.accountId, identity.deviceId,
                        identity.originHash, System.currentTimeMillis()) > 0) {
                    quarantinedEvidenceNotice = true
                    AuthenticatedGatewayStatus.value =
                        "Inbound pilot active; older device uploads quarantined"
                }
                // The writer rejects observations older than seven days; leave old rows local.
                val pending = dao.nextInboundUpload(System.currentTimeMillis() -
                    TimeUnit.DAYS.toMillis(6), identity.accountId, identity.deviceId,
                    identity.originHash) ?: return@execute
                if (awaitingInboundId != null && awaitingInboundId != pending.eventId) return@execute
                if (awaitingInboundId == pending.eventId &&
                    System.nanoTime() - inboundSentAtNanos < TimeUnit.SECONDS.toNanos(30)) return@execute
                val event = dao.inboundByEventId(pending.eventId) ?: error("Missing inbound event")
                check(event.classification in setOf(InboundClassification.CAPTURED_LOCAL,
                    InboundClassification.OPT_OUT, InboundClassification.OPT_OUT_REVIEW,
                    InboundClassification.OPT_IN))
                val upload = if (pending.signatureDer == null) {
                    val signature = keys.signInboundMetadata(accountId, deviceId, pending, event)
                    check(signature.size in 8..80)
                    check(dao.signInboundUpload(pending.eventId, accountId.toString(),
                        deviceId.toString(), identity.originHash, signature) == 1)
                    dao.inboundUpload(pending.eventId) ?: error("Missing signed upload")
                } else pending
                check(upload.accountId == accountId.toString() &&
                    upload.deviceId == deviceId.toString() &&
                    upload.originHash == identity.originHash)
                awaitingInboundId = upload.eventId
                inboundSentAtNanos = System.nanoTime()
                if (!webSocket.send(InboundUploadFrame.encode(epoch, upload, event))) {
                    fail(webSocket, currentGeneration)
                }
            } catch (_: Exception) {
                fail(webSocket, currentGeneration)
            }
        }
    }

    private fun handleInboundAck(webSocket: WebSocket, currentGeneration: Int, eventId: String,
                                 suppressionCleared: Boolean) {
        JournalRuntime.io.execute {
            if (generation != currentGeneration) return@execute
            try {
                val dao = SmsJournalDatabase.get(applicationContext).attempts()
                val upload = dao.inboundUpload(eventId) ?: error("Unknown inbound upload")
                if (awaitingInboundId != eventId) {
                    check(upload.acknowledgedAtMs != null)
                    return@execute
                }
                check(upload.acknowledgedAtMs == null)
                check(dao.acknowledgeInboundAck(eventId, System.currentTimeMillis(),
                    suppressionCleared) == 1)
                awaitingInboundId = null
                reconnect.clearEvidenceCloseStreak()
            } catch (_: Exception) {
                fail(webSocket, currentGeneration)
            }
        }
    }

    private fun pumpLineOptOutEvents(webSocket: WebSocket, machine: DeviceStreamMachine,
                                      keys: DeviceSigningKeyStore, currentGeneration: Int) {
        JournalRuntime.io.execute {
            if (generation != currentGeneration || lineOptOutPaused) return@execute
            try {
                val epoch = machine.heartbeatEpoch()
                val accountId = machine.activeAccountId()
                val deviceId = machine.activeDeviceId()
                val dao = SmsJournalDatabase.get(applicationContext).attempts()
                // Older records remain local blocks, not invalid late uploads.
                val now = System.currentTimeMillis()
                val pending = dao.nextLineOptOut(now - TimeUnit.DAYS.toMillis(6))
                    ?: return@execute
                val eventId = checkNotNull(pending.eventId)
                if (awaitingLineOptOutId != null && awaitingLineOptOutId != eventId) return@execute
                if (awaitingLineOptOutId == eventId &&
                    System.nanoTime() - lineOptOutSentAtNanos < TimeUnit.SECONDS.toNanos(30))
                    return@execute
                val selected = getSharedPreferences("gateway_selection", MODE_PRIVATE)
                    .getInt("subscription_id", SubscriptionManager.INVALID_SUBSCRIPTION_ID)
                val binding = dao.currentLineBinding()
                if (!LineOptOutUploadGate.allows(pending, binding, accountId, deviceId,
                        selected, SimCardContinuity.observe(applicationContext), now)) {
                    pauseLineOptOutUpload()
                    return@execute
                }
                // Open the E.164 sender only at the signing boundary. It never enters Room/logs.
                val recipient = LineOptOutSender.recover(pending, InboundVault::openSender) {
                    InboundVault.token("sender-v1", it.toByteArray(Charsets.US_ASCII))
                }
                if (recipient == null) {
                    pauseLineOptOutUpload()
                    return@execute
                }
                val signed = if (pending.signatureDer == null) {
                    val signature = keys.signLineOptOut(accountId, deviceId, pending, recipient)
                    check(signature.size in 8..80)
                    check(dao.signLineOptOut(eventId, checkNotNull(pending.lineId),
                        checkNotNull(pending.bindingGeneration), signature) == 1)
                    dao.lineOptOutByEventId(eventId) ?: error("Missing signed withdrawal")
                } else pending
                // Re-read the line and SIM immediately before queuing the exact signed row.
                val currentBinding = dao.currentLineBinding()
                val currentSelected = getSharedPreferences("gateway_selection", MODE_PRIVATE)
                    .getInt("subscription_id", SubscriptionManager.INVALID_SUBSCRIPTION_ID)
                if (!LineOptOutUploadGate.allows(signed, currentBinding, accountId, deviceId,
                        currentSelected, SimCardContinuity.observe(applicationContext),
                        System.currentTimeMillis()) ||
                    generation != currentGeneration || machine.heartbeatEpoch() != epoch) {
                    pauseLineOptOutUpload()
                    return@execute
                }
                awaitingLineOptOutId = eventId
                lineOptOutSentAtNanos = System.nanoTime()
                if (!webSocket.send(LineOptOutUploadFrame.encode(epoch, signed, recipient)))
                    disconnect(currentGeneration, DeviceReconnectPolicy.Loss.TRANSPORT)
            } catch (_: Exception) {
                // Never discard a STOP when a local key, journal or writer check fails.
                pauseLineOptOutUpload()
            }
        }
    }

    /**
     * Answers an owner-opened challenge with a signed declaration of the selected
     * SIM with current physical-card or API33+ eSIM profile-record continuity. An ineligible SIM or selection declines silently; the owner sees
     * the challenge stay unanswered. A re-pushed challenge resends the same proof.
     */
    private fun handleSmsLineChallenge(webSocket: WebSocket, machine: DeviceStreamMachine,
                                       keys: DeviceSigningKeyStore, currentGeneration: Int,
                                       challenge: SmsLineChallenge) {
        JournalRuntime.io.execute {
            if (generation != currentGeneration) return@execute
            try {
                val epoch = machine.heartbeatEpoch()
                val existing = smsLineActivation
                val proof = if (existing != null && sameChallenge(existing.challenge, challenge))
                    existing.takeIf { it.sim.profile?.isCurrent() != false }
                else SmsLineActivationDevice.forGateway(applicationContext, keys)
                    .prepare(challenge, machine.activeAccountId(), machine.activeDeviceId())
                if (proof == null) {
                    AuthenticatedGatewayStatus.value =
                        "SMS line activation declined: select an eligible SIM and approve the current profile"
                    return@execute
                }
                if (generation != currentGeneration || machine.heartbeatEpoch() != epoch) return@execute
                smsLineActivation = proof
                AuthenticatedGatewayStatus.value = "SMS line proof sent; waiting for owner approval"
                if (!webSocket.send(SmsLineActivationFrames.proof(epoch, proof)))
                    disconnect(currentGeneration, DeviceReconnectPolicy.Loss.TRANSPORT)
            } catch (_: Exception) {
                smsLineActivation = null
                AuthenticatedGatewayStatus.value = "SMS line activation could not be prepared"
            }
        }
    }

    private fun sameChallenge(a: SmsLineChallenge, b: SmsLineChallenge): Boolean =
        a.challengeId == b.challengeId && a.accountId == b.accountId && a.lineId == b.lineId &&
            a.deviceId == b.deviceId && a.generation == b.generation &&
            a.expiresAtMs == b.expiresAtMs && a.nonce.contentEquals(b.nonce)

    private fun handleSealedLineFrame(webSocket: WebSocket, machine: DeviceStreamMachine, keys: DeviceSigningKeyStore,
                                      currentGeneration: Int, input: SealedLineActivationFrames.Incoming) {
        val epoch = machine.heartbeatEpoch()
        val provider = synchronized(this) {
            if (generation != currentGeneration || socket !== webSocket) return
            val existing = sealedLineActivation
            if (existing != null && existing.sessionIsCurrent()) existing
            else {
                existing?.close()
                sealedLineActivation = null
                SealedLineActivationMount.open(applicationContext, keys, machine.activeAccountId(),
                    machine.activeDeviceId(), epoch, {
                        generation == currentGeneration && socket === webSocket &&
                            machine.phase == DeviceStreamMachine.Phase.ACTIVE &&
                            runCatching { machine.heartbeatEpoch() == epoch }.getOrDefault(false)
                    }).also { sealedLineActivation = it }
            }
        } ?: return // Explicit local acceptance may be supplied after authentication; disabled resolution is inert.
        JournalRuntime.io.execute {
            fun current() = generation == currentGeneration && socket === webSocket &&
                sealedLineActivation === provider && machine.phase == DeviceStreamMachine.Phase.ACTIVE &&
                runCatching { machine.heartbeatEpoch() == epoch }.getOrDefault(false)
            if (!current()) return@execute
            try {
                val reply = provider.accept(input)
                if (reply != null && current() && !webSocket.send(reply))
                    disconnect(currentGeneration, DeviceReconnectPolicy.Loss.TRANSPORT)
            } catch (_: Exception) {
                if (current()) disconnect(currentGeneration, DeviceReconnectPolicy.Loss.PROTOCOL_REJECTED)
            }
        }
    }

    /** Installs the local line binding only for the exact proof this process sent. */
    private fun handleSmsLineActivated(keys: DeviceSigningKeyStore, accountId: UUID,
                                       deviceId: UUID, ack: AuthenticatedSmsLineActivationAck) {
        JournalRuntime.io.execute {
            if (ack.challengeId == installedSmsLineChallenge && (!installedSmsLineIsEsim || runCatching {
                SmsJournalDatabase.get(applicationContext).attempts().currentLineBinding()?.liveContinuity() == true
            }.getOrDefault(false))) return@execute
            val dao = SmsJournalDatabase.get(applicationContext).attempts()
            val proof = smsLineActivation
            if (proof == null || !ack.matches(proof)) {
                // After an app restart the proof is gone, but a resend of an
                // activation installed before the restart is not an error.
                val installedBinding = runCatching {
                    dao.currentLineBinding()?.takeIf {
                        ack.isInstalledAs(it) && it.liveContinuity()
                    }
                }.getOrNull()
                val installedBefore = installedBinding != null
                if (installedBefore) {
                    installedSmsLineChallenge = ack.challengeId
                    installedSmsLineIsEsim = installedBinding?.continuityKind == "esim"
                }
                AuthenticatedGatewayStatus.value = if (installedBefore)
                    "SMS line activated on this phone"
                else "SMS line approved for a proof this app no longer holds; start a new activation"
                return@execute
            }
            val installed = try {
                SmsLineActivationDevice.forGateway(applicationContext, keys).installAfterAuthenticatedAck(
                    dao, proof, ack, accountId, deviceId)
            } catch (_: Exception) { false }
            // Keep the proof after a failed install: the hub resends the ack on
            // the next connection and installAfterAuthenticatedAck bounds retries
            // to its grace window.
            if (installed) {
                smsLineActivation = null
                installedSmsLineChallenge = ack.challengeId
                installedSmsLineIsEsim = proof.sim.profile != null
            }
            val conflict = !installed &&
                runCatching { ack.conflictsWith(dao.currentLineBinding()) }.getOrDefault(false)
            if (conflict) smsLineActivation = null
            AuthenticatedGatewayStatus.value = when {
                installed -> "SMS line activated on this phone"
                conflict -> "This phone already holds a different or newer SMS line binding; " +
                    "this approval cannot be installed"
                else -> "SMS line approved, but this phone's SIM, selection or clock does not " +
                    "match the proof yet; it retries when the hub resends, or start a new activation"
            }
        }
    }

    private fun handleLineOptOutAck(webSocket: WebSocket, currentGeneration: Int,
                                     eventId: String) {
        JournalRuntime.io.execute {
            if (generation != currentGeneration) return@execute
            try {
                val dao = SmsJournalDatabase.get(applicationContext).attempts()
                val event = dao.lineOptOutByEventId(eventId) ?: error("Unknown withdrawal ack")
                if (awaitingLineOptOutId != eventId) {
                    check(event.acknowledgedAtMs != null)
                    return@execute
                }
                check(event.acknowledgedAtMs == null)
                check(dao.acknowledgeLineOptOut(eventId, System.currentTimeMillis()) == 1)
                awaitingLineOptOutId = null
                lineOptOutSentAtNanos = 0L
                reconnect.clearEvidenceCloseStreak()
            } catch (_: Exception) {
                fail(webSocket, currentGeneration)
            }
        }
    }

    private fun pauseLineOptOutUpload() {
        lineOptOutPaused = true
        AuthenticatedGatewayStatus.value = "Line opt-out upload paused; check line and local evidence"
    }

    private fun handleAlphaAck(
        webSocket: WebSocket, machine: DeviceStreamMachine, url: String,
        currentGeneration: Int, eventId: String, state: String, permitted: Boolean
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
                    awaitingEventSentAtNanos = 0L
                    reconnect.clearEvidenceCloseStreak()
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
                    awaitingEventSentAtNanos = 0L
                    reconnect.clearEvidenceCloseStreak()
                }
                // An ack clears the awaited event; more evidence may already be queued.
                alphaPump.requestQuery()
                pumpAlphaEvents(webSocket, machine, url, currentGeneration)
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

    private fun classifyEvidenceClose(code: Int, authenticated: Boolean): DeviceReconnectPolicy.Loss {
        val ordinary = DeviceDisconnectClassifier.closed(code, authenticated)
        if (!authenticated) return ordinary
        val alphaId = awaitingEventId
        val inboundId = awaitingInboundId
        val eventId = alphaId ?: inboundId
        val sentAt = if (alphaId != null) awaitingEventSentAtNanos else inboundSentAtNanos
        val immediate = sentAt != 0L && System.nanoTime() - sentAt in
            0..TimeUnit.SECONDS.toNanos(30)
        val typed = code == EVIDENCE_REJECTED_CLOSE
        if (eventId == null || (!typed && (ordinary !=
                DeviceReconnectPolicy.Loss.ACTIVE_CLOSE || !immediate))) {
            reconnect.clearEvidenceCloseStreak()
            return if (typed) DeviceReconnectPolicy.Loss.PROTOCOL_REJECTED else ordinary
        }
        val key = (if (alphaId != null) "radio:" else "inbound:") + eventId
        if (!reconnect.recordEvidenceClose(key, typed)) return ordinary
        val quarantined = try {
            JournalRuntime.io.submit<Boolean> {
                val dao = SmsJournalDatabase.get(applicationContext).attempts()
                val now = System.currentTimeMillis()
                if (alphaId != null) dao.quarantineAlphaEvent(eventId, "server_rejected", now) == 1
                else dao.quarantineInboundUpload(eventId, "server_rejected", now) == 1
            }.get(5, TimeUnit.SECONDS)
        } catch (_: Exception) { false }
        reconnect.clearEvidenceCloseStreak()
        if (quarantined) quarantinedEvidenceNotice = true
        return if (quarantined) DeviceReconnectPolicy.Loss.EVIDENCE_QUARANTINED
            else DeviceReconnectPolicy.Loss.EVIDENCE_QUARANTINE_FAILED
    }

    @Synchronized
    private fun disconnect(currentGeneration: Int, reason: DeviceReconnectPolicy.Loss) {
        if (generation != currentGeneration) return
        generation += 1 // Fence callbacks before potentially blocking conversation closure.
        closeConversationConnection()
        Log.i("ZTReconnect", "disconnect reason=$reason")
        timingTrace.mark(HeartbeatTraceEvent.DISCONNECT, traceEpoch.get(), reason)
        cancelTimers()
        socket?.cancel()
        socket = null
        activeGrant = null
        awaitingEventId = null
        awaitingEventSentAtNanos = 0L
        awaitingInboundId = null
        inboundSentAtNanos = 0L
        awaitingLineOptOutId = null
        lineOptOutSentAtNanos = 0L
        when (val action = reconnect.lost(reason, SystemClock.elapsedRealtime())) {
            is DeviceReconnectPolicy.Action.RetryAfter -> {
                AuthenticatedGatewayStatus.value = if (reason ==
                    DeviceReconnectPolicy.Loss.EVIDENCE_QUARANTINED)
                    "Server rejected stale evidence; quarantined locally; reconnecting"
                else "Server unavailable; retrying device proof"
                getSystemService(NotificationManager::class.java)
                    .notify(NOTIFICATION_ID, notification(if (reason ==
                        DeviceReconnectPolicy.Loss.EVIDENCE_QUARANTINED)
                        "Stale evidence quarantined; reconnecting" else "Server unavailable; retrying"))
                retry?.cancel(false)
                retry = scheduler.schedule({
                    synchronized(this) {
                        val next = reconnect.retryDue()
                        if (next is DeviceReconnectPolicy.Action.Connect) {
                            check(next.pilotMode == DeviceReconnectPolicy.PilotMode.HEARTBEAT_ONLY)
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
                val rebootResumeCleared = HeartbeatResumeStore.clear(this)
                AuthenticatedGatewayStatus.value = if (reason ==
                    DeviceReconnectPolicy.Loss.EVIDENCE_QUARANTINE_FAILED)
                    "Could not quarantine rejected evidence; paused for repair"
                else if (rebootResumeCleared)
                    "Device proof or protocol rejected; restart manually"
                else "Device proof or protocol rejected; could not disable reboot resume. Retry Pause"
                stopSelf()
            }
            else -> Unit
        }
    }

    private fun hasNetwork(network: Network?): Boolean {
        if (network == null) return false
        return connectivity.getNetworkCapabilities(network)
            ?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true
    }

    private fun refreshNetwork() {
        synchronized(this) {
            if (endpoint == null || approvedDevice == null) return
            val network = connectivity.activeNetwork
            val replaced = observedNetwork != null && network != null && observedNetwork != network
            observedNetwork = network
            val available = hasNetwork(network)
            when (val action = reconnect.networkChanged(available)) {
                DeviceReconnectPolicy.Action.WaitForNetwork -> {
                    generation += 1
                    cancelTimers()
                    retry?.cancel(false)
                    socket?.cancel()
                    socket = null
                    activeGrant = null
                    awaitingEventId = null
                    awaitingEventSentAtNanos = 0L
                    awaitingInboundId = null
                    inboundSentAtNanos = 0L
                    awaitingLineOptOutId = null
                    lineOptOutSentAtNanos = 0L
                    AuthenticatedGatewayStatus.value = "Disconnected; waiting for network"
                    getSystemService(NotificationManager::class.java)
                        .notify(NOTIFICATION_ID, notification("Waiting for network"))
                }
                is DeviceReconnectPolicy.Action.Connect -> {
                    retry?.cancel(false)
                    check(action.pilotMode == DeviceReconnectPolicy.PilotMode.HEARTBEAT_ONLY)
                    openConnection(checkNotNull(endpoint), checkNotNull(approvedDevice))
                }
                DeviceReconnectPolicy.Action.NoChange -> {
                    if (replaced && available && socket != null)
                        disconnect(generation, DeviceReconnectPolicy.Loss.TRANSPORT)
                }
                else -> Unit
            }
        }
    }

    private fun closeConversationConnection() {
        val execution = sealedConnection; sealedConnection = null
        val activation = sealedLineActivation; sealedLineActivation = null
        val host=conversationHost;conversationHost=null
        val old=conversationConnection;conversationConnection=null
        try { execution?.close() } finally {
            try { activation?.close() } finally {
                try {host?.close()} finally {old?.close()}
            }
        }
    }
    private fun halt() {
        SealedExecutionMount.pause()
        generation += 1 // Fence listener callbacks before admission/storage closure can wait.
        closeConversationConnection()
        ConversationProcessMount.runtime.pause(ConversationStopReason.PHONE_SESSION_LOST)
        reconnect.pause()
        JournalWriteSignal.replace(null)
        cancelTimers()
        retry?.cancel(false)
        socket?.cancel()
        socket = null
        activeGrant = null
        awaitingEventId = null
        awaitingEventSentAtNanos = 0L
        awaitingInboundId = null
        inboundSentAtNanos = 0L
        awaitingLineOptOutId = null
        lineOptOutSentAtNanos = 0L
    }

    private fun cancelTimers() {
        closeConversationConnection()
        networkServiceSampler.cancel()
        heartbeat?.cancel(false)
        watchdog?.cancel(false)
        handshakeDeadline?.cancel(false)
        eventPump?.cancel(false)
        grantExpiry?.cancel(false)
        resend?.cancel(false)
    }

    @Synchronized
    override fun onDestroy() {
        SealedLineActivationMount.disable()
        SimProfileContinuity.stop()
        ConversationProcessMount.runtime.pause(ConversationStopReason.WORKER_SHUTDOWN)
        processActive = false
        halt()
        connectivity.unregisterNetworkCallback(networkCallback)
        networkServiceSampler.shutdown()
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

    private fun validUrl(value: String): Boolean = HeartbeatResumeStore.validUrl(value)

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
        @Volatile internal var processActive = false
        const val ACTION_PAUSE = "org.zrotext.gateway.AUTH_PAUSE"
        const val ACTION_BOOT_RESUME = "org.zrotext.gateway.AUTH_BOOT_RESUME"
        const val EXTRA_URL = "url"
        const val EXTRA_DEVICE_ID = "device_id"
        const val EXTRA_REBOOT_RESUME = "reboot_resume"
        const val EXTRA_ALPHA_RECIPIENT = "alpha_recipient"
        const val EXTRA_ALPHA_SUBSCRIPTION_ID = "alpha_subscription_id"
        const val EXTRA_INBOUND_UPLOAD = "inbound_upload"
        const val EXTRA_LINE_OPT_OUT_UPLOAD = "line_opt_out_upload"
        const val EXTRA_HEARTBEAT_TIMING_TRACE = "heartbeat_timing_trace"

        /**
         * Stream liveness is the heartbeat and its 90 s ack watchdog alone; the hub
         * ignores ping/pong. A protocol ping would only duplicate the heartbeat's
         * frames and add a second, redundant failure path.
         */
        fun streamClient(): OkHttpClient = OkHttpClient.Builder().build()
        private const val CHANNEL = "authenticated_gateway"
        private const val NOTIFICATION_ID = 1002
        private const val EVIDENCE_REJECTED_CLOSE = 4409
        private const val MAX_FRAME_BYTES = 4096
    }
}
