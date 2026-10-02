// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.database.ContentObserver
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import kotlinx.coroutines.delay
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.sin

/** Conservative presentation only; the full service observation stays visible. */
internal enum class GatewayConnectionMood(val title: String) {
    PAUSED("Connection paused."), CONNECTING("Proving this phone."),
    CONNECTED("Phone authenticated."), OFFLINE("Waiting for network."),
    ATTENTION("Check the connection.");

    companion object {
        fun from(status: String): GatewayConnectionMood = when {
            status == "Paused" -> PAUSED
            status == "Waiting for network" || status.startsWith("Disconnected") -> OFFLINE
            status.contains("quarantin", ignoreCase = true) || status.contains("rejected", ignoreCase = true) -> ATTENTION
            status == "Waiting for device challenge" || status == "Proving enrolled device key" -> CONNECTING
            status.startsWith("Authenticated heartbeat") || status == "Inbound metadata pilot active" ||
                status == "Line opt-out upload pilot active" || status == "Armed for one synthetic grant" -> CONNECTED
            else -> ATTENTION
        }
    }
}

@Composable
internal fun gatewayMotionAllowed(): Boolean {
    val context = LocalContext.current
    val owner = LocalLifecycleOwner.current
    fun enabled() = Settings.Global.getFloat(context.contentResolver,
        Settings.Global.ANIMATOR_DURATION_SCALE, 1f) > 0f
    var allowed by remember(context) { mutableStateOf(enabled()) }
    var resumed by remember(owner) { mutableStateOf(owner.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) }
    DisposableEffect(context, owner) {
        val setting = object : ContentObserver(Handler(Looper.getMainLooper())) {
            override fun onChange(selfChange: Boolean) { allowed = enabled() }
        }
        val lifecycle = LifecycleEventObserver { _, _ ->
            resumed = owner.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)
            if (resumed) allowed = enabled()
        }
        context.contentResolver.registerContentObserver(
            Settings.Global.getUriFor(Settings.Global.ANIMATOR_DURATION_SCALE), false, setting)
        owner.lifecycle.addObserver(lifecycle)
        onDispose {
            context.contentResolver.unregisterContentObserver(setting)
            owner.lifecycle.removeObserver(lifecycle)
        }
    }
    return allowed && resumed
}

@Composable
internal fun GatewayEntrance(order: Int, motion: Boolean, content: @Composable () -> Unit) {
    val progress = remember { Animatable(if (motion) 0f else 1f) }
    LaunchedEffect(motion) {
        if (motion) {
            delay(order * 45L)
            progress.animateTo(1f, spring(dampingRatio = 0.85f, stiffness = 260f))
        } else progress.snapTo(1f)
    }
    Box(Modifier.graphicsLayer {
        alpha = progress.value
        translationY = (1f - progress.value) * 20.dp.toPx()
        scaleX = 0.97f + progress.value * 0.03f
        scaleY = scaleX
    }) { content() }
}

/** Canvas decoration has no duplicated spoken status and no pretend activity. */
@Composable
internal fun GatewaySignal(mood: GatewayConnectionMood, motion: Boolean, compact: Boolean = false) {
    val live = mood == GatewayConnectionMood.CONNECTED || mood == GatewayConnectionMood.CONNECTING
    val phase = if (motion && live) {
        val transition = rememberInfiniteTransition(label = "Connection breathing")
        transition.animateFloat(0f, 1f,
            infiniteRepeatable(tween(2200), RepeatMode.Restart), label = "Signal rings").value
    } else 0.5f
    val ink = when (mood) {
        GatewayConnectionMood.CONNECTED, GatewayConnectionMood.CONNECTING -> GatewayColors.primary
        GatewayConnectionMood.ATTENTION -> Color(0xFFEDBE70)
        else -> GatewayColors.onSurfaceVariant
    }
    Canvas(Modifier.size(if (compact) 64.dp else 96.dp)) {
        val center = Offset(size.width / 2, size.height / 2)
        val radius = size.minDimension / 2
        drawCircle(ink.copy(alpha = 0.06f), radius * 0.72f, center)
        drawCircle(ink.copy(alpha = 0.18f), radius * 0.90f, center, style = Stroke(1.dp.toPx()))
        drawCircle(ink.copy(alpha = 0.24f), radius * 0.72f, center, style = Stroke(1.dp.toPx()))
        if (live) drawCircle(ink.copy(alpha = (1f - phase) * 0.25f),
            radius * (0.70f + phase * 0.28f), center, style = Stroke(1.5.dp.toPx()))
        drawCircle(ink.copy(alpha = 0.10f), radius * 0.46f, center)
        val s = radius * 0.22f
        val stroke = 3.dp.toPx()
        if (mood == GatewayConnectionMood.PAUSED) {
            drawLine(ink, center + Offset(-s / 2, -s), center + Offset(-s / 2, s), stroke)
            drawLine(ink, center + Offset(s / 2, -s), center + Offset(s / 2, s), stroke)
        } else if (mood == GatewayConnectionMood.ATTENTION) {
            drawLine(ink, center + Offset(0f, -s), center + Offset(0f, s * 0.25f), stroke)
            drawCircle(ink, stroke / 2, center + Offset(0f, s))
        } else if (mood == GatewayConnectionMood.OFFLINE) {
            drawLine(ink, center + Offset(-s, 0f), center + Offset(s, 0f), stroke)
        } else {
            drawLine(ink, center + Offset(-s, s), center + Offset(s, -s), stroke)
            drawLine(ink, center + Offset(0f, -s), center + Offset(s, -s), stroke)
            drawLine(ink, center + Offset(s, -s), center + Offset(s, 0f), stroke)
        }
    }
}

@Composable
internal fun GatewayGearMark() {
    // A native vector keeps the header quiet without adding an icon dependency.
    Canvas(Modifier.size(24.dp)) {
        val center = Offset(size.width / 2, size.height / 2)
        val unit = size.minDimension / 24f
        val outline = Path().apply {
            repeat(32) { index ->
                val angle = index * PI / 16 - PI / 2
                val radius = (if (index % 4 < 2) 10.5f else 8f) * unit
                val point = center + Offset(cos(angle).toFloat() * radius, sin(angle).toFloat() * radius)
                if (index == 0) moveTo(point.x, point.y) else lineTo(point.x, point.y)
            }
            close()
        }
        drawPath(outline, GatewayColors.onSurface, style = Stroke(1.5f * unit))
        drawCircle(GatewayColors.onSurface, 3f * unit, center, style = Stroke(1.5f * unit))
    }
}

@Composable
internal fun GatewayBrandMark() {
    // Same geometry as docs/assets/zrotext-mark.svg, rendered natively.
    Canvas(Modifier.size(26.dp)) {
        val unit = size.width / 48f
        drawRoundRect(GatewayColors.primary, cornerRadius = CornerRadius(11f * unit))
        val mark = Path().apply {
            moveTo(12f * unit, 14f * unit); lineTo(36f * unit, 14f * unit)
            lineTo(15f * unit, 33f * unit); lineTo(36f * unit, 33f * unit)
            moveTo(13f * unit, 24f * unit); lineTo(22f * unit, 24f * unit)
        }
        drawPath(mark, Color(0xFF0B100B), style = Stroke(4f * unit, cap = StrokeCap.Square))
    }
}

@Composable
internal fun GatewayShortcutIcon(page: GatewayPage) {
    Canvas(Modifier.size(22.dp)) {
        val ink = GatewayColors.primary
        val unit = size.width / 24f
        fun line(x: Float, y: Float, x2: Float, y2: Float) =
            drawLine(ink, Offset(x * unit, y * unit), Offset(x2 * unit, y2 * unit), 1.8.dp.toPx())
        when (page) {
            GatewayPage.HOME -> {
                line(3f, 11f, 12f, 3f); line(12f, 3f, 21f, 11f)
                line(6f, 9f, 6f, 21f); line(6f, 21f, 18f, 21f); line(18f, 21f, 18f, 9f)
            }
            GatewayPage.SETUP -> {
                drawCircle(ink, 4f * unit, Offset(7f * unit, 8f * unit), style = Stroke(1.8.dp.toPx()))
                line(10f, 11f, 20f, 21f); line(15f, 16f, 18f, 13f); line(18f, 19f, 21f, 16f)
            }
            GatewayPage.CONNECTION -> {
                line(4f, 20f, 20f, 4f); line(10f, 4f, 20f, 4f); line(20f, 4f, 20f, 14f)
            }
            GatewayPage.TOOLS -> {
                line(4f, 6f, 20f, 6f); line(4f, 12f, 20f, 12f); line(4f, 18f, 20f, 18f)
                drawCircle(ink, 2.5f * unit, Offset(9f * unit, 6f * unit))
                drawCircle(ink, 2.5f * unit, Offset(16f * unit, 12f * unit))
                drawCircle(ink, 2.5f * unit, Offset(7f * unit, 18f * unit))
            }
        }
    }
}
