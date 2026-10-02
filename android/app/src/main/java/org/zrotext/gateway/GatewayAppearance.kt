// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.Shapes
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.compose.ui.text.style.TextAlign

internal val GatewayColors = darkColorScheme(
    primary = Color(0xFFB6F36A),
    onPrimary = Color(0xFF0B0F0C),
    background = Color(0xFF0B0F0C),
    surface = Color(0xFF111712),
    onBackground = Color(0xFFF0F3E9),
    onSurface = Color(0xFFF0F3E9),
    surfaceVariant = Color(0xFF161E17),
    onSurfaceVariant = Color(0xFF99A696),
    outline = Color(0xFF677363)
)

@Composable
internal fun GatewayTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = GatewayColors, shapes = Shapes(
        small = RoundedCornerShape(8.dp),
        medium = RoundedCornerShape(12.dp),
        large = RoundedCornerShape(16.dp)
    )) {
        // The platform window uses a light theme. Paint the background and
        // provide its matching foreground instead of inheriting either one.
        Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background,
            contentColor = MaterialTheme.colorScheme.onBackground, content = content)
    }
}

@Composable
internal fun GatewaySectionTitle(text: String) {
    Text(text, style = MaterialTheme.typography.titleMedium,
        modifier = Modifier.semantics { heading() })
}

@Composable
internal fun GatewayStatusText(label: String, value: String, textAlign: TextAlign = TextAlign.Start) {
    // Heartbeat counters deliberately live outside this region: a routine
    // acknowledgement must not repeatedly interrupt assistive reading.
    Text("$label: $value", textAlign = textAlign,
        modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
}

@Composable
internal fun GatewayButton(onClick: () -> Unit, modifier: Modifier = Modifier,
    content: @Composable RowScope.() -> Unit) {
    // Keep visible and semantic bounds at least 48 dp, not just expanded hit slop.
    Button(onClick = onClick, shape = MaterialTheme.shapes.medium,
        modifier = modifier.sizeIn(minWidth = 48.dp, minHeight = 48.dp),
        content = content)
}
