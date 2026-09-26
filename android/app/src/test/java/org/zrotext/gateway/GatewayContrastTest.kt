// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import org.junit.Assert.assertTrue
import org.junit.Test

class GatewayContrastTest {
    @Test fun enabledTextAndFieldBordersContrastWithPaintedBackgrounds() {
        val colors = GatewayColors
        val pairs = listOf(
            Triple(colors.onBackground, colors.background, 4.5f),
            Triple(colors.onSurface, colors.background, 4.5f),
            Triple(colors.onSurfaceVariant, colors.background, 4.5f),
            Triple(colors.onPrimary, colors.primary, 4.5f),
            Triple(colors.primary, colors.background, 4.5f),
            Triple(colors.error, colors.background, 4.5f),
            Triple(colors.outline, colors.background, 3f)
        )
        for ((foreground, background, minimum) in pairs) {
            assertTrue("Insufficient contrast for $foreground on $background",
                contrast(foreground, background) >= minimum)
        }
    }

    private fun contrast(first: Color, second: Color): Float {
        val brighter = maxOf(first.luminance(), second.luminance())
        val darker = minOf(first.luminance(), second.luminance())
        return (brighter + 0.05f) / (darker + 0.05f)
    }
}
