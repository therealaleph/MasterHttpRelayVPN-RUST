package com.therealaleph.mhrv.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

/**
 * Visual theme tuned to match the desktop `mhrv-rs-ui` eframe UI pixel-for-pixel
 * where Compose semantics allow. The canonical source lives in `src/bin/ui.rs`
 * — these constants are the same `egui::Color32` values, re-expressed as
 * `Color(0xAARRGGBB)`. If you change a value here and not there (or vice
 * versa) the two builds will drift visibly.
 *
 * Deliberate choices:
 *   - ALWAYS dark. The desktop UI is always dark (`egui::Visuals::dark()`),
 *     so Android follows. Neither light mode nor Android 12+ dynamic color
 *     is respected — matching the desktop trumps blending with the user's
 *     wallpaper here.
 *   - Card corners 6.dp, button corners 4.dp, matching the eframe
 *     `.rounding(6.0)` / `.rounding(4.0)` pairs in the desktop code.
 */

// Exact palette from src/bin/ui.rs (line 508+).
// ACCENT / ACCENT_HOVER
val AccentBlue = Color(0xFF4678B4)
val AccentHover = Color(0xFF5A91CD)
// OK_GREEN / ERR_RED
val OkGreen = Color(0xFF50B464)
val ErrRed = Color(0xFFDC6E6E)

// Card fill and stroke used by section containers in the desktop UI.
val CardFill = Color(0xFF1C1E22)
val CardStroke = Color(0xFF32363C)

// Backdrop slightly darker than cards so containers pop off the page —
// egui's default dark background sits right around this value.
val BgDark = Color(0xFF111317)

// Text shades — `egui::Color32::from_gray(200)` etc.
val TextPrimary = Color(0xFFC8C8C8)
val TextSecondary = Color(0xFF8C8C8C)
val TextLabel = Color(0xFFB4B4B4)

private val MhrvDark = darkColorScheme(
    primary = AccentBlue,
    onPrimary = Color.White,
    primaryContainer = AccentHover,
    onPrimaryContainer = Color.White,

    secondary = OkGreen,
    onSecondary = Color.Black,

    tertiary = OkGreen,
    onTertiary = Color.Black,

    error = ErrRed,
    onError = Color.White,

    background = BgDark,
    onBackground = TextPrimary,

    surface = CardFill,
    onSurface = TextPrimary,

    surfaceVariant = CardFill,
    onSurfaceVariant = TextSecondary,

    outline = CardStroke,
    outlineVariant = CardStroke,
)

/**
 * Material3 consumes Shapes through component defaults (Button uses
 * `shapes.full`, Card uses `shapes.medium`, etc.). Mapping every size to
 * tight rounded-rectangles keeps the whole app visually consistent with
 * the desktop's squared-off controls instead of Material's default pills.
 */
private val MhrvShapes = Shapes(
    extraSmall = RoundedCornerShape(4.dp),
    small = RoundedCornerShape(4.dp),
    medium = RoundedCornerShape(6.dp),
    large = RoundedCornerShape(6.dp),
    extraLarge = RoundedCornerShape(8.dp),
)

@Composable
fun MhrvTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = MhrvDark,
        shapes = MhrvShapes,
        content = content,
    )
}
