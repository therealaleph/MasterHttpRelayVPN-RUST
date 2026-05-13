package com.therealaleph.mhrv

import android.content.Context
import android.graphics.Color
import android.graphics.PixelFormat
import android.os.Handler
import android.os.Looper
import android.util.TypedValue
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.WindowManager
import android.widget.LinearLayout
import android.widget.TextView
import org.json.JSONObject

/**
 * Transparent system overlay showing pipeline debug stats.
 * Draggable, semi-transparent, shown on top of all apps.
 * Temporary — remove when pipelining is validated.
 */
class PipelineDebugOverlay(private val context: Context) {

    private val wm = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
    private val handler = Handler(Looper.getMainLooper())
    private var root: View? = null

    private lateinit var tvElevated: TextView
    private lateinit var tvBatches: TextView
    private lateinit var tvEvents: TextView

    private val pollInterval = 500L

    fun show() {
        if (root != null) return

        val dp = { px: Int ->
            TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, px.toFloat(), context.resources.displayMetrics).toInt()
        }

        val layout = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.argb(160, 0, 0, 0))
            setPadding(dp(8), dp(6), dp(8), dp(6))
        }

        val titleTv = TextView(context).apply {
            text = "Pipeline Debug"
            setTextColor(Color.argb(220, 100, 255, 100))
            textSize = 11f
        }
        layout.addView(titleTv)

        tvElevated = TextView(context).apply {
            setTextColor(Color.WHITE)
            textSize = 10f
        }
        layout.addView(tvElevated)

        tvBatches = TextView(context).apply {
            setTextColor(Color.WHITE)
            textSize = 10f
        }
        layout.addView(tvBatches)

        tvEvents = TextView(context).apply {
            setTextColor(Color.argb(200, 200, 200, 200))
            textSize = 9f
            maxLines = 8
        }
        layout.addView(tvEvents)

        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
            PixelFormat.TRANSLUCENT,
        ).apply {
            gravity = Gravity.TOP or Gravity.START
            x = dp(8)
            y = dp(80)
        }

        // Draggable
        var startX = 0
        var startY = 0
        var startTouchX = 0f
        var startTouchY = 0f
        layout.setOnTouchListener { _, event ->
            when (event.action) {
                MotionEvent.ACTION_DOWN -> {
                    startX = params.x
                    startY = params.y
                    startTouchX = event.rawX
                    startTouchY = event.rawY
                    true
                }
                MotionEvent.ACTION_MOVE -> {
                    params.x = startX + (event.rawX - startTouchX).toInt()
                    params.y = startY + (event.rawY - startTouchY).toInt()
                    wm.updateViewLayout(layout, params)
                    true
                }
                else -> false
            }
        }

        root = layout
        wm.addView(layout, params)
        schedulePoll()
    }

    fun hide() {
        handler.removeCallbacksAndMessages(null)
        root?.let {
            try { wm.removeView(it) } catch (_: Throwable) {}
        }
        root = null
    }

    private fun schedulePoll() {
        handler.postDelayed(::poll, pollInterval)
    }

    private fun poll() {
        if (root == null) return
        Thread {
            try {
                val json = Native.pipelineDebugJson()
                handler.post { applyJson(json) }
            } catch (_: Throwable) {}
            schedulePoll()
        }.start()
    }

    private fun applyJson(json: String) {
        if (root == null) return
        try {
            if (json.isNotBlank()) {
                val obj = JSONObject(json)
                val elevated = obj.optInt("elevated", 0)
                val maxElev = obj.optInt("max_elevated", 0)
                val batches = obj.optInt("active_batches", 0)
                val maxBatch = obj.optInt("max_batch_slots", 0)

                val sessions = obj.optInt("active_sessions", 0)
                tvElevated.text = "Sessions: $sessions  Elevated: $elevated / $maxElev"
                tvBatches.text = "Batches: $batches / $maxBatch"

                val sessArr = obj.optJSONArray("sessions")
                val sessLines = if (sessArr != null && sessArr.length() > 0) {
                    (0 until sessArr.length()).joinToString("\n") { i ->
                        val s = sessArr.getJSONObject(i)
                        val sid = s.optString("sid", "?")
                        val d = s.optInt("depth", 0)
                        val inf = s.optInt("inflight", 0)
                        val e = if (s.optBoolean("elevated", false)) " E" else ""
                        "$sid d=$d f=$inf$e"
                    }
                } else ""

                val arr = obj.optJSONArray("events")
                val evtLines = if (arr != null && arr.length() > 0) {
                    val start = maxOf(0, arr.length() - 5)
                    (start until arr.length()).joinToString("\n") { arr.getString(it) }
                } else ""

                tvEvents.text = listOf(sessLines, evtLines).filter { it.isNotEmpty() }.joinToString("\n---\n")
            }
        } catch (_: Throwable) {}
    }
}
