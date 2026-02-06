package com.example.myapplication

import android.os.Bundle
import android.view.View
import android.widget.TextView
import androidx.fragment.app.Fragment
import java.text.SimpleDateFormat
import java.util.*

class DebugFragment : Fragment(R.layout.fragment_debug), UpdatableFragment {
    private lateinit var tvDebugStatus: TextView
    private lateinit var tvDebugLog: TextView

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        tvDebugStatus = view.findViewById(R.id.tvDebugStatus)
        tvDebugLog = view.findViewById(R.id.tvDebugLog)
        update()
    }

    override fun update() {
        val main = activity as? MainActivity ?: return
        val result = main.getAirCatchResult()
        
        if (result != null) {
            val time = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(result.lastUpdate))
            tvDebugStatus.text = "Last Update: $time | Confirmed: ${if (result.confirmed) "YES" else "NO"}"
            tvDebugStatus.setTextColor(if (result.confirmed) 0xFF00E676.toInt() else 0xFFFF5252.toInt())
            tvDebugLog.text = result.summary
        } else {
            tvDebugStatus.text = "Waiting for data..."
            tvDebugLog.text = "The AirCatch algorithm runs every 30 seconds after starting the sniffer."
        }
    }
}
