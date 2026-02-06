package com.example.myapplication

import android.Manifest
import android.app.PendingIntent
import android.content.*
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.os.*
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import androidx.viewpager2.adapter.FragmentStateAdapter
import androidx.viewpager2.widget.ViewPager2
import com.google.android.material.tabs.TabLayout
import com.google.android.material.tabs.TabLayoutMediator

class MainActivity : AppCompatActivity(), SnifferService.ServiceCallback {

    private var snifferService: SnifferService? = null
    private var isBound = false

    private lateinit var btnStartStop: Button
    private lateinit var tvRawDataStatus: TextView
    lateinit var viewPager: ViewPager2
    private lateinit var tabLayout: TabLayout

    private val ACTION_USB_PERMISSION = "com.example.myapplication.USB_PERMISSION"
    
    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            val binder = service as SnifferService.LocalBinder
            snifferService = binder.getService()
            snifferService?.setCallback(this@MainActivity)
            isBound = true
            updateUiState()
            onDataUpdated()
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            snifferService = null
            isBound = false
        }
    }

    private val usbReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.action) {
                ACTION_USB_PERMISSION -> {
                    val device: UsbDevice? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        intent.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice::class.java)
                    } else {
                        @Suppress("DEPRECATION")
                        intent.getParcelableExtra(UsbManager.EXTRA_DEVICE)
                    }
                    
                    if (intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)) {
                        device?.let { startServiceAndSniff(it) }
                    } else {
                        Toast.makeText(context, "USB Permission Denied", Toast.LENGTH_SHORT).show()
                    }
                }
                UsbManager.ACTION_USB_DEVICE_ATTACHED -> {
                    if (snifferService?.isCurrentlyReceiving() == false && snifferService?.isSnifferDesiredState() == true) {
                        requestUsbAndStart()
                    }
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        btnStartStop = findViewById(R.id.btnStartStop)
        tvRawDataStatus = findViewById(R.id.tvRawDataStatus)
        viewPager = findViewById(R.id.viewPager)
        tabLayout = findViewById(R.id.tabLayout)

        val adapter = DashboardAdapter(this)
        viewPager.adapter = adapter

        TabLayoutMediator(tabLayout, viewPager) { tab, position ->
            tab.text = when(position) {
                0 -> "Nearby Tags"
                1 -> "Recent Activity"
                else -> "Tab"
            }
        }.attach()

        btnStartStop.setOnClickListener {
            if (snifferService?.isSnifferDesiredState() == true) {
                snifferService?.stopSniffing()
                updateUiState()
            } else {
                requestUsbAndStart()
            }
        }

        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (snifferService?.isSnifferDesiredState() == true) {
                    AlertDialog.Builder(this@MainActivity)
                        .setTitle("Monitoring in Background")
                        .setMessage("AirCatch is currently monitoring for trackers. If you exit the UI, it will continue in the background. Close UI?")
                        .setPositiveButton("Close UI") { _, _ ->
                            isEnabled = false
                            onBackPressedDispatcher.onBackPressed()
                        }
                        .setNegativeButton("Cancel", null)
                        .show()
                } else {
                    isEnabled = false
                    onBackPressedDispatcher.onBackPressed()
                }
            }
        })

        checkPermissions()
        
        val filter = IntentFilter().apply {
            addAction(ACTION_USB_PERMISSION)
            addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(usbReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(usbReceiver, filter)
        }

        Intent(this, SnifferService::class.java).also { intent ->
            bindService(intent, serviceConnection, Context.BIND_AUTO_CREATE)
        }
    }

    private fun requestUsbAndStart() {
        val usbManager = getSystemService(Context.USB_SERVICE) as UsbManager
        val device = usbManager.deviceList.values.firstOrNull { it.vendorId == 0x303A || it.vendorId == 0x1234 }

        if (device == null) {
            Toast.makeText(this, "Please connect the AirCatch receiver", Toast.LENGTH_SHORT).show()
            return
        }

        if (!usbManager.hasPermission(device)) {
            val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) PendingIntent.FLAG_IMMUTABLE else 0
            val permissionIntent = PendingIntent.getBroadcast(this, 0, Intent(ACTION_USB_PERMISSION), flags)
            usbManager.requestPermission(device, permissionIntent)
        } else {
            startServiceAndSniff(device)
        }
    }

    private fun startServiceAndSniff(device: UsbDevice) {
        val intent = Intent(this, SnifferService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
        
        if (!isBound) {
            bindService(intent, serviceConnection, Context.BIND_AUTO_CREATE)
        }
        
        Handler(Looper.getMainLooper()).postDelayed({
            snifferService?.startSniffing(device)
            updateUiState()
        }, 200)
    }

    private fun updateUiState() {
        val s = snifferService ?: return
        if (s.isSnifferDesiredState()) {
            btnStartStop.text = "STOP MONITORING"
            btnStartStop.setBackgroundColor(0xFFFF5252.toInt())
            if (!s.isCurrentlyReceiving()) {
                tvRawDataStatus.text = "Searching for receiver..."
            }
        } else {
            btnStartStop.text = "START MONITORING"
            btnStartStop.setBackgroundColor(0xFF4CAF50.toInt())
            tvRawDataStatus.text = "Ready to scan for nearby trackers"
        }
    }

    override fun onDataUpdated() {
        val s = snifferService ?: return
        val result = s.airCatchResult
        if (result != null) {
            tvRawDataStatus.text = result.summary
            tvRawDataStatus.setTextColor(if (result.confirmed) 0xFFFF5252.toInt() else 0xFF00E676.toInt())
        }
        
        supportFragmentManager.fragments.forEach {
            (it as? UpdatableFragment)?.update()
        }
    }

    override fun onStatusUpdated(status: String) {
        tvRawDataStatus.text = status
        updateUiState()
    }

    override fun onDumpStatusChanged(isDumping: Boolean, fileName: String?) {}

    override fun onDecodingStatusChanged(isEnabled: Boolean) {}

    override fun onDestroy() {
        super.onDestroy()
        if (isBound) {
            unbindService(serviceConnection)
            isBound = false
        }
        try {
            unregisterReceiver(usbReceiver)
        } catch (e: Exception) {}
    }

    private fun checkPermissions() {
        val permissions = mutableListOf(Manifest.permission.ACCESS_FINE_LOCATION)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            permissions.add(Manifest.permission.BLUETOOTH_SCAN)
            permissions.add(Manifest.permission.BLUETOOTH_CONNECT)
            permissions.add(Manifest.permission.POST_NOTIFICATIONS)
        }
        ActivityCompat.requestPermissions(this, permissions.toTypedArray(), 1)
    }

    inner class DashboardAdapter(fa: AppCompatActivity) : FragmentStateAdapter(fa) {
        override fun getItemCount() = 2
        override fun createFragment(position: Int): Fragment {
            return when(position) {
                0 -> NearbyTagsFragment()
                else -> PacketListFragment()
            }
        }
    }

    fun getPackets(): List<PacketInfo> = snifferService?.allPackets ?: emptyList()
    fun getAirCatchResult(): AirCatchResult? = snifferService?.airCatchResult
}

interface UpdatableFragment {
    fun update()
}

class NearbyTagsFragment : Fragment(R.layout.fragment_stats), UpdatableFragment {
    private var adapter: NearbyTagAdapter? = null

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        val rv = view.findViewById<RecyclerView>(R.id.rvStats) ?: return
        adapter = NearbyTagAdapter()
        rv.layoutManager = LinearLayoutManager(context)
        rv.adapter = adapter
    }

    override fun update() {
        val main = activity as? MainActivity ?: return
        val result = main.getAirCatchResult() ?: return
        adapter?.submitList(result.recentTags)
    }
}

class NearbyTagAdapter : RecyclerView.Adapter<NearbyTagAdapter.ViewHolder>() {
    private var items = emptyList<ConsumerTagInfo>()

    fun submitList(newList: List<ConsumerTagInfo>) {
        items = newList
        notifyDataSetChanged()
    }

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val tvLabel: TextView = view.findViewById(R.id.tvLabel)
        val tvCount: TextView = view.findViewById(R.id.tvCount)
        val tvCrcOk: TextView = view.findViewById(R.id.tvCrcOk)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        return ViewHolder(LayoutInflater.from(parent.context).inflate(R.layout.item_stat_row, parent, false))
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = items[position]
        holder.tvLabel.text = item.type
        holder.tvCount.text = item.mac
        val ago = (System.currentTimeMillis() - item.lastSeenMs) / 1000
        holder.tvCrcOk.text = "Seen ${ago}s ago"
        holder.tvCrcOk.setTextColor(0xFFB0B0B0.toInt())
    }

    override fun getItemCount() = items.size
}

class PacketListFragment : Fragment(R.layout.fragment_list), UpdatableFragment {
    private var adapter: PacketAdapter? = null
    
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        val rv = view.findViewById<RecyclerView>(R.id.recyclerView)
        val tvFilterStatus = view.findViewById<TextView>(R.id.tvFilterStatus)
        tvFilterStatus.visibility = View.GONE
        
        val main = activity as MainActivity
        adapter = PacketAdapter({ main.getPackets() }, { null })
        rv.layoutManager = LinearLayoutManager(context)
        rv.adapter = adapter
    }

    override fun update() {
        adapter?.refresh()
    }
}

class PacketAdapter(
    private val packetsProvider: () -> List<PacketInfo>,
    private val filterProvider: () -> String?
) : RecyclerView.Adapter<PacketAdapter.ViewHolder>() {

    private var filteredPackets: List<PacketInfo> = emptyList()

    init {
        updateFilteredList()
    }

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val tvPacketNum: TextView = view.findViewById(R.id.tvPacketNum)
        val tvTimestamp: TextView = view.findViewById(R.id.tvTimestamp)
        val tvPayload: TextView = view.findViewById(R.id.tvPayload)
    }

    fun refresh() {
        updateFilteredList()
        notifyDataSetChanged()
    }

    private fun updateFilteredList() {
        val allPackets = packetsProvider()
        val source = synchronized(allPackets) { allPackets.toList() }
        filteredPackets = source.take(50)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        return ViewHolder(LayoutInflater.from(parent.context).inflate(R.layout.item_packet, parent, false))
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        if (position >= filteredPackets.size) return
        val info = filteredPackets[position]
        val p = info.decodedPacket
        
        holder.tvPacketNum.text = "Device: ${p.tagInfo.family} | ${p.advA ?: "Unknown MAC"}"
        holder.tvPacketNum.setTextColor(if (p.crcOk) 0xFF00E676.toInt() else 0xFFFF5252.toInt())
        holder.tvTimestamp.text = info.timestamp
        
        val payloadHex = p.payload.joinToString("") { "%02X".format(it.toInt() and 0xFF) }
        holder.tvPayload.text = "Raw Data: $payloadHex"
    }

    override fun getItemCount() = filteredPackets.size
}
