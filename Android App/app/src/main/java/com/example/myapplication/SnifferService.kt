package com.example.myapplication

import android.Manifest
import android.app.*
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.hardware.usb.UsbConstants
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbDeviceConnection
import android.hardware.usb.UsbEndpoint
import android.hardware.usb.UsbInterface
import android.hardware.usb.UsbManager
import android.location.Location
import android.os.*
import android.util.Log
import androidx.core.content.ContextCompat
import androidx.core.app.NotificationCompat
import com.google.android.gms.location.FusedLocationProviderClient
import com.google.android.gms.location.LocationCallback
import com.google.android.gms.location.LocationRequest
import com.google.android.gms.location.LocationResult
import com.google.android.gms.location.LocationServices
import com.google.android.gms.location.Priority
import java.io.File
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

class SnifferService : Service() {
    private val CHANNEL_ID = "SnifferServiceChannel"
    private val ALARM_CHANNEL_ID = "AdversaryAlarmChannel"
    private val NOTIFICATION_ID = 1
    private val ALARM_NOTIFICATION_ID = 2
    private val ACTION_USB_PERMISSION = "com.example.myapplication.USB_PERMISSION"

    private var usbConnection: UsbDeviceConnection? = null
    private var usbInterface: UsbInterface? = null
    private var usbEndpoint: UsbEndpoint? = null
    private var isReceiving = false
    private var receiveThread: Thread? = null
    private var processingThread: Thread? = null
    private val bleDecoder = BleDecoder()
    private val airCatch = AirCatch()

    private val rawDataBuffer = ByteArray(32 * 1024 * 1024)
    private var writePtr = 0
    private val totalBytesReceived = AtomicLong(0)
    private val totalBytesDropped = AtomicLong(0)
    private var lastProcessedByteCount = 0L
    private val timestampFormat = SimpleDateFormat("HH:mm:ss.SSS", Locale.getDefault())

    private val CHUNK_SIZE = 128 * 2048
    private val OVERLAP_SIZE = 2 * 2048

    val allPackets = Collections.synchronizedList(mutableListOf<PacketInfo>())
    val stats = GlobalStats()
    var airCatchResult: AirCatchResult? = null
    private val groundTruthPackets = mutableMapOf<String, Pair<ByteArray, Long>>()
    private lateinit var bluetoothAdapter: BluetoothAdapter

    private lateinit var fusedLocationClient: FusedLocationProviderClient
    private var locationCallback: LocationCallback? = null
    @Volatile private var lastLocation: Location? = null

    @Volatile private var isDumping = false
    @Volatile private var isDecodingEnabled = true // Enabled by default for consumers
    private var currentDumpFile: File? = null
    private var currentRawDumpFile: File? = null
    private var currentTimestampLogFile: File? = null
    private val dumpChunkCount = AtomicLong(0)

    private val binder = LocalBinder()
    private var callback: ServiceCallback? = null

    private val wakeLock: PowerManager.WakeLock by lazy {
        (getSystemService(Context.POWER_SERVICE) as PowerManager).run {
            newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "SnifferApp::ServiceWakeLock")
        }
    }

    private val usbReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.action) {
                UsbManager.ACTION_USB_DEVICE_ATTACHED -> {
                    tryReconnect()
                }
                UsbManager.ACTION_USB_DEVICE_DETACHED -> {
                    val device: UsbDevice? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        intent.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice::class.java)
                    } else {
                        @Suppress("DEPRECATION")
                        intent.getParcelableExtra(UsbManager.EXTRA_DEVICE)
                    }
                    if (device != null && usbInterface?.let { it.id == device.getInterface(0).id } == true) {
                        stopUsbThreads()
                    }
                }
                ACTION_USB_PERMISSION -> {
                    val device: UsbDevice? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        intent.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice::class.java)
                    } else {
                        @Suppress("DEPRECATION")
                        intent.getParcelableExtra(UsbManager.EXTRA_DEVICE)
                    }
                    if (intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)) {
                        device?.let { startSniffing(it) }
                    }
                }
            }
        }
    }

    interface ServiceCallback {
        fun onDataUpdated()
        fun onStatusUpdated(status: String)
        fun onDumpStatusChanged(isDumping: Boolean, fileName: String?)
        fun onDecodingStatusChanged(isEnabled: Boolean)
    }

    inner class LocalBinder : Binder() {
        fun getService(): SnifferService = this@SnifferService
    }

    override fun onBind(intent: Intent): IBinder = binder

    fun setCallback(callback: ServiceCallback?) {
        this.callback = callback
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        loadState()
        
        // Always try to start in foreground
        val notification = getNotification("Searching for tags...")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, 
                ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE or ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION)
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }

        val bluetoothManager = getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        bluetoothAdapter = bluetoothManager.adapter
        fusedLocationClient = LocationServices.getFusedLocationProviderClient(this)
        
        val filter = IntentFilter().apply {
            addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED)
            addAction(UsbManager.ACTION_USB_DEVICE_DETACHED)
            addAction(ACTION_USB_PERMISSION)
        }
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(usbReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(usbReceiver, filter)
        }
        
        startLocationUpdates()
        
        // Auto-start sniffing if device is already connected
        tryReconnect()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (!isReceiving) {
            tryReconnect()
        }
        startLocationUpdates()
        return START_STICKY
    }

    private fun isSnifferDesired(): Boolean {
        return true // Always desired for consumer version
    }

    private fun saveState() {
        val prefs = getSharedPreferences("sniffer_prefs", Context.MODE_PRIVATE)
        prefs.edit().apply {
            putBoolean("is_decoding_enabled", isDecodingEnabled)
            apply()
        }
    }

    private fun loadState() {
        val prefs = getSharedPreferences("sniffer_prefs", Context.MODE_PRIVATE)
        isDecodingEnabled = prefs.getBoolean("is_decoding_enabled", true)
    }

    fun isSnifferDesiredState(): Boolean = true

    private fun tryReconnect() {
        val usbManager = getSystemService(Context.USB_SERVICE) as UsbManager
        val device = usbManager.deviceList.values.firstOrNull { it.vendorId == 0x303A || it.vendorId == 0x1234 }
        if (device != null) {
            if (usbManager.hasPermission(device)) {
                startSniffing(device)
            } else {
                val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) PendingIntent.FLAG_IMMUTABLE else 0
                val permissionIntent = PendingIntent.getBroadcast(this, 0, Intent(ACTION_USB_PERMISSION), flags)
                usbManager.requestPermission(device, permissionIntent)
            }
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val serviceChannel = NotificationChannel(
                CHANNEL_ID,
                "AirCatch Monitoring Service",
                NotificationManager.IMPORTANCE_LOW
            )
            val alarmChannel = NotificationChannel(
                ALARM_CHANNEL_ID,
                "Adversary Detection Alerts",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                enableLights(true)
                enableVibration(true)
                lockscreenVisibility = Notification.VISIBILITY_PUBLIC
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(serviceChannel)
            manager?.createNotificationChannel(alarmChannel)
        }
    }

    private fun getNotification(text: String): Notification {
        val notificationIntent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, notificationIntent,
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) PendingIntent.FLAG_IMMUTABLE else 0
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("AirCatch Active")
            .setContentText(text)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String) {
        val notification = getNotification(text)
        val manager = getSystemService(NotificationManager::class.java)
        manager?.notify(NOTIFICATION_ID, notification)
    }

    private fun showAdversaryNotification() {
        val notificationIntent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, notificationIntent,
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) PendingIntent.FLAG_IMMUTABLE else 0
        )

        val notification = NotificationCompat.Builder(this, ALARM_CHANNEL_ID)
            .setContentTitle("⚠️ Adversary Detected")
            .setContentText("Possible tracking adversary detected nearby!")
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentIntent(pendingIntent)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setDefaults(Notification.DEFAULT_ALL)
            .setVibrate(longArrayOf(0, 500, 200, 500))
            .setAutoCancel(true)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .build()

        val manager = getSystemService(NotificationManager::class.java)
        manager?.notify(ALARM_NOTIFICATION_ID, notification)
    }

    fun startSniffing(device: UsbDevice) {
        if (isReceiving) return
        saveState()

        val usbManager = getSystemService(Context.USB_SERVICE) as UsbManager
        val connection = usbManager.openDevice(device) ?: return

        var dataInterface: UsbInterface? = null
        var bulkIn: UsbEndpoint? = null

        for (i in 0 until device.interfaceCount) {
            val iface = device.getInterface(i)
            for (j in 0 until iface.endpointCount) {
                val ep = iface.getEndpoint(j)
                if (ep.type == UsbConstants.USB_ENDPOINT_XFER_BULK && ep.direction == UsbConstants.USB_DIR_IN) {
                    dataInterface = iface
                    bulkIn = ep
                    if (i > 0) break
                }
            }
            if (bulkIn != null && i > 0) break
        }

        if (dataInterface == null || bulkIn == null || !connection.claimInterface(dataInterface, true)) {
            connection.close()
            return
        }

        connection.controlTransfer(0x21, 0x22, 0x03, 0, null, 0, 1000)
        val lineCoding = byteArrayOf(
            (115200 and 0xFF).toByte(),
            (115200 shr 8 and 0xFF).toByte(),
            (115200 shr 16 and 0xFF).toByte(),
            (115200 shr 24 and 0xFF).toByte(),
            0x00, 0x00, 0x08
        )
        connection.controlTransfer(0x21, 0x20, 0, 0, lineCoding, lineCoding.size, 1000)

        usbConnection = connection
        usbInterface = dataInterface
        usbEndpoint = bulkIn
        isReceiving = true

        lastProcessedByteCount = 0
        totalBytesReceived.set(0)
        totalBytesDropped.set(0)
        writePtr = 0

        if (!wakeLock.isHeld) try { wakeLock.acquire() } catch (e: Exception) {}
        updateNotification("Monitoring tags...")

        try { bluetoothAdapter.bluetoothLeScanner?.startScan(scanCallback) } catch (e: Exception) {}

        receiveThread = thread(name = "USBReceive", priority = Thread.MAX_PRIORITY) {
            val epInternal = usbEndpoint
            if (epInternal == null) {
                isReceiving = false
                return@thread
            }
            val buffer = ByteArray(epInternal.maxPacketSize * 32)
            while (isReceiving) {
                val conn = usbConnection ?: break
                val ep = usbEndpoint ?: break
                val len = conn.bulkTransfer(ep, buffer, buffer.size, 1000)
                if (len > 0) {
                    val spaceAtEnd = rawDataBuffer.size - writePtr
                    if (len <= spaceAtEnd) {
                        System.arraycopy(buffer, 0, rawDataBuffer, writePtr, len)
                    } else {
                        System.arraycopy(buffer, 0, rawDataBuffer, writePtr, spaceAtEnd)
                        System.arraycopy(buffer, buffer.size - (len - spaceAtEnd), rawDataBuffer, 0, len - spaceAtEnd)
                    }
                    writePtr = (writePtr + len) % rawDataBuffer.size
                    totalBytesReceived.addAndGet(len.toLong())
                } else if (len < 0) {
                    break
                }
            }
            if (isReceiving) {
                Handler(Looper.getMainLooper()).post { 
                    callback?.onStatusUpdated("Waiting for device...")
                    updateNotification("Ready to monitor")
                }
                stopUsbThreadsInternal()
            }
        }

        processingThread = thread(name = "BLEProcess") {
            var lastAirCatchTime = 0L
            while (isReceiving) {
                val currentReceived = totalBytesReceived.get()
                val backlog = currentReceived - lastProcessedByteCount

                if (backlog > rawDataBuffer.size - CHUNK_SIZE - OVERLAP_SIZE) {
                    val dropAmount = ((backlog - (rawDataBuffer.size / 2)) / CHUNK_SIZE) * CHUNK_SIZE
                    if (dropAmount > 0) {
                        lastProcessedByteCount += dropAmount
                        totalBytesDropped.addAndGet(dropAmount)
                    }
                }

                if (currentReceived - lastProcessedByteCount >= CHUNK_SIZE) {
                    val chunkTimestampMs = System.currentTimeMillis()

                    stats.totalBytes = currentReceived
                    stats.droppedBytes = totalBytesDropped.get()

                    if (isDecodingEnabled) {
                        val processWindow = CHUNK_SIZE + OVERLAP_SIZE
                        val linear = ByteArray(processWindow)
                        val startOffsetInBuf = ((lastProcessedByteCount - OVERLAP_SIZE + rawDataBuffer.size) % rawDataBuffer.size).toInt()
                        val spaceAtEnd = rawDataBuffer.size - startOffsetInBuf
                        if (processWindow <= spaceAtEnd) {
                            System.arraycopy(rawDataBuffer, startOffsetInBuf, linear, 0, processWindow)
                        } else {
                            System.arraycopy(rawDataBuffer, startOffsetInBuf, linear, 0, spaceAtEnd)
                            System.arraycopy(rawDataBuffer, 0, linear, spaceAtEnd, processWindow - spaceAtEnd)
                        }

                        val found = bleDecoder.findPackets(linear)
                        if (found.isNotEmpty()) {
                            val nowMs = System.currentTimeMillis()
                            val timestamp = timestampFormat.format(Date(nowMs))

                            for (p in found) {
                                val byteOffsetInChunk = p.sampleOffset * 4
                                if (byteOffsetInChunk >= OVERLAP_SIZE && byteOffsetInChunk < (CHUNK_SIZE + OVERLAP_SIZE)) {
                                    val payloadHex = p.payload.joinToString("") { "%02X".format(it.toInt() and 0xFF) }
                                    var isGTMatched = false
                                    val gtEntry = groundTruthPackets[p.advA]
                                    if (gtEntry != null && nowMs - gtEntry.second < 2000) {
                                        val gtHex = gtEntry.first.joinToString("") { "%02X".format(it.toInt() and 0xFF) }
                                        if (gtHex.contains(payloadHex)) isGTMatched = true
                                    }

                                    val info = PacketInfo(
                                        packetNumber = allPackets.size + 1,
                                        timestamp = timestamp,
                                        timestampMs = nowMs,
                                        decodedPacket = p,
                                        isGroundTruth = isGTMatched
                                    )
                                    allPackets.add(0, info)
                                    if (allPackets.size > 5000) allPackets.removeAt(allPackets.size - 1)

                                    val s = stats.ecosystemStats[p.tagInfo.family] ?: TagStats()
                                    s.total++
                                    if (p.crcOk) s.crcOk++
                                }
                            }

                            if (nowMs - lastAirCatchTime > 15000) {
                                val packetsForAirCatch = synchronized(allPackets) { allPackets.toList() }
                                val result = airCatch.processPackets(packetsForAirCatch)
                                
                                if (result.confirmed && (airCatchResult == null || !airCatchResult!!.confirmed)) {
                                    showAdversaryNotification()
                                }
                                airCatchResult = result
                                lastAirCatchTime = nowMs
                            }
                        }
                    }

                    Handler(Looper.getMainLooper()).post { 
                        callback?.onDataUpdated()
                    }
                    lastProcessedByteCount += CHUNK_SIZE
                } else {
                    try { Thread.sleep(5) } catch (e: Exception) {}
                }
            }
        }
    }

    private fun stopUsbThreadsInternal() {
        isReceiving = false
        receiveThread = null
        processingThread = null
        usbInterface?.let { usbConnection?.releaseInterface(it) }
        usbConnection?.close()
        usbConnection = null
        usbInterface = null
        usbEndpoint = null
        try { bluetoothAdapter.bluetoothLeScanner?.stopScan(scanCallback) } catch (e: Exception) {}
        if (wakeLock.isHeld) try { wakeLock.release() } catch (e: Exception) {}
    }

    private fun stopUsbThreads() {
        stopUsbThreadsInternal()
    }

    fun stopSniffing() {
        isDumping = false
        saveState()
        stopUsbThreads()
        updateNotification("Ready to monitor")
        callback?.onStatusUpdated("Disconnected")
    }

    fun toggleDecoding() {
        isDecodingEnabled = !isDecodingEnabled
        saveState()
        callback?.onDecodingStatusChanged(isDecodingEnabled)
    }

    fun isCurrentlyDecoding(): Boolean = isDecodingEnabled
    fun isCurrentlyDumping(): Boolean = isDumping
    fun isCurrentlyReceiving(): Boolean = isReceiving

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val deviceAddress = result.device.address
            val scanRecord = result.scanRecord?.bytes ?: return
            groundTruthPackets[deviceAddress] = Pair(scanRecord, System.currentTimeMillis())
        }
    }

    private fun startLocationUpdates() {
        if (!::fusedLocationClient.isInitialized) return
        val perm = ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION)
        if (perm != PackageManager.PERMISSION_GRANTED) return

        if (locationCallback == null) {
            locationCallback = object : LocationCallback() {
                override fun onLocationResult(result: LocationResult) {
                    val bestLoc = result.locations.minByOrNull { it.accuracy } ?: result.lastLocation
                    bestLoc?.let { lastLocation = it }
                }
            }
            
            val request = LocationRequest.Builder(Priority.PRIORITY_HIGH_ACCURACY, 1000L)
                .setMinUpdateIntervalMillis(500L)
                .setWaitForAccurateLocation(true)
                .build()

            try {
                fusedLocationClient.requestLocationUpdates(request, locationCallback as LocationCallback, Looper.getMainLooper())
                fusedLocationClient.getCurrentLocation(Priority.PRIORITY_HIGH_ACCURACY, null)
                    .addOnSuccessListener { loc -> if (loc != null) lastLocation = loc }
            } catch (e: Exception) {
                Log.e("SnifferService", "Error starting location updates", e)
            }
        }
    }

    private fun stopLocationUpdates() {
        if (!::fusedLocationClient.isInitialized) return
        val cb = locationCallback ?: return
        try {
            fusedLocationClient.removeLocationUpdates(cb)
        } catch (e: Exception) {}
        locationCallback = null
    }

    override fun onDestroy() {
        stopLocationUpdates()
        stopUsbThreads()
        try {
            unregisterReceiver(usbReceiver)
        } catch (e: Exception) {}
        super.onDestroy()
    }
}
