package com.example.myapplication

import java.util.*

// Data classes for stats
data class TagStats(var total: Int = 0, var crcOk: Int = 0)

data class GlobalStats(
    val ecosystemStats: MutableMap<String, TagStats> = mutableMapOf(
        "Apple" to TagStats(),
        "Google" to TagStats(),
        "Samsung" to TagStats(),
        "Tile" to TagStats()
    ),
    var totalFrames: Int = 0,
    var totalBytes: Long = 0,
    var droppedBytes: Long = 0
)

data class PacketInfo(
    val packetNumber: Int,
    val timestamp: String,
    val timestampMs: Long,
    val decodedPacket: BleDecoder.DecodedPacket,
    val isGroundTruth: Boolean = false
)

data class ConsumerTagInfo(
    val mac: String,
    val type: String,
    val lastSeenMs: Long
)

data class AirCatchResult(
    val summary: String,
    val confirmed: Boolean,
    val lastUpdate: Long,
    val recentTags: List<ConsumerTagInfo> = emptyList()
)
