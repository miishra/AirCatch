package com.example.myapplication

import java.util.*
import kotlin.math.*

class AirCatch {
    companion object {
        const val WINDOW_S = 120
        
        // Density safety
        const val R_MIN = 0.15
        const val EPS = 1e-9
        
        // Strict decision thresholds
        const val DUR_MIN = 1700
        const val UNIQUE_MACS_MIN = 2
        const val DENSITY_MIN = 1.15
        
        // Core density settings
        const val CORE_FRAC_Q = 0.2
        const val CORE_MIN_PTS = 3
        const val CORE_RADIUS_STD_K = 1.5
        
        val ADV_PAYLOAD_TAGS = listOf("4C001219FC", "4C001219FD", "4C001219FE", "4C001219FF")
    }

    data class Segment(
        val segId: Int,
        val eco: String,
        val devId: String,
        val tStart: Long,
        val tEnd: Long,
        val nPackets: Int,
        val keySet: Set<String>,
        val cfoStats: Map<String, Float>,
        val gtAdv: Boolean,
        val advPackets: Int,
        var features: DoubleArray = doubleArrayOf()
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as Segment
            if (segId != other.segId) return false
            if (eco != other.eco) return false
            if (devId != other.devId) return false
            return true
        }

        override fun hashCode(): Int {
            var result = segId
            result = 31 * result + eco.hashCode()
            result = 31 * result + devId.hashCode()
            return result
        }
    }

    data class ClusterSummary(
        val clusterId: Int,
        val eco: String,
        val segments: Int,
        val durationCov: Double,
        val persistenceS: Double,
        val uniqueMacs: Int,
        val coreMacDensityScaled: Double,
        val advMacPct: Double,
        val confirmed: Boolean
    )

    fun processPackets(packets: List<PacketInfo>): AirCatchResult {
        val now = System.currentTimeMillis()
        val validPackets = packets.filter { it.decodedPacket.crcOk }
        
        // 30-second window for consumer display
        val recentWindowMs = 30000L
        val uniqueRecentTags = validPackets
            .filter { now - it.timestampMs <= recentWindowMs && it.decodedPacket.advA != null }
            .groupBy { it.decodedPacket.advA!! }
            .map { (mac, pList) ->
                ConsumerTagInfo(
                    mac = mac,
                    type = pList.first().decodedPacket.tagInfo.family,
                    lastSeenMs = pList.maxOf { it.timestampMs }
                )
            }
            .sortedByDescending { it.lastSeenMs }

        if (validPackets.isEmpty()) {
            return AirCatchResult("No tags detected yet.", false, now, uniqueRecentTags)
        }

        // --- Per-Device Segmentation ---
        val segMap = mutableMapOf<String, MutableList<PacketInfo>>()
        for (p in validPackets) {
            val segId = ((p.timestampMs / 1000) / WINDOW_S).toInt()
            val eco = p.decodedPacket.tagInfo.family
            val devId = p.decodedPacket.tagInfo.privId ?: p.decodedPacket.advA ?: "UNKNOWN"
            val key = "$segId|$eco|$devId"
            segMap.getOrPut(key) { mutableListOf() }.add(p)
        }

        val segments = mutableListOf<Segment>()
        for ((key, group) in segMap) {
            val parts = key.split("|")
            val segId = parts[0].toInt()
            val eco = parts[1]
            val devId = parts[2]

            val tStart = group.minOf { it.timestampMs }
            val tEnd = group.maxOf { it.timestampMs }
            
            var advPacketsCount = 0
            val keys = mutableSetOf<String>()
            for (p in group) {
                val hx = p.decodedPacket.payload.toHex().uppercase()
                if (ADV_PAYLOAD_TAGS.any { hx.contains(it) }) advPacketsCount++
                if (hx.length >= 32) keys.add(hx.take(32))
            }
            
            val gtAdv = group.any { it.isGroundTruth }
            val cfoStats = computeCfoStats(group)
            segments.add(Segment(segId, eco, devId, tStart, tEnd, group.size, keys, cfoStats, gtAdv, advPacketsCount))
        }

        val clusterSummaries = runClustering(segments)
        val anyConfirmed = clusterSummaries.any { it.confirmed }

        val summary = if (anyConfirmed) {
            "⚠️ ALERT: A tracking adversary has been detected."
        } else if (uniqueRecentTags.isNotEmpty()) {
            "Found ${uniqueRecentTags.size} unique tags nearby in the last 30s."
        } else {
            "Monitoring... No suspicious activity detected."
        }

        return AirCatchResult(summary, anyConfirmed, now, uniqueRecentTags)
    }

    private fun computeCfoStats(group: List<PacketInfo>): Map<String, Float> {
        val stats = mutableMapOf<String, Float>()
        val cols = listOf("CFO", "CFO_00", "CFO_11", "CFO_10", "CFO_01")
        for (col in cols) {
            val vals = group.mapNotNull { 
                when(col) {
                    "CFO" -> it.decodedPacket.cfoHz
                    "CFO_00" -> it.decodedPacket.cfoDetailed?.cfo00
                    "CFO_11" -> it.decodedPacket.cfoDetailed?.cfo11
                    "CFO_10" -> it.decodedPacket.cfoDetailed?.cfo10
                    "CFO_01" -> it.decodedPacket.cfoDetailed?.cfo01
                    else -> null
                }
            }.filter { !it.isNaN() }
            if (vals.isNotEmpty()) stats[col] = vals.average().toFloat()
        }
        return stats
    }

    private fun runClustering(segments: List<Segment>): List<ClusterSummary> {
        if (segments.isEmpty()) return emptyList()
        
        // Group by ecosystem for per-dev_type clustering
        return segments.groupBy { it.eco }.flatMap { (eco, ecoSegs) ->
            if (ecoSegs.size < 3) return@flatMap emptyList<ClusterSummary>()
            
            val cfoKeys = listOf("CFO", "CFO_00", "CFO_11", "CFO_10", "CFO_01")
            
            // 1. Basic CFO features
            val baseFeatures = Array(ecoSegs.size) { i ->
                val s = ecoSegs[i]
                DoubleArray(cfoKeys.size) { j -> s.cfoStats[cfoKeys[j]]?.toDouble() ?: 0.0 }
            }
            
            // Standardize base features
            for (j in cfoKeys.indices) {
                val col = DoubleArray(ecoSegs.size) { i -> baseFeatures[i][j] }
                val avg = col.average()
                val std = sqrt(col.map { (it - avg).pow(2) }.average()).coerceAtLeast(1e-9)
                for (i in ecoSegs.indices) baseFeatures[i][j] = (baseFeatures[i][j] - avg) / std
            }

            // 2. Add packet support feature (log-compressed and standardized)
            val logPackets = ecoSegs.map { ln1p(it.nPackets.toDouble()) }
            val lpAvg = if (logPackets.isNotEmpty()) logPackets.average() else 0.0
            val lpStd = if (logPackets.size > 1) sqrt(logPackets.map { (it - lpAvg).pow(2) }.average()).coerceAtLeast(1e-9) else 1.0
            val packetFeatures = logPackets.map { (it - lpAvg) / lpStd * 3.0 }

            // 3. Add CFO robust spread features (L1/L2 dev from median)
            val medians = DoubleArray(cfoKeys.size) { j ->
                val col = ecoSegs.map { it.cfoStats[cfoKeys[j]]?.toDouble() ?: 0.0 }.sorted()
                if (col.isEmpty()) 0.0
                else if (col.size % 2 == 0) (col[col.size/2] + col[col.size/2-1]) / 2.0 
                else col[col.size/2]
            }
            
            val l2Devs = ecoSegs.map { s ->
                var sum = 0.0
                for (j in cfoKeys.indices) sum += ( (s.cfoStats[cfoKeys[j]]?.toDouble() ?: 0.0) - medians[j] ).pow(2)
                sqrt(sum)
            }
            val l2Avg = if (l2Devs.isNotEmpty()) l2Devs.average() else 0.0
            val l2Std = if (l2Devs.size > 1) sqrt(l2Devs.map { (it - l2Avg).pow(2) }.average()).coerceAtLeast(1e-9) else 1.0
            val l2Features = l2Devs.map { (it - l2Avg) / l2Std }

            // Combine all features
            val finalFeatures = Array(ecoSegs.size) { i ->
                baseFeatures[i] + doubleArrayOf(packetFeatures[i], l2Features[i])
            }

            // Simplified Agglomerative Clustering
            val clusters = ecoSegs.mapIndexed { index, _ -> mutableListOf(index) }.toMutableList()
            val kTarget = (ecoSegs.size / 5).coerceIn(2, 10).coerceAtMost(ecoSegs.size - 1)
            
            while (clusters.size > kTarget) {
                var minDist = Double.MAX_VALUE
                var pair = Pair(-1, -1)
                for (i in 0 until clusters.size) {
                    for (j in i + 1 until clusters.size) {
                        val d = clusterDist(clusters[i], clusters[j], finalFeatures)
                        if (d < minDist) { minDist = d; pair = Pair(i, j) }
                    }
                }
                if (pair.first != -1) {
                    clusters[pair.first].addAll(clusters[pair.second])
                    clusters.removeAt(pair.second)
                } else break
            }

            clusters.mapIndexed { cIdx, indices ->
                val cSegs = indices.map { ecoSegs[it] }
                val persistenceS = (cSegs.maxOf { it.tEnd } - cSegs.minOf { it.tStart }) / 1000.0
                val durationCov = cSegs.map { it.segId }.distinct().size.toDouble() * WINDOW_S
                val macs = cSegs.map { it.devId }.distinct()
                
                // Core Density Calculation (only on CFO space as per Python logic)
                val coreK = max(CORE_MIN_PTS, ceil(CORE_FRAC_Q * cSegs.size).toInt()).coerceAtMost(cSegs.size)
                val distances = Array(cSegs.size) { i ->
                    DoubleArray(cSegs.size) { j -> euclideanDist(baseFeatures[indices[i]], baseFeatures[indices[j]]) }
                }
                val medoidIdx = distances.indices.minByOrNull { i -> distances[i].sum() } ?: 0
                val distsToMedoid = distances[medoidIdx].sortedArray()
                val coreDists = distsToMedoid.sliceArray(0 until coreK)
                
                val coreRadius = if (coreK > 1) {
                    val avg = coreDists.average()
                    val std = sqrt(coreDists.map { (it - avg).pow(2) }.average())
                    CORE_RADIUS_STD_K * std
                } else 0.0
                
                val radiusClamped = max(coreRadius, R_MIN)
                val macDivFull = macs.size.toDouble() / cSegs.size
                val coreDensity = if (macs.size >= 2 && cSegs.size >= CORE_MIN_PTS) {
                    macDivFull / (radiusClamped + EPS)
                } else 0.0

                val advMacsInCluster = cSegs.count { it.advPackets > 0 }
                val advMacPct = advMacsInCluster.toDouble() / macs.size.coerceAtLeast(1)

                val confirmed = persistenceS >= DUR_MIN && 
                                macs.size >= UNIQUE_MACS_MIN && 
                                coreDensity >= DENSITY_MIN

                ClusterSummary(cIdx, eco, cSegs.size, durationCov, persistenceS, macs.size, coreDensity, advMacPct, confirmed)
            }
        }
    }

    private fun clusterDist(c1: List<Int>, c2: List<Int>, features: Array<DoubleArray>): Double {
        var sum = 0.0
        for (i in c1) {
            for (j in c2) {
                sum += euclideanDist(features[i], features[j])
            }
        }
        return sum / (c1.size * c2.size)
    }

    private fun euclideanDist(f1: DoubleArray, f2: DoubleArray): Double {
        var sum = 0.0
        for (i in f1.indices) sum += (f1[i] - f2[i]).pow(2)
        return sqrt(sum)
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02X".format(it.toInt() and 0xFF) }
}
