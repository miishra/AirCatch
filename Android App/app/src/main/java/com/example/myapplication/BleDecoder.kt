package com.example.myapplication

import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.Future
import kotlin.math.*

class BleDecoder {
    companion object {
        const val FS_IN = 1344102
        const val FS_OUT = 16000000.0
        const val SYMBOL_RATE = 1000000.0
        const val SPS = (FS_OUT / SYMBOL_RATE).toInt()
        const val AA_ADV = 0x8E89BED6L

        val AA_BITS = aaBitsOnAir(AA_ADV)
        val TARGET_AA_INT = run {
            var v = 0
            for (i in 0 until 32) v = (v shl 1) or AA_BITS[i]
            v
        }
        val TARGET_PRE_BYTE = if (AA_BITS[0] == 0) 0x55 else 0xAA

        // Session-based key for MAC obfuscation
        private val SESSION_SALT = UUID.randomUUID().toString()

        fun obfuscateMac(mac: String): String {
            return try {
                val md = MessageDigest.getInstance("SHA-256")
                val hash = md.digest((mac + SESSION_SALT).toByteArray())
                // Return first 12 chars of hex hash, formatted like a MAC for visual consistency
                hash.joinToString("") { "%02X".format(it.toInt() and 0xFF) }.take(12)
                    .chunked(2).joinToString(":")
            } catch (e: Exception) {
                "XX:XX:XX:XX:XX:XX"
            }
        }

        fun aaBitsOnAir(aa: Long): IntArray {
            val bits = IntArray(32)
            for (i in 0 until 4) {
                val byte = ((aa ushr (i * 8)) and 0xFFL).toInt()
                for (j in 0 until 8) bits[i * 8 + j] = ((byte ushr j) and 1)
            }
            return bits
        }

        fun swapBits8(v: Int): Int {
            var x = (v and 0xFF)
            var y = 0
            for (i in 0 until 8) {
                y = (y shl 1) or (x and 1)
                x = (x ushr 1)
            }
            return y
        }

        fun dewhiten(chan: Int, data: ByteArray) {
            var lfsr = ((swapBits8(chan) or 0x02) and 0xFF)
            for (i in data.indices) {
                var b = (data[i].toInt() and 0xFF)
                var mask = 0x80
                while (mask != 0) {
                    if ((lfsr and 0x80) != 0) {
                        lfsr = (lfsr xor 0x11)
                        b = (b xor mask)
                    }
                    lfsr = ((lfsr shl 1) and 0xFF)
                    mask = (mask ushr 1)
                }
                data[i] = b.toByte()
            }
        }

        fun reverseCrc(data: ByteArray): Int {
            var dst0 = 0x55; var dst1 = 0x55; var dst2 = 0x55
            for (byte in data) {
                var d = swapBits8(byte.toInt() and 0xFF)
                for (i in 0 until 8) {
                    val t = ((dst0 ushr 7) and 1)
                    val nextDst0 = (((dst0 shl 1) and 0xFF) or ((dst1 ushr 7) and 1))
                    val nextDst1 = (((dst1 shl 1) and 0xFF) or ((dst2 ushr 7) and 1))
                    val nextDst2 = ((dst2 shl 1) and 0xFF)
                    dst0 = nextDst0
                    dst1 = nextDst1
                    dst2 = nextDst2
                    if (t != (d and 1)) {
                        dst2 = (dst2 xor 0x5B)
                        dst1 = (dst1 xor 0x06)
                    }
                    d = (d ushr 1)
                }
            }
            return (((dst0 shl 16) or (dst1 shl 8) or dst2) and 0xFFFFFF)
        }
    }

    private val numCores = maxOf(1, Runtime.getRuntime().availableProcessors() - 1)
    private val executor = Executors.newFixedThreadPool(numCores)

    private var iIn = FloatArray(1)
    private var qIn = FloatArray(1)
    private var iOut = FloatArray(1)
    private var qOut = FloatArray(1)
    private var fastDemod = FloatArray(1)

    data class CfoDetailed(
        val total: Float,
        val cfo00: Float,
        val cfo11: Float,
        val cfo10: Float,
        val cfo01: Float,
        val n00: Int,
        val n11: Int,
        val n10: Int,
        val n01: Int
    )

    data class TagInfo(
        val family: String,
        val isAirtag: Boolean,
        val isTagEcosystem: Boolean,
        val reason: String,
        val privId: String? = null
    )

    data class DecodedPacket(
        val typeName: String,
        val pduType: Int,
        val length: Int,
        val txAdd: Int,
        val rxAdd: Int,
        val payload: ByteArray,
        val crcOk: Boolean,
        val crcRx: Int,
        val crcCalc: Int,
        val advA: String?,
        val tagInfo: TagInfo,
        val aaCorr: Int,
        val preCorr: Int,
        val aaPos: Int,
        val phase: Int,
        val polarity: Int,
        val slip: Int,
        val cfoHz: Float,
        val cfoDetailed: CfoDetailed?,
        val hpMsb: ByteArray,
        val crcRxMsb: ByteArray,
        val hpStd: ByteArray,
        var sampleOffset: Int = 0,
        var channel: Int = 37,
        var debugInfo: String? = null
    )

    @Synchronized
    fun findPackets(rawBytes: ByteArray): List<DecodedPacket> {
        val spiChunkSize = 2048
        val numChunks = rawBytes.size / spiChunkSize
        if (numChunks == 0) return emptyList()

        val samplesPerChunk = spiChunkSize / 4
        val numIn = numChunks * samplesPerChunk

        if (iIn.size < numIn) {
            iIn = FloatArray(numIn)
            qIn = FloatArray(numIn)
        }

        for (c in 0 until numChunks) {
            val chunkStart = (c * spiChunkSize)
            val outStart = (c * samplesPerChunk)
            iIn[outStart] = 0f; qIn[outStart] = 0f
            for (s in 1 until samplesPerChunk) {
                val idx = (chunkStart + (s * 4))
                val iVal = (((rawBytes[idx + 1].toInt() and 0xFF) shl 8) or (rawBytes[idx].toInt() and 0xFF))
                val qVal = (((rawBytes[idx + 3].toInt() and 0xFF) shl 8) or (rawBytes[idx + 2].toInt() and 0xFF))
                iIn[outStart + s] = iVal.toShort().toFloat() / 32768f
                qIn[outStart + s] = qVal.toShort().toFloat() / 32768f
            }
        }

        val ratio = (FS_OUT / FS_IN)
        val numOut = (numIn * ratio).toInt()

        if (iOut.size < numOut) {
            iOut = FloatArray(numOut)
            qOut = FloatArray(numOut)
            fastDemod = FloatArray(numOut)
        }

        val invRatio = (1.0 / ratio)
        for (i in 0 until numOut) {
            val pos = (i * invRatio)
            val i1 = pos.toInt()
            val i2 = minOf(i1 + 1, numIn - 1)
            val frac = (pos - i1).toFloat()
            iOut[i] = ((iIn[i1] * (1f - frac)) + (iIn[i2] * frac))
            qOut[i] = ((qIn[i1] * (1f - frac)) + (qIn[i2] * frac))
        }

        for (i in 0 until numOut - 1) {
            val det = ((qOut[i + 1] * iOut[i]) - (iOut[i + 1] * qOut[i]))
            val dot = ((qOut[i + 1] * qOut[i]) + (iOut[i + 1] * qOut[i]))
            fastDemod[i] = atan2(det, dot)
        }

        val futures = mutableListOf<java.util.concurrent.Future<List<Pair<Int, DecodedPacket>>>>()
        val chunkSize = (numOut / numCores)
        val overlapSamples = (1000 * SPS)

        val sharedI = iOut
        val sharedQ = qOut
        val sharedDemod = fastDemod

        for (c in 0 until numCores) {
            val start = (c * chunkSize)
            val end = if (c == numCores - 1) numOut - 1 else ((c + 1) * chunkSize + overlapSamples)
            if (start >= numOut - 1) break

            futures.add(executor.submit<List<Pair<Int, DecodedPacket>>> {
                val candidates = mutableListOf<Pair<Int, DecodedPacket>>()
                val polarity = -1
                for (phase in 0 until SPS) {
                    var slidingWin = 0L
                    var i = 0
                    val initialIdx = (start + ((phase - (start % SPS) + SPS) % SPS))
                    var idx = initialIdx
                    while (idx + SPS < end && (idx + SPS) < sharedDemod.size) {
                        var symDet = 0f
                        for (s in 0 until SPS) symDet += sharedDemod[idx + s]
                        val bit = if ((if (polarity > 0) symDet else -symDet) > 0) 1 else 0
                        slidingWin = ((slidingWin shl 1) or bit.toLong())
                        if (i >= 39) {
                            val currentAA = (slidingWin.toInt())
                            val aaCorr = (32 - Integer.bitCount(currentAA xor TARGET_AA_INT))
                            if (aaCorr >= 28) {
                                val currentPre = ((slidingWin ushr 32).toInt() and 0xFF)
                                val preCorr = (8 - Integer.bitCount(currentPre xor TARGET_PRE_BYTE))
                                if (preCorr >= 7) {
                                    val aaStartIdx = (initialIdx + ((i - 31) * SPS))
                                    if (aaStartIdx >= 0 && (aaStartIdx + (400 * SPS)) < numOut) {
                                        val decoded = decodeFromIQ(sharedI, sharedQ, aaStartIdx, polarity, aaCorr, preCorr, 37, phase, 0, i - 31)
                                        if (decoded != null && decoded.tagInfo.family != "Unknown") {
                                            decoded.sampleOffset = (aaStartIdx / ratio).toInt()
                                            candidates.add(aaStartIdx to decoded)
                                        }
                                    }
                                }
                            }
                        }
                        idx += SPS
                        i++
                    }
                }
                candidates
            })
        }

        val allCandidates = futures.flatMap {
            try { it.get() } catch (e: Exception) { emptyList<Pair<Int, DecodedPacket>>() }
        }.sortedBy { it.first }

        val results = mutableListOf<DecodedPacket>()
        var resIdx = 0
        while (resIdx < allCandidates.size) {
            val (startPos, _) = allCandidates[resIdx]
            val windowLimit = (startPos + (400 * SPS))
            val group = mutableListOf<DecodedPacket>()
            var searchIdx = resIdx
            while (searchIdx < allCandidates.size && allCandidates[searchIdx].first < windowLimit) {
                group.add(allCandidates[searchIdx].second)
                searchIdx++
            }
            if (group.isNotEmpty()) {
                val crcOkGroup = group.filter { it.crcOk }
                val best = if (crcOkGroup.isNotEmpty()) {
                    crcOkGroup.maxBy { it.aaCorr }!!
                } else {
                    group.maxBy { it.aaCorr }!!
                }
                results.add(best)
            }
            resIdx = searchIdx
        }
        return results
    }

    private fun decodeFromIQ(iOut: FloatArray, qOut: FloatArray, aaStartIdx: Int, polarity: Int, aaCorr: Int, preCorr: Int, chan: Int, phase: Int, slip: Int, aaPos: Int): DecodedPacket? {
        val start = (aaStartIdx + (32 * SPS))
        if ((start + (1400 * SPS)) > iOut.size) return null

        val pktBitsSize = ((2 + 37 + 3) * 8)
        val pktFreq = FloatArray(pktBitsSize)
        for (i in 0 until pktBitsSize) {
            val idxStart = start + (i * SPS)
            var accDet = 0f
            var accDot = 0f
            for (s in 0 until SPS) {
                val idx = idxStart + s
                val dot = ((iOut[idx + 1] * iOut[idx]) + (qOut[idx + 1] * qOut[idx]))
                val det = ((qOut[idx + 1] * iOut[idx]) - (iOut[idx + 1] * qOut[idx]))
                accDet += det
                accDot += dot
            }
            pktFreq[i] = atan2(accDet, accDot)
        }

        val hdrBits = IntArray(16)
        for (i in 0 until 16) {
            val f = pktFreq[i]
            hdrBits[i] = if ((if (polarity > 0) f else -f) > 0) 1 else 0
        }
        val hdrMsbWhitened = bitsToBytesMsbFirst(hdrBits)
        val hdrMsb = hdrMsbWhitened.copyOf()
        dewhiten(chan, hdrMsb)

        val h0 = swapBits8(hdrMsb[0].toInt() and 0xFF)
        val h1 = swapBits8(hdrMsb[1].toInt() and 0xFF)
        val pduType = (h0 and 0x0F)
        val txAdd = (h0 ushr 6) and 1
        val rxAdd = (h0 ushr 7) and 1
        val length = (h1 and 0x3F)

        if (length > 37) return null

        val actualPktBitsSize = ((2 + length + 3) * 8)
        val pktBits = IntArray(actualPktBitsSize)
        for (i in 0 until actualPktBitsSize) {
            val f = pktFreq[i]
            pktBits[i] = if ((if (polarity > 0) f else -f) > 0) 1 else 0
        }
        val pktMsb = bitsToBytesMsbFirst(pktBits)
        dewhiten(chan, pktMsb)

        val crcCalc = reverseCrc(pktMsb.copyOfRange(0, 2 + length))
        val b0 = (pktMsb[2 + length].toInt() and 0xFF)
        val b1 = (pktMsb[2 + length + 1].toInt() and 0xFF)
        val b2 = (pktMsb[2 + length + 2].toInt() and 0xFF)
        val crcRx = (((b0 shl 16) or (b1 shl 8) or b2) and 0xFFFFFF)

        val crcOk = (crcCalc == crcRx)
        val hpMsb = pktMsb.copyOfRange(0, 2 + length)
        val crcRxMsb = pktMsb.copyOfRange(2 + length, 2 + length + 3)
        val pktStd = ByteArray(2 + length) { swapBits8(pktMsb[it].toInt() and 0xFF).toByte() }
        val hpStd = pktStd.copyOf()

        val tagInfo = detectTagFamilyExtended(pktStd)
        if (tagInfo.family == "Unknown") return null

        val payload = pktStd.copyOfRange(2, 2 + length)
        val rawAdvA = if (length >= 6) payload.sliceArray(0 until 6).reversedArray().joinToString(":") { "%02X".format(it) } else null
        val advA = rawAdvA?.let { obfuscateMac(it) }

        var cfoDetailed: CfoDetailed? = null
        var overallCfo = 0f
        val winStart = (aaStartIdx - (8 * SPS))
        val winEnd = (aaStartIdx + ((32 + 2 + length) * 8 * SPS))
        if (winStart >= 0 && winEnd < iOut.size - 1) {
            val count = (winEnd - winStart) / SPS
            val samples = FloatArray(count)
            for (i in 0 until count) {
                val idx = winStart + (i * SPS)
                val dot = ((iOut[idx + 1] * iOut[idx]) + (qOut[idx + 1] * qOut[idx]))
                val det = ((qOut[idx + 1] * iOut[idx]) - (iOut[idx + 1] * qOut[idx]))
                samples[i] = atan2(det, dot)
            }
            val sortedSamples = samples.copyOf()
            sortedSamples.sort()
            val lo = (0.10 * count).toInt()
            val hi = (0.90 * count).toInt()
            if (hi > lo) {
                overallCfo = sortedSamples[(lo + hi) / 2] * (FS_OUT.toFloat() / (2f * PI.toFloat()))
            }
            cfoDetailed = calculateCfoDetailed(iOut, qOut, aaStartIdx, polarity, length, overallCfo)
        }

        return DecodedPacket(
            typeName = listOf("ADV_IND", "ADV_DIRECT_IND", "ADV_NONCONN_IND", "SCAN_REQ", "SCAN_RSP", "CONNECT_IND", "ADV_SCAN_IND")[pduType.coerceIn(0, 6)],
            pduType = pduType, length = length, txAdd = txAdd, rxAdd = rxAdd,
            payload = payload, crcOk = crcOk, crcRx = crcRx, crcCalc = crcCalc,
            advA = advA, tagInfo = tagInfo,
            aaCorr = aaCorr, preCorr = preCorr, aaPos = aaPos, phase = phase, polarity = polarity, slip = slip,
            cfoHz = overallCfo, cfoDetailed = cfoDetailed,
            hpMsb = hpMsb, crcRxMsb = crcRxMsb, hpStd = hpStd
        )
    }

    private fun calculateCfoDetailed(iOut: FloatArray, qOut: FloatArray, aaStartIdx: Int, polarity: Int, length: Int, totalCfo: Float): CfoDetailed {
        val bitsCount = 8 + 32 + 16 + length * 8
        val startSample = aaStartIdx - 8 * SPS

        var acc00R = 0.0; var acc00I = 0.0; var n00 = 0
        var acc11R = 0.0; var acc11I = 0.0; var n11 = 0
        var acc10R = 0.0; var acc10I = 0.0; var n10 = 0
        var acc01R = 0.0; var acc01I = 0.0; var n01 = 0

        val bits = IntArray(bitsCount)
        for (i in 0 until bitsCount) {
            val idx = startSample + i * SPS
            if (idx + 1 >= iOut.size) break
            val dot = ((iOut[idx + 1] * iOut[idx]) + (qOut[idx + 1] * qOut[idx]))
            val det = ((qOut[idx + 1] * iOut[idx]) - (iOut[idx + 1] * qOut[idx]))
            bits[i] = if ((if (polarity > 0) det else -det) > 0) 1 else 0
        }

        for (i in 1 until bitsCount) {
            val prevBit = bits[i - 1]
            val currBit = bits[i]
            val idxStart = startSample + i * SPS
            for (s in 0 until SPS) {
                val idx = idxStart + s
                if (idx + 1 >= iOut.size) break
                val dot = ((iOut[idx + 1] * iOut[idx]) + (qOut[idx + 1] * qOut[idx]))
                val det = ((qOut[idx + 1] * iOut[idx]) - (iOut[idx + 1] * qOut[idx]))

                if (prevBit == 0 && currBit == 0) { acc00R += dot; acc00I += det; n00++ }
                else if (prevBit == 1 && currBit == 1) { acc11R += dot; acc11I += det; n11++ }
                else if (prevBit == 1 && currBit == 0) { acc10R += dot; acc10I += det; n10++ }
                else if (prevBit == 0 && currBit == 1) { acc01R += dot; acc01I += det; n01++ }
            }
        }

        fun toHz(r: Double, i: Double, n: Int): Float {
            if (n == 0) return 0f
            return atan2(i, r).toFloat() * (FS_OUT.toFloat() / (2f * PI.toFloat()))
        }

        return CfoDetailed(
            total = totalCfo,
            cfo00 = toHz(acc00R, acc00I, n00),
            cfo11 = toHz(acc11R, acc11I, n11),
            cfo10 = toHz(acc10R, acc10I, n10),
            cfo01 = toHz(acc01R, acc01I, n01),
            n00 = n00, n11 = n11, n10 = n10, n01 = n01
        )
    }

    private fun bitsToBytesMsbFirst(bits: IntArray): ByteArray {
        val out = ByteArray(bits.size / 8)
        for (i in out.indices) {
            var b = 0
            for (k in 0 until 8) b = (b or (bits[(i * 8) + k] shl (7 - k)))
            out[i] = b.toByte()
        }
        return out
    }

    private fun detectTagFamilyExtended(pkt: ByteArray): TagInfo {
        if (pkt.size < 8) return TagInfo("Unknown", false, false, "")
        val payload = pkt.copyOfRange(2, pkt.size)
        val adData = payload.copyOfRange(6, payload.size)
        var pos = 0
        while (pos + 1 < adData.size) {
            val len = (adData[pos].toInt() and 0xFF)
            if (len == 0 || (pos + 1 + len) > adData.size) break
            val adType = (adData[pos + 1].toInt() and 0xFF)
            val data = adData.copyOfRange(pos + 2, pos + 1 + len)
            
            if (adType == 0xFF && data.size >= 4) {
                val compId = ((data[0].toInt() and 0xFF) or ((data[1].toInt() and 0xFF) shl 8))
                if (compId == 0x004C && data.size >= 4) {
                    if (data[2].toInt() and 0xFF == 0x12 && data[3].toInt() and 0xFF == 0x19) {
                        // Check for 'Other' device marker 0x00
                        if (data.size >= 5 && data[4].toInt() and 0xFF == 0x00) {
                            // Skip Apple devices that are not trackers
                        } else {
                            return TagInfo("Apple", true, true, "Apple 0x004C + 0x12 0x19")
                        }
                    }
                }
            }
            if (adType == 0x16 && data.size >= 2) {
                val svcUuid = ((data[0].toInt() and 0xFF) or ((data[1].toInt() and 0xFF) shl 8))
                if (svcUuid == 0xFEAA) {
                    // Check for Connected state 'aafe40'
                    if (data.size >= 3 && data[2].toInt() and 0xFF == 0x40) {
                        // Skip
                    } else {
                        return TagInfo("Google", false, true, "ServiceData UUID 0xFEAA")
                    }
                }
                if (svcUuid == 0xFEED) return TagInfo("Tile", false, true, "ServiceData UUID 0xFEED")
                if (svcUuid == 0xFD5A) {
                    val privId = if (data.size >= 12) {
                        data.copyOfRange(4, 12).joinToString("") { "%02X".format(it.toInt() and 0xFF) }
                    } else null
                    return TagInfo("Samsung", false, true, "ServiceData UUID 0xFD5A", privId)
                }
            }
            pos += (1 + len)
        }
        return TagInfo("Unknown", false, false, "")
    }

    fun shutdown() {
        executor.shutdown()
    }
}
