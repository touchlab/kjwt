package co.touchlab.kjwt.hardware.internal

/** Returns (length, bytesConsumed) for a DER length field. */
internal fun readDerLength(bytes: ByteArray, pos: Int): Pair<Int, Int> {
    val first = bytes[pos].toInt() and 0xFF
    return if (first < 0x80) {
        Pair(first, 1)
    } else {
        val numOctets = first and 0x7F
        var len = 0
        for (i in 0 until numOctets) {
            len = (len shl 8) or (bytes[pos + 1 + i].toInt() and 0xFF)
        }
        Pair(len, 1 + numOctets)
    }
}

/**
 * Converts a DER-encoded ECDSA signature (as returned by Android Keystore or Apple Security
 * framework) to the P1363 (IEEE 1363) raw `r || s` format required by JWT.
 */
internal fun ByteArray.ecdsaDerToP1363(coordinateLen: Int): ByteArray {
    var pos = 0
    // SEQUENCE tag
    require(this[pos++] == 0x30.toByte()) { "Expected SEQUENCE tag 0x30" }
    // Skip SEQUENCE length
    val (_, seqLenBytes) = readDerLength(this, pos)
    pos += seqLenBytes
    // r INTEGER
    require(this[pos++] == 0x02.toByte()) { "Expected INTEGER tag 0x02 for r" }
    val (rLen, rLenBytes) = readDerLength(this, pos)
    pos += rLenBytes
    val rBytes = copyOfRange(pos, pos + rLen)
    pos += rLen
    // s INTEGER
    require(this[pos++] == 0x02.toByte()) { "Expected INTEGER tag 0x02 for s" }
    val (sLen, sLenBytes) = readDerLength(this, pos)
    pos += sLenBytes
    val sBytes = copyOfRange(pos, pos + sLen)

    return stripAndPad(rBytes, coordinateLen) + stripAndPad(sBytes, coordinateLen)
}

/**
 * Converts a P1363 (raw `r || s`) ECDSA signature as used by JWT to the DER-encoded format
 * expected by Android Keystore and Apple Security framework verification APIs.
 */
internal fun ByteArray.ecdsaP1363ToDer(coordinateLen: Int): ByteArray {
    val r = copyOf(coordinateLen)
    val s = copyOfRange(coordinateLen, coordinateLen * 2)

    fun encodeDerInteger(raw: ByteArray): ByteArray {
        var start = 0
        while (start < raw.size - 1 && raw[start] == 0x00.toByte()) start++
        val stripped = raw.copyOfRange(start, raw.size)
        val withSign = if (stripped[0].toInt() and 0x80 != 0) byteArrayOf(0x00) + stripped else stripped
        return byteArrayOf(0x02.toByte(), withSign.size.toByte()) + withSign
    }

    val rDer = encodeDerInteger(r)
    val sDer = encodeDerInteger(s)
    val body = rDer + sDer

    val seqLen = if (body.size < 0x80) {
        byteArrayOf(body.size.toByte())
    } else {
        byteArrayOf(0x81.toByte(), body.size.toByte())
    }

    return byteArrayOf(0x30.toByte()) + seqLen + body
}

/** Strips leading 0x00 DER sign bytes and zero-pads to [targetLen] on the left. */
private fun stripAndPad(bytes: ByteArray, targetLen: Int): ByteArray {
    var start = 0
    while (start < bytes.size - 1 && bytes[start] == 0x00.toByte()) start++
    val stripped = bytes.copyOfRange(start, bytes.size)
    return ByteArray(maxOf(0, targetLen - stripped.size)) + stripped
}
