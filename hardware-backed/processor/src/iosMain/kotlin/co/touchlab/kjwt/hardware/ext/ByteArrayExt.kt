package co.touchlab.kjwt.hardware.ext

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.refTo
import platform.Security.SecRandomCopyBytes
import platform.Security.kSecRandomDefault

internal fun ByteArray.constantTimeEquals(other: ByteArray): Boolean {
    if (size != other.size) return false
    var diff = 0
    for (i in indices) diff = diff or (this[i].toInt() xor other[i].toInt())
    return diff == 0
}


@OptIn(ExperimentalForeignApi::class)
internal fun generateSecureRandomBytes(count: Int): ByteArray {
    val buf = ByteArray(count)
    memScoped {
        SecRandomCopyBytes(kSecRandomDefault, count.convert(), buf.refTo(0))
    }
    return buf
}