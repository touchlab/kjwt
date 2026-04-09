package co.touchlab.kjwt.hardware_testing

import co.touchlab.kjwt.hardware.SecureKeyFactory
import co.touchlab.kjwt.hardware.model.SecureHardwarePreference
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import co.touchlab.kjwt.processor.JwsProcessor
import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.usePinned
import platform.Foundation.NSData
import platform.Foundation.create
import platform.posix.memcpy

@OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
public object HardwareTesting {
    @Throws(IllegalArgumentException::class)
    public fun getSecureSigningKey(
        keyId: String?,
        algorithm: SigningAlgorithm,
        keySizeInBits: Int = 2048,
        secureHardwarePreference: SecureHardwarePreference = SecureHardwarePreference.Preferred,
    ): JwsProcessor = SecureKeyFactory.getOrCreateSecureSigningKey(
        keyId = keyId,
        algorithm = algorithm,
        keySizeInBits = keySizeInBits,
        secureHardwarePreference = secureHardwarePreference
    )

    public fun toKotlinByteArray(data: NSData): ByteArray {
        val size = data.length.toInt()
        val result = ByteArray(size)
        if (size > 0) {
            result.usePinned { pinned ->
                memcpy(pinned.addressOf(0), data.bytes, data.length)
            }
        }
        return result
    }

    public fun toNSData(byteArray: ByteArray): NSData {
        return byteArray.usePinned { pinned ->
            NSData.create(bytes = pinned.addressOf(0), length = byteArray.size.toULong())
        }
    }

    // Algorithm accessors to avoid companion object confusion in Swift
    public val ES256: SigningAlgorithm = SigningAlgorithm.ES256
    public val RS256: SigningAlgorithm = SigningAlgorithm.RS256
    public val HS256: SigningAlgorithm = SigningAlgorithm.HS256
}
