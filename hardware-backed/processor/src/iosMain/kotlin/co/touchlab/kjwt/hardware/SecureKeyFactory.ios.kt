package co.touchlab.kjwt.hardware

import co.touchlab.kjwt.hardware.model.SecureHardwarePreference
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import co.touchlab.kjwt.processor.JwsProcessor

public actual object SecureKeyFactory {
    public actual fun getOrCreateSecureSigningKey(
        keyId: String?,
        algorithm: SigningAlgorithm,
        keySizeInBits: Int,
        secureHardwarePreference: SecureHardwarePreference,
    ): JwsProcessor =
        AppleKeychainSigningKey.getOrCreateInstance(algorithm, keyId, keySizeInBits, secureHardwarePreference)
}
