package co.touchlab.kjwt.hardware

import co.touchlab.kjwt.hardware.model.SecureHardwarePreference
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import co.touchlab.kjwt.processor.JwsProcessor

/**
 * Platform-agnostic factory for creating hardware-backed signing keys.
 *
 * Provides a single entry point for generating keys backed by the platform's secure hardware
 * element from shared (common) code, without needing to reference platform-specific types.
 * The underlying implementation delegates to the appropriate platform key store:
 * - **Android:** `AndroidKeyStoreSigningKey` backed by the Android Keystore (TEE or StrongBox).
 * - **Apple (iOS/macOS):** `AppleKeychainSigningKey` backed by the Keychain or Secure Enclave.
 */
public expect object SecureKeyFactory {
    /**
     * Returns a [JwsProcessor] backed by a hardware-bound signing key, creating the key if it
     * does not already exist.
     *
     * @param keyId The platform key-store alias. When `null`, a library-managed default alias
     *   derived from [algorithm] is used.
     * @param algorithm The signing algorithm for the key. Defaults to [SigningAlgorithm.ES256].
     * @param keySizeInBits RSA key size in bits. Ignored for ECDSA and HMAC keys. Defaults to 2048.
     * @param secureHardwarePreference Controls whether the key is generated inside dedicated secure
     *   hardware (Android StrongBox or Apple Secure Enclave). Defaults to
     *   [SecureHardwarePreference.None].
     */
    public fun getOrCreateSecureSigningKey(
        keyId: String? = null,
        algorithm: SigningAlgorithm = SigningAlgorithm.ES256,
        keySizeInBits: Int = 2048,
        secureHardwarePreference: SecureHardwarePreference = SecureHardwarePreference.Preferred,
    ): JwsProcessor
}
