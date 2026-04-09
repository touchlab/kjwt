package co.touchlab.kjwt.hardware.model

import co.touchlab.kjwt.model.algorithm.SigningAlgorithm

/** Thrown when Secure Enclave key generation fails, allowing [SecureHardwarePreference.Preferred] to fall back. */
internal class SecureEnclaveUnavailableException(message: String) : Exception(message)

/**
 * Invokes [handler] with a boolean indicating whether key generation should target the
 * Secure Enclave.
 *
 * - [SecureHardwarePreference.None]: always calls `handler(false)`.
 * - [SecureHardwarePreference.Required]: asserts that [algorithm] is ES256 (the only algorithm
 *   supported by the Secure Enclave), then calls `handler(true)`. Throws
 *   [IllegalArgumentException] for any other algorithm.
 * - [SecureHardwarePreference.Preferred]: if [algorithm] is ES256, calls `handler(true)` and
 *   catches [SecureEnclaveUnavailableException], retrying with `handler(false)`; for all other
 *   algorithms calls `handler(false)` directly.
 */
internal fun SecureHardwarePreference.runWithFlag(
    algorithm: SigningAlgorithm,
    handler: (useSecureEnclave: Boolean) -> Unit,
) {
    val supportsSecureEnclave = algorithm == SigningAlgorithm.ES256

    when (this) {
        SecureHardwarePreference.None -> handler(false)

        SecureHardwarePreference.Required -> {
            require(supportsSecureEnclave) {
                "Secure Enclave is only supported for ES256; '${algorithm.id}' cannot use it"
            }
            handler(true)
        }

        SecureHardwarePreference.Preferred -> {
            if (supportsSecureEnclave) {
                try {
                    handler(true)
                } catch (_: SecureEnclaveUnavailableException) {
                    handler(false)
                }
            } else {
                handler(false)
            }
        }
    }
}
