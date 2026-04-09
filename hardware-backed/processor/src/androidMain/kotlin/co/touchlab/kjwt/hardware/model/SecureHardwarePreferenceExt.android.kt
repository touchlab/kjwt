package co.touchlab.kjwt.hardware.model

import android.os.Build
import android.security.keystore.StrongBoxUnavailableException

/**
 * Invokes [handler] with a boolean indicating whether the Android Keystore should be asked
 * to back the key with StrongBox.
 *
 * - [SecureHardwarePreference.None]: always calls `handler(false)`.
 * - [SecureHardwarePreference.Required]: asserts API 28+ is available, then calls `handler(true)`.
 *   Throws [IllegalStateException] if the device is below API 28.
 * - [SecureHardwarePreference.Preferred]: calls `handler(true)` on API 28+, catching
 *   `StrongBoxUnavailableException` and retrying with `handler(false)` if the device has no
 *   StrongBox; calls `handler(false)` directly on older API levels.
 */
internal fun SecureHardwarePreference.runWithFlag(handler: (useStrongBox: Boolean) -> Unit) {
    when (this) {
        SecureHardwarePreference.None -> {
            handler(false)
        }

        SecureHardwarePreference.Required -> {
            check(Build.VERSION.SDK_INT >= 28) {
                "StrongBox requires API 28+, current: ${Build.VERSION.SDK_INT}"
            }
            handler(true)
        }

        SecureHardwarePreference.Preferred -> {
            if (Build.VERSION.SDK_INT >= 28) {
                try {
                    handler(true)
                } catch (_: StrongBoxUnavailableException) {
                    handler(false)
                }
            } else {
                handler(false)
            }
        }
    }
}
