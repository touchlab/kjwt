package co.touchlab.kjwt.hardware.helpers

import co.touchlab.kjwt.model.algorithm.Jwa
import java.security.KeyStore

internal object AndroidKeyStoreManager {
    private const val DEFAULT_JWE_KEY_ALIAS = "__kjwt_default_%s_key__"

    private val keystore: KeyStore
        get() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun getKey(keyId: String): KeyStore.Entry? = keystore.getEntry(keyId, null)

    fun containsKey(keyId: String): Boolean = keystore.containsAlias(keyId)

    fun getDefaultKey(key: String?, algorithm: Jwa): String = key ?: DEFAULT_JWE_KEY_ALIAS.format(algorithm.id)
}
