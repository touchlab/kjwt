package co.touchlab.kjwt.algorithm

import co.touchlab.kjwt.cryptography.SimpleKey
import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.materials.key.Key
import kotlin.jvm.JvmStatic

sealed class JwsAlgorithm<out K : Key>(val id: String) {
    sealed class HashBased(id: String) : JwsAlgorithm<HMAC.Key>(id)
    sealed class PKCS1Based(id: String) : JwsAlgorithm<RSA.PKCS1.PrivateKey>(id)
    sealed class PSSBased(id: String) : JwsAlgorithm<RSA.PSS.PrivateKey>(id)
    sealed class ECDSABased(id: String) : JwsAlgorithm<ECDSA.PrivateKey>(id)

    data object HS256 : HashBased("HS256")
    data object HS384 : HashBased("HS384")
    data object HS512 : HashBased("HS512")

    data object RS256 : PKCS1Based("RS256")
    data object RS384 : PKCS1Based("RS384")
    data object RS512 : PKCS1Based("RS512")

    data object PS256 : PSSBased("PS256")
    data object PS384 : PSSBased("PS384")
    data object PS512 : PSSBased("PS512")

    data object ES256 : ECDSABased("ES256")
    data object ES384 : ECDSABased("ES384")
    data object ES512 : ECDSABased("ES512")

    /** Unsecured JWT — opt-in only. Rejected by parser unless `allowUnsecured(true)`. */
    data object None : JwsAlgorithm<SimpleKey>("none")

    override fun toString(): String = id

    companion object {
        @JvmStatic
        val entries: List<JwsAlgorithm<*>> by lazy {
            listOf(
                HS256, HS384, HS512,
                RS256, RS384, RS512,
                PS256, PS384, PS512,
                ES256, ES384, ES512,
                None,
            )
        }

        @JvmStatic
        fun fromId(id: String): JwsAlgorithm<*> =
            entries.firstOrNull { it.id == id }
                ?: throw IllegalArgumentException("Unknown JWS algorithm: '$id'")
    }
}