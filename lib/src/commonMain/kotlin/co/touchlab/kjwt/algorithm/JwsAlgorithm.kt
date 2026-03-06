package co.touchlab.kjwt.algorithm

import dev.whyoleg.cryptography.CryptographyProviderApi
import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.materials.key.EncodableKey
import dev.whyoleg.cryptography.materials.key.KeyFormat
import kotlin.jvm.JvmStatic

sealed class JwsAlgorithm<out Key : EncodableKey<*>>(val id: String) {
    data object HS256 : JwsAlgorithm<HMAC.Key>("HS256")
    data object HS384 : JwsAlgorithm<HMAC.Key>("HS384")
    data object HS512 : JwsAlgorithm<HMAC.Key>("HS512")

    data object RS256 : JwsAlgorithm<RSA.PKCS1.PrivateKey>("RS256")
    data object RS384 : JwsAlgorithm<RSA.PKCS1.PrivateKey>("RS384")
    data object RS512 : JwsAlgorithm<RSA.PKCS1.PrivateKey>("RS512")

    data object PS256 : JwsAlgorithm<RSA.PSS.PrivateKey>("PS256")
    data object PS384 : JwsAlgorithm<RSA.PSS.PrivateKey>("PS384")
    data object PS512 : JwsAlgorithm<RSA.PSS.PrivateKey>("PS512")

    data object ES256 : JwsAlgorithm<ECDSA.PrivateKey>("ES256")
    data object ES384 : JwsAlgorithm<ECDSA.PrivateKey>("ES384")
    data object ES512 : JwsAlgorithm<ECDSA.PrivateKey>("ES512")

    /** Unsecured JWT — opt-in only. Rejected by parser unless `allowUnsecured(true)`. */
    data object None : JwsAlgorithm<None.NoneKey>("none") {
        @OptIn(CryptographyProviderApi::class)
        data object NoneKey : EncodableKey<NoneKeyFormat> {
            override suspend fun encodeToByteArray(format: NoneKeyFormat): ByteArray = TODO()
            override fun encodeToByteArrayBlocking(format: NoneKeyFormat): ByteArray = TODO()
        }

        @OptIn(CryptographyProviderApi::class)
        data object NoneKeyFormat : KeyFormat {
            override val name: String = "none"
        }
    }

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