package co.touchlab.kjwt.model

import co.touchlab.kjwt.algorithm.JweContentAlgorithm
import co.touchlab.kjwt.algorithm.JweKeyAlgorithm
import co.touchlab.kjwt.algorithm.JwsAlgorithm
import co.touchlab.kjwt.serializers.JweHeaderSerializer
import co.touchlab.kjwt.serializers.JwsHeaderSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

sealed class JwtHeader {
    abstract val algorithm: String
    abstract val type: String?
    abstract val contentType: String?
    abstract val keyId: String?
    abstract val extra: Map<String, JsonElement>

    @Serializable(with = JwsHeaderSerializer::class)
    data class Jws(
        override val algorithm: String,
        override val type: String? = "JWT",
        override val contentType: String? = null,
        override val keyId: String? = null,
        override val extra: Map<String, JsonElement> = emptyMap(),
    ) : JwtHeader()

    @Serializable(with = JweHeaderSerializer::class)
    data class Jwe(
        override val algorithm: String,
        val encryption: String,
        override val type: String? = "JWT",
        override val contentType: String? = null,
        override val keyId: String? = null,
        override val extra: Map<String, JsonElement> = emptyMap(),
    ) : JwtHeader()

    class Builder {
        var type: String? = "JWT"
        var contentType: String? = null
        var keyId: String? = null
        private val extra: MutableMap<String, JsonElement> = mutableMapOf()

        fun extra(name: String, value: JsonElement) {
            extra[name] = value
        }

        internal fun build(algorithm: JwsAlgorithm<*, *>) = Jws(
            algorithm = algorithm.id,
            type = type,
            contentType = contentType,
            keyId = keyId,
            extra = extra,
        )

        internal fun build(
            keyAlgorithm: JweKeyAlgorithm<*, *>,
            contentAlgorithm: JweContentAlgorithm,
        ) = Jwe(
            algorithm = keyAlgorithm.id,
            encryption = contentAlgorithm.id,
            type = type,
            contentType = contentType,
            keyId = keyId,
            extra = extra,
        )
    }

    companion object {
        const val ALG = "alg"
        const val ENC = "enc"
        const val TYP = "typ"
        const val CTY = "cty"
        const val KID = "kid"
    }
}