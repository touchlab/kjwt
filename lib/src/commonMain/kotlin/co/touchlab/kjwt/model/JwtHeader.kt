package co.touchlab.kjwt.model

import co.touchlab.kjwt.algorithm.JweContentAlgorithm
import co.touchlab.kjwt.algorithm.JweKeyAlgorithm
import co.touchlab.kjwt.algorithm.JwsAlgorithm
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject

sealed class JwtHeader {
    abstract val algorithm: String
    abstract val type: String?
    abstract val contentType: String?
    abstract val keyId: String?
    abstract val extra: Map<String, JsonElement>

    @Serializable(with = Jws.JwsSerializer::class)
    data class Jws(
        override val algorithm: String,
        override val type: String? = "JWT",
        override val contentType: String? = null,
        override val keyId: String? = null,
        override val extra: Map<String, JsonElement> = emptyMap(),
    ) : JwtHeader() {
        object JwsSerializer : KSerializer<Jws> {
            private val delegate = JsonObject.serializer()
            override val descriptor: SerialDescriptor = delegate.descriptor

            override fun serialize(encoder: Encoder, value: Jws) {
                encoder.encodeSerializableValue(
                    delegate,
                    buildJsonObject {
                        put(ALG, JsonPrimitive(value.algorithm))
                        value.type?.let { put(TYP, JsonPrimitive(it)) }
                        value.contentType?.let { put(CTY, JsonPrimitive(it)) }
                        value.keyId?.let { put(KID, JsonPrimitive(it)) }
                        value.extra.forEach { (k, v) -> put(k, v) }
                    }
                )
            }

            override fun deserialize(decoder: Decoder): Jws {
                val obj = decoder.decodeSerializableValue(delegate)
                val extra = obj.filterKeys { it !in setOf(ALG, TYP, CTY, KID) }

                return Jws(
                    algorithm = obj[ALG]?.let { (it as JsonPrimitive).content }
                        ?: error("Missing 'alg' in JWS header"),
                    type = (obj[TYP] as? JsonPrimitive)?.content,
                    contentType = (obj[CTY] as? JsonPrimitive)?.content,
                    keyId = (obj[KID] as? JsonPrimitive)?.content,
                    extra = extra,
                )
            }
        }
    }

    @Serializable(with = Jwe.JweSerializer::class)
    data class Jwe(
        override val algorithm: String,
        val encryption: String,
        override val type: String? = "JWT",
        override val contentType: String? = null,
        override val keyId: String? = null,
        override val extra: Map<String, JsonElement> = emptyMap(),
    ) : JwtHeader() {
        object JweSerializer : KSerializer<Jwe> {
            private val delegate = JsonObject.serializer()
            override val descriptor: SerialDescriptor = delegate.descriptor

            override fun serialize(encoder: Encoder, value: Jwe) {
                encoder.encodeSerializableValue(
                    delegate,
                    buildJsonObject {
                        put(ALG, JsonPrimitive(value.algorithm))
                        put(ENC, JsonPrimitive(value.encryption))
                        value.type?.let { put(TYP, JsonPrimitive(it)) }
                        value.contentType?.let { put(CTY, JsonPrimitive(it)) }
                        value.keyId?.let { put(KID, JsonPrimitive(it)) }
                        value.extra.forEach { (k, v) -> put(k, v) }
                    }
                )
            }

            override fun deserialize(decoder: Decoder): Jwe {
                val obj = decoder.decodeSerializableValue(delegate)
                val extra = obj.filterKeys { it !in setOf(ALG, ENC, TYP, CTY, KID) }

                return Jwe(
                    algorithm = obj[ALG]?.let { (it as JsonPrimitive).content }
                        ?: error("Missing 'alg' in JWE header"),
                    encryption = obj[ENC]?.let { (it as JsonPrimitive).content }
                        ?: error("Missing 'enc' in JWE header"),
                    type = (obj[TYP] as? JsonPrimitive)?.content,
                    contentType = (obj[CTY] as? JsonPrimitive)?.content,
                    keyId = (obj[KID] as? JsonPrimitive)?.content,
                    extra = extra,
                )
            }
        }
    }

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