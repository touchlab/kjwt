package co.touchlab.kjwt.model

import co.touchlab.kjwt.exception.MissingHeaderException
import co.touchlab.kjwt.internal.JwtJson
import co.touchlab.kjwt.internal.decodeBase64Url
import co.touchlab.kjwt.internal.encodeToBase64Url
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.EncryptionContentAlgorithm
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import co.touchlab.kjwt.serializers.JwtHeaderSerializer
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

@Serializable(with = JwtHeaderSerializer::class)
public class JwtHeader internal constructor(
    internal val base64Encoded: String,
    internal val jsonData: JsonObject,
) {
    internal constructor(jsonData: JsonObject) : this(
        base64Encoded = JwtJson.encodeToBase64Url(jsonData),
        jsonData = jsonData,
    )

    internal constructor(base64Encoded: String) : this(
        base64Encoded = base64Encoded,
        jsonData = JwtJson.decodeBase64Url(
            deserializer = JsonObject.serializer(),
            base64UrlString = base64Encoded,
            name = "header"
        )
    )

    public val algorithm: String =
        getHeaderOrNull(String.serializer(), ALG) ?: throw MissingHeaderException(ALG)

    public fun hasHeader(name: String): Boolean =
        jsonData.containsKey(name)

    public fun <T> getHeader(serializer: DeserializationStrategy<T>, name: String): T =
        getHeaderOrNull(serializer, name) ?: throw NullPointerException("Header '$name' not found")

    public fun <T> getHeaderOrNull(serializer: DeserializationStrategy<T>, name: String): T? {
        val element = jsonData[name] ?: return null
        return JwtJson.decodeFromJsonElement(serializer, element)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JwtHeader

        return base64Encoded == other.base64Encoded
    }

    override fun hashCode(): Int = base64Encoded.hashCode()

    override fun toString(): String = base64Encoded

    public class Builder {
        private val content: MutableMap<String, JsonElement> = mutableMapOf(
            TYP to JsonPrimitive("JWT")
        )

        public var type: String? = "JWT"
            set(value) {
                field = value
                extra(TYP, value)
            }

        public var contentType: String? = null
            set(value) {
                field = value
                extra(CTY, value)
            }

        public var keyId: String? = null
            set(value) {
                field = value
                extra(KID, value)
            }

        public fun extra(name: String, value: JsonElement?) {
            if (value == null) {
                content.remove(name)
            } else {
                content[name] = value
            }
        }

        public fun <T> extra(name: String, serializer: SerializationStrategy<T>, value: T?) {
            extra(name, value?.let { JwtJson.encodeToJsonElement(serializer, it) })
        }

        public inline fun <reified T> extra(name: String, value: T) {
            extra(name, kotlinx.serialization.serializer<T>(), value)
        }

        internal fun build(algorithm: SigningAlgorithm<*, *>) = JwtHeader(
            buildToJson {
                put(ALG, algorithm.id)
            }
        )

        internal fun build(
            keyAlgorithm: EncryptionAlgorithm<*, *>,
            contentAlgorithm: EncryptionContentAlgorithm,
        ) = JwtHeader(
            buildToJson {
                put(ALG, keyAlgorithm.id)
                put(ENC, contentAlgorithm.id)
            }
        )

        private fun buildToJson(builder: JsonObjectBuilder.() -> Unit) = buildJsonObject {
            content.forEach { (name, value) -> put(name, value) }
            builder()
        }
    }

    public companion object {
        public const val ALG: String = "alg"
        public const val ENC: String = "enc"
        public const val TYP: String = "typ"
        public const val CTY: String = "cty"
        public const val KID: String = "kid"
    }
}
