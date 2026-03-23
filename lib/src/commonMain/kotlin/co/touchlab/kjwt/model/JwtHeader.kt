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
    @PublishedApi internal val jsonData: JsonObject,
) {
    internal constructor(jsonData: JsonObject) : this(
        base64Encoded = JwtJson.encodeToBase64Url(jsonData),
        jsonData = jsonData,
    )

    internal constructor(base64Encoded: String) : this(
        base64Encoded = base64Encoded,
        jsonData =
        JwtJson.decodeBase64Url(
            deserializer = JsonObject.serializer(),
            base64UrlString = base64Encoded,
            name = "header",
        ),
    )

    /**
     * The algorithm (`alg`) header parameter identifying the cryptographic algorithm used.
     *
     * @throws MissingHeaderException if the `alg` header is absent
     */
    public val algorithm: String =
        getHeaderOrNull(String.serializer(), ALG) ?: throw MissingHeaderException(ALG)

    /**
     * Returns `true` if a header parameter with the given name exists.
     *
     * @param name the header parameter name to look up
     * @return `true` if the header is present, `false` otherwise
     */
    public fun hasHeader(name: String): Boolean = jsonData.containsKey(name)

    /**
     * Returns the value of the named header parameter deserialized using the given [serializer].
     *
     * @param serializer the deserialization strategy for type [T]
     * @param name the header parameter name
     * @return the deserialized header value
     * @throws NullPointerException if the header parameter is absent
     */
    public fun <T> getHeader(
        serializer: DeserializationStrategy<T>,
        name: String,
    ): T = getHeaderOrNull(serializer, name) ?: throw NullPointerException("Header '$name' not found")

    /**
     * Returns the value of the named header parameter deserialized using the given [serializer], or `null` if absent.
     *
     * @param serializer the deserialization strategy for type [T]
     * @param name the header parameter name
     * @return the deserialized header value, or `null` if the parameter is not present
     */
    public fun <T> getHeaderOrNull(
        serializer: DeserializationStrategy<T>,
        name: String,
    ): T? {
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

    /** Builder for constructing a [JwtHeader] with standard and extra parameters. */
    public class Builder {
        private val content: MutableMap<String, JsonElement> =
            mutableMapOf(
                TYP to JsonPrimitive("JWT"),
            )

        /** The token type (`typ`) header parameter; defaults to `"JWT"`. */
        public var type: String? = "JWT"
            set(value) {
                field = value
                extra(TYP, value)
            }

        /** The content type (`cty`) header parameter, used when the payload is itself a JWT. */
        public var contentType: String? = null
            set(value) {
                field = value
                extra(CTY, value)
            }

        /**
         * Sets an extra header parameter using a pre-built [JsonElement], or removes it if [value] is `null`.
         *
         * @param name the header parameter name
         * @param value the header value, or `null` to remove the parameter
         */
        public fun extra(
            name: String,
            value: JsonElement?,
        ) {
            if (value == null) {
                content.remove(name)
            } else {
                content[name] = value
            }
        }

        /**
         * Sets an extra header parameter using an explicit [SerializationStrategy].
         *
         * @param name the header parameter name
         * @param serializer the serialization strategy for [T]
         * @param value the header value, or `null` to remove the parameter
         */
        public fun <T> extra(
            name: String,
            serializer: SerializationStrategy<T>,
            value: T?,
        ) {
            extra(name, value?.let { JwtJson.encodeToJsonElement(serializer, it) })
        }

        /**
         * Sets an extra header parameter, inferring the serializer from the reified type [T].
         *
         * @param name the header parameter name
         * @param value the header value
         */
        public inline fun <reified T> extra(
            name: String,
            value: T,
        ) {
            extra(name, kotlinx.serialization.serializer<T>(), value)
        }

        internal fun build(
            algorithm: SigningAlgorithm<*, *>,
            keyId: String?,
        ) = JwtHeader(
            buildToJson {
                put(ALG, algorithm.id)
                if (keyId != null) put(KID, keyId)
            },
        )

        internal fun build(
            keyAlgorithm: EncryptionAlgorithm<*, *>,
            contentAlgorithm: EncryptionContentAlgorithm,
            keyId: String?,
        ) = JwtHeader(
            buildToJson {
                put(ALG, keyAlgorithm.id)
                put(ENC, contentAlgorithm.id)
                if (keyId != null) put(KID, keyId)
            },
        )

        private fun buildToJson(builder: JsonObjectBuilder.() -> Unit) =
            buildJsonObject {
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
