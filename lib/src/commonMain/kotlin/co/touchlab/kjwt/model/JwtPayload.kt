package co.touchlab.kjwt.model

import co.touchlab.kjwt.internal.JwtJson
import co.touchlab.kjwt.internal.decodeBase64Url
import co.touchlab.kjwt.internal.encodeToBase64Url
import co.touchlab.kjwt.serializers.InstantEpochSecondsSerializer
import co.touchlab.kjwt.serializers.JwtPayloadSerializer
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Instant
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

@Serializable(with = JwtPayloadSerializer::class)
public class JwtPayload internal constructor(
    internal val base64Encoded: String,
    @PublishedApi internal val jsonData: JsonObject,
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
            name = "payload"
        )
    )

    public fun hasClaim(name: String): Boolean =
        jsonData.containsKey(name)

    public fun <T> getClaim(serializer: DeserializationStrategy<T>, name: String): T =
        getClaimOrNull(serializer, name) ?: throw NullPointerException(name)

    public fun <T> getClaimOrNull(serializer: DeserializationStrategy<T>, name: String): T? {
        val element = jsonData[name] ?: return null
        return JwtJson.decodeFromJsonElement(serializer, element)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JwtPayload

        return base64Encoded == other.base64Encoded
    }

    override fun hashCode(): Int = base64Encoded.hashCode()

    override fun toString(): String = base64Encoded

    public class Builder {
        @PublishedApi
        internal val content: MutableMap<String, JsonElement> = mutableMapOf()

        public var issuer: String? = null
            set(value) {
                field = value
                claim(ISS, value)
            }

        public var subject: String? = null
            set(value) {
                field = value
                claim(SUB, value)
            }

        public var audience: Set<String>? = null
            set(value) {
                field = value
                if (value != null && value.size == 1) {
                    claim(AUD, value.first())
                } else {
                    claim(AUD, value)
                }
            }

        public var expiration: Instant? = null
            set(value) {
                field = value
                claim(EXP, InstantEpochSecondsSerializer, value)
            }

        public var notBefore: Instant? = null
            set(value) {
                field = value
                claim(NBF, InstantEpochSecondsSerializer, value)
            }

        public var issuedAt: Instant? = null
            set(value) {
                field = value
                claim(IAT, InstantEpochSecondsSerializer, value)
            }

        public var id: String? = null
            set(value) {
                field = value
                claim(JTI, value)
            }

        public fun claim(name: String, value: JsonElement?) {
            if (value != null) {
                content[name] = value
            } else {
                content.remove(name)
            }
        }

        public fun <T> claim(name: String, serializer: SerializationStrategy<T>, value: T?) {
            claim(name, value?.let { JwtJson.encodeToJsonElement(serializer, it) })
        }

        public inline fun <reified T> claim(name: String, value: T) {
            claim(name, kotlinx.serialization.serializer<T>(), value)
        }

        public fun expiresIn(duration: Duration) {
            expiration = Clock.System.now() + duration
        }

        public fun notBeforeNow() {
            notBefore = Clock.System.now()
        }

        public fun issuedNow() {
            issuedAt = Clock.System.now()
        }

        @ExperimentalUuidApi
        public fun randomId() {
            id = Uuid.random().toString()
        }

        internal fun build() = JwtPayload(JsonObject(content))
    }

    public companion object {
        public const val ISS: String = "iss"
        public const val SUB: String = "sub"
        public const val AUD: String = "aud"
        public const val EXP: String = "exp"
        public const val NBF: String = "nbf"
        public const val IAT: String = "iat"
        public const val JTI: String = "jti"
    }
}
