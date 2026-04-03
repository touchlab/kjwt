package co.touchlab.kjwt.model

import co.touchlab.kjwt.Jwt
import co.touchlab.kjwt.internal.decodeBase64Url
import co.touchlab.kjwt.internal.encodeToBase64Url
import co.touchlab.kjwt.serializers.InstantEpochSecondsSerializer
import co.touchlab.kjwt.serializers.JwtPayloadSerializer
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Instant
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * Immutable representation of a JWT payload (claims set) as defined in RFC 7519.
 *
 * The payload is backed by a [JsonObject] and also stored in its base64url-encoded form so that
 * the compact serialization can be reproduced exactly. Registered claim names (e.g. `iss`, `sub`,
 * `aud`, `exp`) are accessible through named properties on [Builder]; arbitrary custom claims can
 * be read with [getClaim] and [getClaimOrNull].
 *
 * @see JwtPayload.Builder
 * @see JwtInstance
 */
@Serializable(with = JwtPayloadSerializer::class)
public class JwtPayload internal constructor(
    internal val base64Encoded: String,
    @PublishedApi internal val jsonData: JsonObject,
) {
    internal constructor(jsonData: JsonObject, jsonInstance: Json) : this(
        base64Encoded = jsonInstance.encodeToBase64Url(jsonData),
        jsonData = jsonData,
    )

    internal constructor(base64Encoded: String, jsonInstance: Json) : this(
        base64Encoded = base64Encoded,
        jsonData = jsonInstance.decodeBase64Url(
            deserializer = JsonObject.serializer(),
            base64UrlString = base64Encoded,
            name = "payload",
        ),
    )

    /**
     * Returns `true` if a claim with the given name exists in the payload.
     *
     * @param name the claim name to look up
     * @return `true` if the claim is present, `false` otherwise
     */
    public fun hasClaim(name: String): Boolean = jsonData.containsKey(name)

    /**
     * Returns the value of the named claim, deserialized using the given [serializer].
     *
     * @param serializer the deserialization strategy for type [T]
     * @param name the claim name
     * @param jsonInstance the [Json] instance to use for deserialization; defaults to the library's
     *   [Jwt.defaultJsonParser] configuration (`ignoreUnknownKeys = true`, `explicitNulls = false`)
     * @return the deserialized claim value
     * @throws NullPointerException if the claim is absent
     */
    public fun <T> getClaim(
        serializer: DeserializationStrategy<T>,
        name: String,
        jsonInstance: Json = Jwt.defaultJsonParser,
    ): T = getClaimOrNull(serializer, name, jsonInstance) ?: throw NullPointerException(name)

    /**
     * Returns the value of the named claim deserialized using the given [serializer], or `null` if absent.
     *
     * @param serializer the deserialization strategy for type [T]
     * @param name the claim name
     * @param jsonInstance the [Json] instance to use for deserialization; defaults to the library's
     *   [Jwt.defaultJsonParser] configuration (`ignoreUnknownKeys = true`, `explicitNulls = false`)
     * @return the deserialized claim value, or `null` if the claim is not present
     */
    public fun <T> getClaimOrNull(
        serializer: DeserializationStrategy<T>,
        name: String,
        jsonInstance: Json = Jwt.defaultJsonParser,
    ): T? {
        val element = jsonData[name] ?: return null
        return jsonInstance.decodeFromJsonElement(serializer, element)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JwtPayload

        return base64Encoded == other.base64Encoded
    }

    override fun hashCode(): Int = base64Encoded.hashCode()

    override fun toString(): String = base64Encoded

    /** Builder for constructing a [JwtPayload] with standard and custom claims. */
    public class Builder {
        @PublishedApi
        internal val content: MutableMap<String, JsonElement> = mutableMapOf()

        /** The issuer (`iss`) claim identifying the principal that issued the token. */
        public var issuer: String? = null
            set(value) {
                field = value
                claim(ISS, value)
            }

        /** The subject (`sub`) claim identifying the principal that is the subject of the token. */
        public var subject: String? = null
            set(value) {
                field = value
                claim(SUB, value)
            }

        /**
         * The audience (`aud`) claim identifying the recipients that the token is intended for.
         *
         * A single-element set is serialized as a plain string; multiple elements are serialized as a JSON array.
         */
        public var audience: Set<String>? = null
            set(value) {
                field = value
                if (value != null && value.size == 1) {
                    claim(AUD, value.first())
                } else {
                    claim(AUD, value)
                }
            }

        /** The expiration time (`exp`) claim, expressed as an epoch-seconds timestamp. */
        public var expiration: Instant? = null
            set(value) {
                field = value
                claim(EXP, InstantEpochSecondsSerializer, value)
            }

        /** The not-before (`nbf`) claim; the token must not be accepted before this time. */
        public var notBefore: Instant? = null
            set(value) {
                field = value
                claim(NBF, InstantEpochSecondsSerializer, value)
            }

        /** The issued-at (`iat`) claim identifying the time at which the token was issued. */
        public var issuedAt: Instant? = null
            set(value) {
                field = value
                claim(IAT, InstantEpochSecondsSerializer, value)
            }

        /** The JWT ID (`jti`) claim providing a unique identifier for this token. */
        public var id: String? = null
            set(value) {
                field = value
                claim(JTI, value)
            }

        /**
         * Sets a raw claim using a pre-built [JsonElement], or removes it if [value] is `null`.
         *
         * @param name the claim name
         * @param value the claim value, or `null` to remove the claim
         */
        public fun claim(
            name: String,
            value: JsonElement?,
        ) {
            if (value != null) {
                content[name] = value
            } else {
                content.remove(name)
            }
        }

        /**
         * Sets a typed claim using an explicit [SerializationStrategy].
         *
         * @param name the claim name
         * @param serializer the serialization strategy for [T]
         * @param value the claim value, or `null` to remove the claim
         * @param jsonInstance the [Json] instance to use for serialization; defaults to the library's
         *   [Jwt.defaultJsonParser] configuration (`ignoreUnknownKeys = true`, `explicitNulls = false`)
         */
        public fun <T> claim(
            name: String,
            serializer: SerializationStrategy<T>,
            value: T?,
            jsonInstance: Json = Jwt.defaultJsonParser,
        ) {
            claim(name, value?.let { jsonInstance.encodeToJsonElement(serializer, it) })
        }

        /**
         * Sets a typed claim, inferring the serializer from the reified type [T].
         *
         * @param name the claim name
         * @param value the claim value
         */
        public inline fun <reified T> claim(
            name: String,
            value: T,
        ) {
            claim(name, kotlinx.serialization.serializer<T>(), value)
        }

        /**
         * Merges all fields from [value] into this builder, encoded using [serializer].
         *
         * The object is serialized to a [JsonObject] and each key-value pair is added to the
         * payload, overwriting any existing claim with the same name.
         *
         * @param serializer the serialization strategy for [T]
         * @param value the object whose fields should be merged into the payload
         * @param jsonInstance the [Json] instance to use for serialization; defaults to the library's
         *   [Jwt.defaultJsonParser] configuration (`ignoreUnknownKeys = true`, `explicitNulls = false`)
         */
        public fun <T> takeFrom(
            serializer: SerializationStrategy<T>,
            value: T,
            jsonInstance: Json = Jwt.defaultJsonParser,
        ) {
            val jsonObject = jsonInstance.encodeToJsonElement(serializer, value) as JsonObject
            jsonObject.forEach { (key, element) -> content[key] = element }
        }

        /**
         * Merges all fields from [value] into this builder, inferring the serializer from the
         * reified type [T].
         *
         * The object is serialized to a [JsonObject] and each key-value pair is added to the
         * payload, overwriting any existing claim with the same name.
         *
         * @param value the object whose fields should be merged into the payload
         */
        public inline fun <reified T> takeFrom(value: T) {
            takeFrom(kotlinx.serialization.serializer<T>(), value)
        }

        /**
         * Sets the expiration time (`exp`) claim relative to the current time.
         *
         * @param duration the duration from now until the token expires
         */
        public fun expiresIn(duration: Duration) {
            expiration = Clock.System.now() + duration
        }

        /** Sets the not-before (`nbf`) claim to the current time. */
        public fun notBeforeNow() {
            notBefore = Clock.System.now()
        }

        /** Sets the issued-at (`iat`) claim to the current time. */
        public fun issuedNow() {
            issuedAt = Clock.System.now()
        }

        /** Sets the JWT ID (`jti`) claim to a randomly generated UUID. */
        @ExperimentalUuidApi
        public fun randomId() {
            id = Uuid.random().toString()
        }

        internal fun build(jsonInstance: Json) = JwtPayload(JsonObject(content), jsonInstance)
    }

    public companion object {
        /** The `iss` (issuer) claim name (RFC 7519 §4.1.1). */
        public const val ISS: String = "iss"

        /** The `sub` (subject) claim name (RFC 7519 §4.1.2). */
        public const val SUB: String = "sub"

        /** The `aud` (audience) claim name (RFC 7519 §4.1.3). */
        public const val AUD: String = "aud"

        /** The `exp` (expiration time) claim name (RFC 7519 §4.1.4). */
        public const val EXP: String = "exp"

        /** The `nbf` (not before) claim name (RFC 7519 §4.1.5). */
        public const val NBF: String = "nbf"

        /** The `iat` (issued at) claim name (RFC 7519 §4.1.6). */
        public const val IAT: String = "iat"

        /** The `jti` (JWT ID) claim name (RFC 7519 §4.1.7). */
        public const val JTI: String = "jti"
    }
}
