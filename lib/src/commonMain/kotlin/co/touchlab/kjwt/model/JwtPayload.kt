package co.touchlab.kjwt.model

import co.touchlab.kjwt.exception.MissingClaimException
import co.touchlab.kjwt.internal.JwtJson
import co.touchlab.kjwt.model.JwtPayload.Companion.AUD
import co.touchlab.kjwt.model.JwtPayload.Companion.EXP
import co.touchlab.kjwt.model.JwtPayload.Companion.IAT
import co.touchlab.kjwt.model.JwtPayload.Companion.ISS
import co.touchlab.kjwt.model.JwtPayload.Companion.JTI
import co.touchlab.kjwt.model.JwtPayload.Companion.NBF
import co.touchlab.kjwt.model.JwtPayload.Companion.SUB
import co.touchlab.kjwt.serializers.AudienceDeserializer
import co.touchlab.kjwt.serializers.ClaimsSerializer
import co.touchlab.kjwt.serializers.InstantEpochSecondsSerializer
import kotlin.time.Instant
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

interface JwtPayload {
    fun <T> getClaim(serializer: DeserializationStrategy<T>, name: String): T
    fun <T> getClaimOrNull(serializer: DeserializationStrategy<T>, name: String): T?

    companion object {
        const val ISS = "iss"
        const val SUB = "sub"
        const val AUD = "aud"
        const val EXP = "exp"
        const val NBF = "nbf"
        const val IAT = "iat"
        const val JTI = "jti"
    }
}

inline fun <reified T> JwtPayload.getClaim(name: String): T =
    getClaim(kotlinx.serialization.serializer<T>(), name)

inline fun <reified T> JwtPayload.getClaimOrNull(name: String): T? =
    getClaimOrNull(kotlinx.serialization.serializer<T>(), name)

val JwtPayload.issuer: String get() = getClaim(ISS)
val JwtPayload.issuerOrNull: String? get() = getClaimOrNull(ISS)

val JwtPayload.subject: String get() = getClaim(SUB)
val JwtPayload.subjectOrNull: String? get() = getClaimOrNull(SUB)

val JwtPayload.audience: Set<String> get() = getClaim(AudienceDeserializer, AUD)
val JwtPayload.audienceOrNull: Set<String>? get() = getClaimOrNull(AudienceDeserializer, AUD)

val JwtPayload.expiration: Instant get() = getClaim(InstantEpochSecondsSerializer, EXP)
val JwtPayload.expirationOrNull: Instant? get() = getClaimOrNull(InstantEpochSecondsSerializer, EXP)

val JwtPayload.notBefore: Instant get() = getClaim(InstantEpochSecondsSerializer, NBF)
val JwtPayload.notBeforeOrNull: Instant? get() = getClaimOrNull(InstantEpochSecondsSerializer, NBF)

val JwtPayload.issuedAt: Instant get() = getClaim(InstantEpochSecondsSerializer, IAT)
val JwtPayload.issuedAtOrNull: Instant? get() = getClaimOrNull(InstantEpochSecondsSerializer, IAT)

val JwtPayload.jwtId: String get() = getClaim(JTI)
val JwtPayload.jwtIdOrNull: String? get() = getClaimOrNull(JTI)

@Serializable(with = ClaimsSerializer::class)
class Claims(@PublishedApi internal val data: Map<String, JsonElement>) : JwtPayload {
    override fun <T> getClaim(serializer: DeserializationStrategy<T>, name: String): T =
        getClaimOrNull(serializer, name) ?: throw MissingClaimException(name)

    override fun <T> getClaimOrNull(serializer: DeserializationStrategy<T>, name: String): T? {
        val element = data[name] ?: return null
        return JwtJson.decodeFromJsonElement(serializer, element)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Claims

        return data == other.data
    }

    override fun hashCode(): Int = data.hashCode()
    override fun toString(): String = "Claims(data=$data)"

    class Builder {
        var issuer: String? = null
            set(value) {
                field = value
                claim(ISS, value)
            }

        var subject: String? = null
            set(value) {
                field = value
                claim(SUB, value)
            }

        var audience: Set<String>? = null
            set(value) {
                field = value
                claim(AUD, value)
            }

        var expiration: Instant? = null
            set(value) {
                field = value
                claim(EXP, InstantEpochSecondsSerializer, value)
            }

        var notBefore: Instant? = null
            set(value) {
                field = value
                claim(NBF, InstantEpochSecondsSerializer, value)
            }

        var issuedAt: Instant? = null
            set(value) {
                field = value
                claim(IAT, InstantEpochSecondsSerializer, value)
            }

        var jwtId: String? = null
            set(value) {
                field = value
                claim(JTI, value)
            }

        @PublishedApi
        internal val content: MutableMap<String, JsonElement> = mutableMapOf()

        fun claim(name: String, value: JsonElement) {
            content[name] = value
        }

        fun <T> claim(name: String, serializer: SerializationStrategy<T>, value: T?) {
            if (value != null) {
                claim(name, JwtJson.encodeToJsonElement(serializer, value))
            } else {
                content.remove(name)
            }
        }

        inline fun <reified T> claim(name: String, value: T) {
            claim(name, kotlinx.serialization.serializer<T>(), value)
        }

        internal fun build(): Claims = Claims(JsonObject(content))
    }
}
