package co.touchlab.kjwt.model

import co.touchlab.kjwt.exception.MissingClaimException
import co.touchlab.kjwt.internal.JwtJson
import co.touchlab.kjwt.serializers.AudienceDeserializer
import co.touchlab.kjwt.serializers.ClaimsSerializer
import co.touchlab.kjwt.serializers.InstantEpochSecondsDeserializer
import kotlin.time.Instant
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement

@Serializable(with = ClaimsSerializer::class)
class Claims(@PublishedApi internal val data: Map<String, JsonElement>) {
    val issuer: String get() = getClaim(ISS)
    val issuerOrNull: String? get() = getClaimOrNull(ISS)

    val subject: String get() = getClaim(SUB)
    val subjectOrNull: String? get() = getClaimOrNull(SUB)

    val audience: Set<String> get() = getClaim(AudienceDeserializer, AUD)
    val audienceOrNull: Set<String>? get() = getClaimOrNull(AudienceDeserializer, AUD)

    val expiration: Instant get() = getClaim(InstantEpochSecondsDeserializer, EXP)
    val expirationOrNull: Instant? get() = getClaimOrNull(InstantEpochSecondsDeserializer, EXP)

    val notBefore: Instant get() = getClaim(InstantEpochSecondsDeserializer, NBF)
    val notBeforeOrNull: Instant? get() = getClaimOrNull(InstantEpochSecondsDeserializer, NBF)

    val issuedAt: Instant get() = getClaim(InstantEpochSecondsDeserializer, IAT)
    val issuedAtOrNull: Instant? get() = getClaimOrNull(InstantEpochSecondsDeserializer, IAT)

    val jwtId: String get() = getClaim(JTI)
    val jwtIdOrNull: String? get() = getClaimOrNull(JTI)

    inline fun <reified T> getClaim(name: String): T =
        getClaim(kotlinx.serialization.serializer<T>(), name)

    inline fun <reified T> getClaimOrNull(name: String): T? =
        getClaimOrNull(kotlinx.serialization.serializer<T>(), name)

    fun <T> getClaim(serializer: DeserializationStrategy<T>, name: String): T =
        getClaimOrNull(serializer, name) ?: throw MissingClaimException(name)

    fun <T> getClaimOrNull(serializer: DeserializationStrategy<T>, name: String): T? {
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
        var subject: String? = null
        var audience: Set<String>? = null
        var expiration: Instant? = null
        var notBefore: Instant? = null
        var issuedAt: Instant? = null
        var jwtId: String? = null

        @PublishedApi
        internal val extra: MutableMap<String, JsonElement> = mutableMapOf()

        fun claim(name: String, value: JsonElement) {
            extra[name] = value
        }

        inline fun <reified T> claim(name: String, value: T) {
            extra[name] = JwtJson.encodeToJsonElement(value)
        }

        internal fun build(): Claims = Claims(
            buildJsonObject {
                issuer?.let { put(ISS, JsonPrimitive(it)) }
                subject?.let { put(SUB, JsonPrimitive(it)) }
                audience?.let { aud ->
                    if (aud.size == 1) put(AUD, JsonPrimitive(aud.first()))
                    else put(AUD, JsonArray(aud.map { JsonPrimitive(it) }))
                }
                expiration?.let { put(EXP, JsonPrimitive(it.epochSeconds)) }
                notBefore?.let { put(NBF, JsonPrimitive(it.epochSeconds)) }
                issuedAt?.let { put(IAT, JsonPrimitive(it.epochSeconds)) }
                jwtId?.let { put(JTI, JsonPrimitive(it)) }
                extra.forEach { (k, v) -> put(k, v) }
            })
    }

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
