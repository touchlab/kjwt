package co.touchlab.kjwt.model

import co.touchlab.kjwt.internal.JwtJson
import kotlin.time.Instant
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull

@Serializable(with = Claims.ClaimsSerializer::class)
class Claims(@PublishedApi internal val data: Map<String, JsonElement>) {

    val issuer: String? get() = data[ISS]?.jsonPrimitive?.content

    val subject: String? get() = data[SUB]?.jsonPrimitive?.content

    val audience: Set<String>?
        get() = data[AUD]?.let { aud ->
            when (aud) {
                is JsonArray -> aud.jsonArray.mapNotNull { it.jsonPrimitive.content }.toSet()
                is JsonPrimitive -> setOf(aud.content)
                else -> null
            }
        }

    val expiration: Instant? get() = data[EXP]?.jsonPrimitive?.longOrNull?.let { Instant.fromEpochSeconds(it) }

    val notBefore: Instant? get() = data[NBF]?.jsonPrimitive?.longOrNull?.let { Instant.fromEpochSeconds(it) }

    val issuedAt: Instant? get() = data[IAT]?.jsonPrimitive?.longOrNull?.let { Instant.fromEpochSeconds(it) }

    val jwtId: String? get() = data[JTI]?.jsonPrimitive?.content

    inline fun <reified T> getClaim(name: String): T? {
        val element = data[name] ?: return null
        return JwtJson.decodeFromJsonElement(kotlinx.serialization.serializer<T>(), element)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Claims

        if (data != other.data) return false
        if (issuer != other.issuer) return false
        if (subject != other.subject) return false
        if (audience != other.audience) return false
        if (expiration != other.expiration) return false
        if (notBefore != other.notBefore) return false
        if (issuedAt != other.issuedAt) return false
        if (jwtId != other.jwtId) return false

        return true
    }

    override fun hashCode(): Int {
        var result = data.hashCode()
        result = 31 * result + (issuer?.hashCode() ?: 0)
        result = 31 * result + (subject?.hashCode() ?: 0)
        result = 31 * result + (audience?.hashCode() ?: 0)
        result = 31 * result + (expiration?.hashCode() ?: 0)
        result = 31 * result + (notBefore?.hashCode() ?: 0)
        result = 31 * result + (issuedAt?.hashCode() ?: 0)
        result = 31 * result + (jwtId?.hashCode() ?: 0)
        return result
    }

    override fun toString(): String =
        "Claims(" +
                "data=$data, " +
                "issuer=$issuer, " +
                "subject=$subject, " +
                "audience=$audience, " +
                "expiration=$expiration, " +
                "notBefore=$notBefore, " +
                "issuedAt=$issuedAt, " +
                "jwtId=$jwtId" +
                ")"

    object ClaimsSerializer : KSerializer<Claims> {
        private val delegate = JsonObject.serializer()
        override val descriptor: SerialDescriptor = delegate.descriptor

        override fun serialize(encoder: Encoder, value: Claims) {
            encoder.encodeSerializableValue(delegate, JsonObject(value.data))
        }

        override fun deserialize(decoder: Decoder): Claims {
            return Claims(decoder.decodeSerializableValue(delegate))
        }
    }

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
            }
        )
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