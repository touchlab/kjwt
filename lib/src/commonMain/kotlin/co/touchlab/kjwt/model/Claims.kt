package co.touchlab.kjwt.model

import co.touchlab.kjwt.internal.JwtJson
import kotlinx.datetime.Instant
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull

class Claims(@PublishedApi internal val data: Map<String, JsonElement>) : Map<String, JsonElement> by data {

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

class ClaimsBuilder {
    var issuer: String? = null
    var subject: String? = null
    var audience: Set<String>? = null
    var expiration: Instant? = null
    var notBefore: Instant? = null
    var issuedAt: Instant? = null
    var jwtId: String? = null

    @PublishedApi internal val extra: MutableMap<String, JsonElement> = mutableMapOf()

    fun claim(name: String, value: JsonElement) {
        extra[name] = value
    }

    inline fun <reified T> claim(name: String, value: T) {
        extra[name] = JwtJson.encodeToJsonElement(value)
    }

    internal fun toJsonObject(): JsonObject = buildJsonObject {
        issuer?.let { put(Claims.ISS, JsonPrimitive(it)) }
        subject?.let { put(Claims.SUB, JsonPrimitive(it)) }
        audience?.let { aud ->
            if (aud.size == 1) put(Claims.AUD, JsonPrimitive(aud.first()))
            else put(Claims.AUD, JsonArray(aud.map { JsonPrimitive(it) }))
        }
        expiration?.let { put(Claims.EXP, JsonPrimitive(it.epochSeconds)) }
        notBefore?.let { put(Claims.NBF, JsonPrimitive(it.epochSeconds)) }
        issuedAt?.let { put(Claims.IAT, JsonPrimitive(it.epochSeconds)) }
        jwtId?.let { put(Claims.JTI, JsonPrimitive(it)) }
        extra.forEach { (k, v) -> put(k, v) }
    }

    internal fun build(): Claims = Claims(toJsonObject())
}