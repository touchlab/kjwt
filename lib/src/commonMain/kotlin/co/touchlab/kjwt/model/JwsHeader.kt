package co.touchlab.kjwt.model

import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject

data class JwsHeader(
    val algorithm: String,
    val type: String? = "JWT",
    val contentType: String? = null,
    val keyId: String? = null,
    val extra: Map<String, JsonElement> = emptyMap(),
) {
    internal fun toJsonObject(): JsonObject = buildJsonObject {
        put(ALG, JsonPrimitive(algorithm))
        type?.let { put(TYP, JsonPrimitive(it)) }
        contentType?.let { put(CTY, JsonPrimitive(it)) }
        keyId?.let { put(KID, JsonPrimitive(it)) }
        extra.forEach { (k, v) -> put(k, v) }
    }

    companion object {
        const val ALG = "alg"
        const val TYP = "typ"
        const val CTY = "cty"
        const val KID = "kid"

        internal fun fromJsonObject(obj: JsonObject): JwsHeader {
            val extra = obj.filterKeys { it !in setOf(ALG, TYP, CTY, KID) }
            return JwsHeader(
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

class JwsHeaderBuilder {
    var type: String? = "JWT"
    var contentType: String? = null
    var keyId: String? = null
    private val extra: MutableMap<String, JsonElement> = mutableMapOf()

    fun extra(name: String, value: JsonElement) {
        extra[name] = value
    }

    internal fun build(algorithm: String) = JwsHeader(
        algorithm = algorithm,
        type = type,
        contentType = contentType,
        keyId = keyId,
        extra = extra,
    )
}