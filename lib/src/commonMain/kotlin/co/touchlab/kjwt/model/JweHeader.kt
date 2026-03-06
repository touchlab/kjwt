package co.touchlab.kjwt.model

import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject

data class JweHeader(
    val algorithm: String,
    val encryption: String,
    val type: String? = "JWT",
    val contentType: String? = null,
    val keyId: String? = null,
    val extra: Map<String, JsonElement> = emptyMap(),
) {
    internal fun toJsonObject(): JsonObject = buildJsonObject {
        put(ALG, JsonPrimitive(algorithm))
        put(ENC, JsonPrimitive(encryption))
        type?.let { put(TYP, JsonPrimitive(it)) }
        contentType?.let { put(CTY, JsonPrimitive(it)) }
        keyId?.let { put(KID, JsonPrimitive(it)) }
        extra.forEach { (k, v) -> put(k, v) }
    }

    companion object {
        const val ALG = "alg"
        const val ENC = "enc"
        const val TYP = "typ"
        const val CTY = "cty"
        const val KID = "kid"

        internal fun fromJsonObject(obj: JsonObject): JweHeader {
            val extra = obj.filterKeys { it !in setOf(ALG, ENC, TYP, CTY, KID) }
            return JweHeader(
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