package co.touchlab.kjwt.serializers

import co.touchlab.kjwt.model.JwtHeader.Companion.ALG
import co.touchlab.kjwt.model.JwtHeader.Companion.CTY
import co.touchlab.kjwt.model.JwtHeader.Companion.KID
import co.touchlab.kjwt.model.JwtHeader.Companion.TYP
import co.touchlab.kjwt.model.JwtHeader.Jws
import kotlin.collections.component1
import kotlin.collections.component2
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject


object JwsHeaderSerializer : KSerializer<Jws> {
    private val delegate = JsonObject.serializer()
    override val descriptor: SerialDescriptor = delegate.descriptor

    override fun serialize(encoder: Encoder, value: Jws) {
        encoder.encodeSerializableValue(
            delegate,
            buildJsonObject {
                put(ALG, JsonPrimitive(value.algorithm))
                value.type?.let { put(TYP, JsonPrimitive(it)) }
                value.contentType?.let { put(CTY, JsonPrimitive(it)) }
                value.keyId?.let { put(KID, JsonPrimitive(it)) }
                value.extra.forEach { (k, v) -> put(k, v) }
            }
        )
    }

    override fun deserialize(decoder: Decoder): Jws {
        val obj = decoder.decodeSerializableValue(delegate)
        val extra = obj.filterKeys { it !in setOf(ALG, TYP, CTY, KID) }

        return Jws(
            algorithm = obj[ALG]?.let { (it as JsonPrimitive).content }
                ?: error("Missing 'alg' in JWS header"),
            type = (obj[TYP] as? JsonPrimitive)?.content,
            contentType = (obj[CTY] as? JsonPrimitive)?.content,
            keyId = (obj[KID] as? JsonPrimitive)?.content,
            extra = extra,
        )
    }
}