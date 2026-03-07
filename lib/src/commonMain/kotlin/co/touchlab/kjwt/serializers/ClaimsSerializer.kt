package co.touchlab.kjwt.serializers

import co.touchlab.kjwt.model.Claims
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonObject

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