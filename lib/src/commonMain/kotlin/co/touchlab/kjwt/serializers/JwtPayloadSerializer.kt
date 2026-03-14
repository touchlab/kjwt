package co.touchlab.kjwt.serializers

import co.touchlab.kjwt.model.JwtPayload
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonObject

object JwtPayloadSerializer : KSerializer<JwtPayload> {
    private val delegate = JsonObject.serializer()
    override val descriptor: SerialDescriptor = delegate.descriptor

    override fun serialize(encoder: Encoder, value: JwtPayload) {
        encoder.encodeSerializableValue(delegate, value.jsonData)
    }

    override fun deserialize(decoder: Decoder): JwtPayload {
        val obj = decoder.decodeSerializableValue(delegate)
        return JwtPayload(obj)
    }
}
