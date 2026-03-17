package co.touchlab.kjwt.serializers

import co.touchlab.kjwt.model.JwtHeader
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonObject

public object JwtHeaderSerializer : KSerializer<JwtHeader> {
    private val delegate = JsonObject.serializer()
    override val descriptor: SerialDescriptor = delegate.descriptor

    override fun serialize(encoder: Encoder, value: JwtHeader) {
        encoder.encodeSerializableValue(delegate, value.jsonData)
    }

    override fun deserialize(decoder: Decoder): JwtHeader {
        val obj = decoder.decodeSerializableValue(delegate)
        return JwtHeader(obj)
    }
}
