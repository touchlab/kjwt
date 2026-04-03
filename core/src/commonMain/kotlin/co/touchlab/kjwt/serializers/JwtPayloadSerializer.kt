package co.touchlab.kjwt.serializers

import co.touchlab.kjwt.internal.encodeBase64Url
import co.touchlab.kjwt.model.JwtPayload
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonObject

/**
 * Serializer for [JwtPayload] values to and from their JSON object representation.
 *
 * Serializes by encoding the underlying [JwtPayload.jsonData] JSON object directly. Deserializes
 * by parsing the JSON object and constructing a [JwtPayload] with the canonical Base64URL-encoded
 * representation of the serialized JSON as the raw payload bytes.
 */
public object JwtPayloadSerializer : KSerializer<JwtPayload> {
    private val delegate = JsonObject.serializer()
    override val descriptor: SerialDescriptor = delegate.descriptor

    override fun serialize(
        encoder: Encoder,
        value: JwtPayload,
    ) {
        encoder.encodeSerializableValue(delegate, value.jsonData)
    }

    override fun deserialize(decoder: Decoder): JwtPayload {
        val obj = decoder.decodeSerializableValue(delegate)
        return JwtPayload(
            obj.toString().encodeToByteArray().encodeBase64Url(),
            obj
        )
    }
}
