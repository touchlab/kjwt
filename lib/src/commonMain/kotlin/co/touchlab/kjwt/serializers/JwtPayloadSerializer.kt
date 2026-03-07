package co.touchlab.kjwt.serializers

import co.touchlab.kjwt.model.JwtPayload
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject

fun <T : JwtPayload> KSerializer<T>.asJwtPayloadSerializer(): KSerializer<T> =
    this as? JwtPayloadSerializer ?: JwtPayloadSerializer(this)

class JwtPayloadSerializer<T : JwtPayload>(private val dataSerializer: KSerializer<T>) : KSerializer<T> {
    private val extraPropertyName: String = "jsonData"

    override val descriptor: SerialDescriptor = dataSerializer.descriptor

    override fun deserialize(decoder: Decoder): T {
        val input = decoder as? JsonDecoder
            ?: throw SerializationException("JSON format required")

        // 1. Decode the entire JSON object
        val root = input.decodeJsonElement().jsonObject

        // 2. Map EVERYTHING from the root into the "extra" field
        // We nest the entire root object inside the property name we're targeting
        val jsonWithAll = JsonObject(root + (extraPropertyName to root))

        return input.json.decodeFromJsonElement(dataSerializer, jsonWithAll)
    }

    override fun serialize(encoder: Encoder, value: T) {
        val output = encoder as? JsonEncoder
            ?: throw SerializationException("JSON format required")

        // 1. Encode the object normally
        val baseJson = output.json.encodeToJsonElement(dataSerializer, value)
            .jsonObject[extraPropertyName]
            ?: throw SerializationException("Failed to serialize $value")

        output.encodeJsonElement(baseJson)
    }
}