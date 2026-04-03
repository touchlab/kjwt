package co.touchlab.kjwt.serializers

import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive

/**
 * Deserializer for the JWT `aud` (audience) claim as defined by RFC 7519.
 *
 * Accepts both a single JSON string value and a JSON array of strings, normalizing the result to a
 * [Set] of strings in either case. An unrecognized JSON structure produces an empty set.
 *
 * @see co.touchlab.kjwt.ext.audience
 */
public object AudienceDeserializer : DeserializationStrategy<Set<String>> {
    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("Audience")

    override fun deserialize(decoder: Decoder): Set<String> =
        when (val element = (decoder as JsonDecoder).decodeJsonElement()) {
            is JsonArray -> element.mapNotNull { it.jsonPrimitive.contentOrNull }.toSet()
            is JsonPrimitive -> setOf(element.content)
            else -> emptySet()
        }
}
