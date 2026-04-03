package co.touchlab.kjwt.serializers

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlin.time.Instant

/**
 * Serializer for [Instant] values as Unix epoch seconds (a JSON long integer).
 *
 * Used for JWT NumericDate fields (`exp`, `nbf`, `iat`) as defined by RFC 7519 §2. Serializes an
 * [Instant] to its [Instant.epochSeconds] value and deserializes a long back to an [Instant].
 *
 * @see co.touchlab.kjwt.ext.expiration
 * @see co.touchlab.kjwt.ext.notBefore
 * @see co.touchlab.kjwt.ext.issuedAt
 */
public object InstantEpochSecondsSerializer : KSerializer<Instant> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("Instant", PrimitiveKind.LONG)

    override fun deserialize(decoder: Decoder): Instant = Instant.fromEpochSeconds(decoder.decodeLong())

    override fun serialize(
        encoder: Encoder,
        value: Instant,
    ) {
        encoder.encodeLong(value.epochSeconds)
    }
}
