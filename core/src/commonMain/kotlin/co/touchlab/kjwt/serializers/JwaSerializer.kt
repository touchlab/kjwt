package co.touchlab.kjwt.serializers

import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.Jwa
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Serializer for [Jwa] values as their JWA algorithm identifier string (e.g. `"HS256"`, `"RSA-OAEP"`).
 *
 * Converts between the sealed [Jwa] hierarchy and its string `id` representation using [Jwa.fromId]
 * for deserialization. Registered via `@Serializable(JwaSerializer::class)` on [Jwa].
 */
public object JwaSerializer : KSerializer<Jwa> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("Jwa", PrimitiveKind.STRING)

    override fun serialize(
        encoder: Encoder,
        value: Jwa,
    ) {
        encoder.encodeString(value.id)
    }

    override fun deserialize(decoder: Decoder): Jwa = Jwa.fromId(decoder.decodeString())
}

/**
 * Serializer for [EncryptionAlgorithm] values as their JWA identifier string (e.g. `"RSA-OAEP"`, `"dir"`).
 *
 * Converts between [EncryptionAlgorithm] and its string `id` using [EncryptionAlgorithm.fromId]
 * for deserialization. Used for the `alg` header field in JWE tokens per RFC 7516.
 */
public object EncryptionAlgorithmSerializer : KSerializer<EncryptionAlgorithm> {
    override val descriptor: SerialDescriptor = JwaSerializer.descriptor

    override fun serialize(
        encoder: Encoder,
        value: EncryptionAlgorithm,
    ) {
        encoder.encodeString(value.id)
    }

    override fun deserialize(decoder: Decoder): EncryptionAlgorithm = EncryptionAlgorithm.fromId(
        decoder.decodeString()
    )
}

/**
 * Serializer for [SigningAlgorithm] values as their JWA identifier string (e.g. `"HS256"`, `"RS256"`).
 *
 * Converts between [SigningAlgorithm] and its string `id` using [SigningAlgorithm.fromId]
 * for deserialization. Used for the `alg` header field in JWS tokens per RFC 7515.
 */
public object SigningAlgorithmSerializer : KSerializer<SigningAlgorithm> {
    override val descriptor: SerialDescriptor = JwaSerializer.descriptor

    override fun serialize(
        encoder: Encoder,
        value: SigningAlgorithm,
    ) {
        encoder.encodeString(value.id)
    }

    override fun deserialize(decoder: Decoder): SigningAlgorithm = SigningAlgorithm.fromId(decoder.decodeString())
}
