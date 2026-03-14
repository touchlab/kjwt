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

object JwaSerializer : KSerializer<Jwa<*, *>> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("Jwa", PrimitiveKind.STRING)

    override fun serialize(
        encoder: Encoder,
        value: Jwa<*, *>
    ) {
        encoder.encodeString(value.id)
    }

    override fun deserialize(decoder: Decoder): Jwa<*, *> =
        Jwa.fromId(decoder.decodeString())
}

object EncryptionAlgorithmSerializer : KSerializer<EncryptionAlgorithm<*, *>> {
    override val descriptor: SerialDescriptor = JwaSerializer.descriptor

    override fun serialize(encoder: Encoder, value: EncryptionAlgorithm<*, *>) {
        encoder.encodeString(value.id)
    }

    override fun deserialize(decoder: Decoder): EncryptionAlgorithm<*, *> =
        EncryptionAlgorithm.fromId(decoder.decodeString())
}

object SigningAlgorithmSerializer : KSerializer<SigningAlgorithm<*, *>> {
    override val descriptor: SerialDescriptor = JwaSerializer.descriptor

    override fun serialize(encoder: Encoder, value: SigningAlgorithm<*, *>) {
        encoder.encodeString(value.id)
    }

    override fun deserialize(decoder: Decoder): SigningAlgorithm<*, *> =
        SigningAlgorithm.fromId(decoder.decodeString())
}
