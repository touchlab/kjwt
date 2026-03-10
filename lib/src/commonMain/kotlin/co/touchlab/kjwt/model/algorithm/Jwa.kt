package co.touchlab.kjwt.model.algorithm

import co.touchlab.kjwt.serializers.JwaSerializer
import dev.whyoleg.cryptography.materials.key.Key
import kotlinx.serialization.Serializable

@Serializable(JwaSerializer::class)
sealed interface Jwa<PublicKey : Key, PrivateKey : Key> {
    val id: String

    companion object {
        internal val entries: List<Jwa<*, *>> by lazy {
            EncryptionAlgorithm.entries + SigningAlgorithm.entries
        }

        fun fromId(id: String): Jwa<*, *> =
            entries.firstOrNull { it.id == id }
                ?: throw IllegalArgumentException("Unknown JSON Web Algorithm: '$id'")
    }
}