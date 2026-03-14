package co.touchlab.kjwt.model.algorithm

import co.touchlab.kjwt.serializers.JwaSerializer
import dev.whyoleg.cryptography.CryptographyAlgorithmId
import dev.whyoleg.cryptography.algorithms.Digest
import dev.whyoleg.cryptography.materials.key.Key
import kotlinx.serialization.Serializable

@Serializable(JwaSerializer::class)
sealed interface Jwa<PublicKey : Key, PrivateKey : Key> {
    val id: String

    interface UsesHashingAlgorithm {
        val digest: CryptographyAlgorithmId<Digest>
    }

    companion object {
        internal val entries: List<Jwa<*, *>> by lazy {
            EncryptionAlgorithm.entries + SigningAlgorithm.entries
        }

        fun fromId(id: String): Jwa<*, *> =
            requireNotNull(entries.firstOrNull { it.id == id }) {
                "Unknown JSON Web Algorithm: '$id'"
            }
    }
}
