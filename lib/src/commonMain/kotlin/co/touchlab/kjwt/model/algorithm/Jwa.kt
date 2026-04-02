package co.touchlab.kjwt.model.algorithm

import co.touchlab.kjwt.serializers.JwaSerializer
import dev.whyoleg.cryptography.CryptographyAlgorithmId
import dev.whyoleg.cryptography.algorithms.Digest
import kotlinx.serialization.Serializable

@Serializable(JwaSerializer::class)
public sealed interface Jwa {
    /** The JWA algorithm identifier string (e.g. `"HS256"`, `"RS256"`). */
    public val id: String

    /** Marker interface for JWA algorithms that require a digest (hashing) function. */
    public interface UsesHashingAlgorithm {
        /** The [CryptographyAlgorithmId] of the digest used by this algorithm. */
        public val digest: CryptographyAlgorithmId<Digest>
    }

    public companion object {
        internal val entries: List<Jwa> by lazy {
            EncryptionAlgorithm.entries + SigningAlgorithm.entries
        }

        /**
         * Returns the [Jwa] instance whose [id] matches the given string.
         *
         * @param id the JWA algorithm identifier to look up (e.g. `"HS256"`)
         * @return the matching [Jwa] instance
         * @throws IllegalArgumentException if no algorithm with the given [id] is registered
         */
        public fun fromId(id: String): Jwa =
            requireNotNull(entries.firstOrNull { it.id == id }) {
                "Unknown JSON Web Algorithm: '$id'"
            }
    }
}
