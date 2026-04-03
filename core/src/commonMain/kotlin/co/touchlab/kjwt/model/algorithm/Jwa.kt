package co.touchlab.kjwt.model.algorithm

import co.touchlab.kjwt.serializers.JwaSerializer
import kotlinx.serialization.Serializable

/**
 * Sealed interface representing a JSON Web Algorithm (JWA) identifier as defined in RFC 7518.
 *
 * All concrete signing and encryption algorithms in the library implement this interface. The
 * [id] property holds the algorithm identifier string used in JWT headers (e.g. `"HS256"`,
 * `"RSA-OAEP"`). Use [Jwa.fromId] to resolve an identifier string to the corresponding instance.
 *
 * @see SigningAlgorithm
 * @see EncryptionAlgorithm
 */
@Serializable(JwaSerializer::class)
public sealed interface Jwa {
    /** The JWA algorithm identifier string (e.g. `"HS256"`, `"RS256"`). */
    public val id: String

    /** Marker interface for JWA algorithms that require a digest (hashing) function. */
    public interface UsesHashingAlgorithm {
        /** The [JwtDigest] used by this algorithm. */
        public val digest: JwtDigest
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
