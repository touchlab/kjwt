package co.touchlab.kjwt.model.algorithm

import co.touchlab.kjwt.serializers.EncryptionAlgorithmSerializer
import kotlinx.serialization.Serializable

/**
 * Sealed class representing the JWE key management algorithms defined in RFC 7518.
 *
 * The key management algorithm determines how the Content Encryption Key (CEK) is protected in
 * the JWE compact serialization. The supported algorithms are:
 * - [RsaOaep] — RSA-OAEP with SHA-1 key wrapping.
 * - [RsaOaep256] — RSA-OAEP with SHA-256 key wrapping.
 * - [Dir] — direct use of a shared symmetric key as the CEK; no key wrapping is performed.
 *
 * Use [fromId] to look up an instance by its JWA identifier string.
 *
 * @see EncryptionContentAlgorithm
 * @see co.touchlab.kjwt.builder.JwtBuilder.encryptWith
 */
@Serializable(EncryptionAlgorithmSerializer::class)
public sealed class EncryptionAlgorithm(
    override val id: String,
) : Jwa {
    /**
     * RSA-OAEP with SHA-1.
     * Key must be created with `RSA.OAEP.keyPairGenerator(SHA1)` or equivalent.
     */
    public data object RsaOaep : OAEPBased("RSA-OAEP")

    /**
     * RSA-OAEP with SHA-256.
     * Key must be created with `RSA.OAEP.keyPairGenerator(SHA256)` or equivalent.
     */
    public data object RsaOaep256 : OAEPBased("RSA-OAEP-256")

    /** Direct use of a shared symmetric CEK — no key wrapping. */
    public data object Dir : EncryptionAlgorithm("dir")

    /**
     * Base class for RSA OAEP key encryption variants ([RsaOaep] and [RsaOaep256]).
     *
     * Subclasses wrap the Content Encryption Key (CEK) using RSA-OAEP with the appropriate digest.
     */
    public sealed class OAEPBased(
        id: String,
    ) : EncryptionAlgorithm(id),
        Jwa.UsesHashingAlgorithm {
        override val digest: JwtDigest
            get() =
                when (this) {
                    RsaOaep -> JwtDigest.SHA1
                    RsaOaep256 -> JwtDigest.SHA256
                }
    }

    override fun toString(): String = id

    public companion object {
        /**
         * List of all supported [EncryptionAlgorithm] instances.
         */
        internal val entries by lazy { listOf(Dir, RsaOaep, RsaOaep256) }

        /**
         * Returns the [EncryptionAlgorithm] whose [id] matches the given string.
         *
         * @param id the JWE key algorithm identifier to look up (e.g. `"RSA-OAEP"`)
         * @return the matching [EncryptionAlgorithm] instance
         * @throws IllegalArgumentException if no algorithm with the given [id] is registered
         */
        public fun fromId(id: String): EncryptionAlgorithm =
            requireNotNull(entries.firstOrNull { it.id == id }) {
                "Unknown JWE key algorithm: '$id'"
            }
    }
}
