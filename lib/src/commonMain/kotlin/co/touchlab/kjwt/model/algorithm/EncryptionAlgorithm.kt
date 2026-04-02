@file:OptIn(DelicateCryptographyApi::class)

package co.touchlab.kjwt.model.algorithm

import co.touchlab.kjwt.cryptography.SimpleKey
import co.touchlab.kjwt.serializers.EncryptionAlgorithmSerializer
import dev.whyoleg.cryptography.CryptographyAlgorithmId
import dev.whyoleg.cryptography.DelicateCryptographyApi
import dev.whyoleg.cryptography.algorithms.Digest
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.algorithms.SHA1
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.materials.key.Key
import kotlinx.serialization.Serializable

@Serializable(EncryptionAlgorithmSerializer::class)
public sealed class EncryptionAlgorithm<PublicKey : Key, PrivateKey : Key>(
    override val id: String,
) : Jwa<PublicKey, PrivateKey> {
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
    public data object Dir : EncryptionAlgorithm<SimpleKey, SimpleKey>("dir")

    /**
     * Base class for RSA OAEP key encryption variants ([RsaOaep] and [RsaOaep256]).
     *
     * Subclasses wrap the Content Encryption Key (CEK) using RSA-OAEP with the appropriate digest.
     */
    public sealed class OAEPBased(
        id: String,
    ) : EncryptionAlgorithm<RSA.OAEP.PublicKey, RSA.OAEP.PrivateKey>(id),
        Jwa.UsesHashingAlgorithm {
        override val digest: CryptographyAlgorithmId<Digest>
            get() =
                when (this) {
                    RsaOaep -> SHA1
                    RsaOaep256 -> SHA256
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
        public fun fromId(id: String): EncryptionAlgorithm<*, *> =
            requireNotNull(entries.firstOrNull { it.id == id }) {
                "Unknown JWE key algorithm: '$id'"
            }
    }
}
