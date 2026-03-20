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
    public data object Dir : EncryptionAlgorithm<SimpleKey, SimpleKey>("dir") {
        override suspend fun generateContentEncryptionKey(
            key: SimpleKey,
            contentAlgorithm: EncryptionContentAlgorithm,
        ): Pair<ByteArray, ByteArray> = Pair(key.value, ByteArray(0))

        override suspend fun getContentEncryptionKey(
            key: SimpleKey,
            encryptedKey: ByteArray
        ): ByteArray = key.value
    }

    internal suspend fun encrypt(
        key: PublicKey,
        contentAlgorithm: EncryptionContentAlgorithm,
        plaintext: ByteArray,
        aad: ByteArray,
    ): JweEncryptResult {
        val (cek, encryptedKey) = generateContentEncryptionKey(key, contentAlgorithm)
        return contentAlgorithm.encrypt(cek, plaintext, aad, encryptedKey)
    }

    internal suspend fun decrypt(
        key: PrivateKey,
        contentAlgorithm: EncryptionContentAlgorithm,
        encryptedKey: ByteArray,
        iv: ByteArray,
        ciphertext: ByteArray,
        tag: ByteArray,
        aad: ByteArray,
    ): ByteArray {
        val cek = getContentEncryptionKey(key, encryptedKey)
        return contentAlgorithm.decrypt(cek, iv, ciphertext, tag, aad)
    }

    internal abstract suspend fun generateContentEncryptionKey(
        key: PublicKey,
        contentAlgorithm: EncryptionContentAlgorithm,
    ): Pair<ByteArray, ByteArray>

    internal abstract suspend fun getContentEncryptionKey(
        key: PrivateKey,
        encryptedKey: ByteArray,
    ): ByteArray

    /**
     * Base class for RSA OAEP key encryption variants ([RsaOaep] and [RsaOaep256]).
     *
     * Subclasses wrap the Content Encryption Key (CEK) using RSA-OAEP with the appropriate digest.
     */
    public sealed class OAEPBased(
        id: String,
    ) : EncryptionAlgorithm<RSA.OAEP.PublicKey, RSA.OAEP.PrivateKey>(id), Jwa.UsesHashingAlgorithm {
        override val digest: CryptographyAlgorithmId<Digest>
            get() = when (this) {
                RsaOaep -> SHA1
                RsaOaep256 -> SHA256
            }

        override suspend fun generateContentEncryptionKey(
            key: RSA.OAEP.PublicKey,
            contentAlgorithm: EncryptionContentAlgorithm,
        ): Pair<ByteArray, ByteArray> {
            val cek = contentAlgorithm.generateCek()
            val encKey = key.encryptor().encrypt(cek)
            return Pair(cek, encKey)
        }

        override suspend fun getContentEncryptionKey(
            key: RSA.OAEP.PrivateKey,
            encryptedKey: ByteArray
        ): ByteArray = key.decryptor().decrypt(encryptedKey)
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
