@file:OptIn(DelicateCryptographyApi::class)

package co.touchlab.kjwt.model.algorithm

import co.touchlab.kjwt.cryptography.SimpleKey
import co.touchlab.kjwt.serializers.EncryptionAlgorithmSerializer
import dev.whyoleg.cryptography.CryptographyAlgorithmId
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.DelicateCryptographyApi
import dev.whyoleg.cryptography.algorithms.AES
import dev.whyoleg.cryptography.algorithms.Digest
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.algorithms.SHA1
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.algorithms.SHA384
import dev.whyoleg.cryptography.algorithms.SHA512
import dev.whyoleg.cryptography.materials.key.Key
import kotlinx.serialization.Serializable
import kotlin.random.Random

@Serializable(EncryptionAlgorithmSerializer::class)
sealed class EncryptionAlgorithm<PublicKey : Key, PrivateKey : Key>(
    override val id: String,
) : Jwa<PublicKey, PrivateKey> {
    /**
     * RSA-OAEP with SHA-1.
     * Key must be created with `RSA.OAEP.keyPairGenerator(SHA1)` or equivalent.
     */
    data object RsaOaep : OAEPBased("RSA-OAEP")

    /**
     * RSA-OAEP with SHA-256.
     * Key must be created with `RSA.OAEP.keyPairGenerator(SHA256)` or equivalent.
     */
    data object RsaOaep256 : OAEPBased("RSA-OAEP-256")

    /** Direct use of a shared symmetric CEK — no key wrapping. */
    data object Dir : EncryptionAlgorithm<SimpleKey, SimpleKey>("dir") {
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

    sealed class OAEPBased(
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

    companion object {
        internal val entries by lazy { listOf(Dir, RsaOaep, RsaOaep256) }

        fun fromId(id: String): EncryptionAlgorithm<*, *> =
            requireNotNull(entries.firstOrNull { it.id == id }) {
                "Unknown JWE key algorithm: '$id'"
            }
    }
}

sealed class EncryptionContentAlgorithm(val id: String) {
    data object A128GCM : AesGCMBased("A128GCM")
    data object A192GCM : AesGCMBased("A192GCM")
    data object A256GCM : AesGCMBased("A256GCM")

    data object A128CbcHs256 : AesCBCBased("A128CBC-HS256")
    data object A192CbcHs384 : AesCBCBased("A192CBC-HS384")
    data object A256CbcHs512 : AesCBCBased("A256CBC-HS512")

    internal abstract suspend fun encrypt(
        cek: ByteArray,
        plaintext: ByteArray,
        aad: ByteArray,
        encryptedKey: ByteArray,
    ): JweEncryptResult

    internal abstract suspend fun decrypt(
        cek: ByteArray,
        iv: ByteArray,
        ciphertext: ByteArray,
        tag: ByteArray,
        aad: ByteArray,
    ): ByteArray

    sealed class AesGCMBased(id: String) : EncryptionContentAlgorithm(id) {
        companion object {
            private const val GCM_IV_SIZE = 12
            private const val GCM_TAG_SIZE = 16
        }

        override suspend fun encrypt(
            cek: ByteArray,
            plaintext: ByteArray,
            aad: ByteArray,
            encryptedKey: ByteArray
        ): JweEncryptResult {
            val aesKey = CryptographyProvider.Default.get(AES.GCM)
                .keyDecoder()
                .decodeFromByteArray(AES.Key.Format.RAW, cek)

            val cipher = aesKey.cipher()
            val iv = Random.nextBytes(GCM_IV_SIZE)

            // encryptWithIv returns ciphertext || auth_tag
            val combined = cipher.encryptWithIv(iv, plaintext, aad)
            val ctLen = combined.size - GCM_TAG_SIZE
            val ciphertext = combined.copyOfRange(0, ctLen)
            val tag = combined.copyOfRange(ctLen, combined.size)

            return JweEncryptResult(encryptedKey, iv, ciphertext, tag)
        }

        override suspend fun decrypt(
            cek: ByteArray,
            iv: ByteArray,
            ciphertext: ByteArray,
            tag: ByteArray,
            aad: ByteArray
        ): ByteArray {
            val aesKey = CryptographyProvider.Default.get(AES.GCM)
                .keyDecoder()
                .decodeFromByteArray(AES.Key.Format.RAW, cek)
            // Recombine ciphertext || tag before passing to the cipher
            return aesKey.cipher().decryptWithIv(iv, ciphertext + tag, aad)
        }
    }

    sealed class AesCBCBased(id: String) : EncryptionContentAlgorithm(id) {
        companion object {
            private const val CBC_IV_SIZE = 16
        }

        override suspend fun encrypt(
            cek: ByteArray,
            plaintext: ByteArray,
            aad: ByteArray,
            encryptedKey: ByteArray
        ): JweEncryptResult {
            val half = cek.size / 2
            val macKey = cek.copyOfRange(0, half)
            val encKey = cek.copyOfRange(half, cek.size)

            val iv = Random.nextBytes(CBC_IV_SIZE)

            val aesKey = CryptographyProvider.Default.get(AES.CBC)
                .keyDecoder()
                .decodeFromByteArray(AES.Key.Format.RAW, encKey)
            val ciphertext = aesKey.cipher().encryptWithIv(iv, plaintext)

            val tag = computeCbcHmacTag(macKey, aad, iv, ciphertext)

            return JweEncryptResult(encryptedKey, iv, ciphertext, tag)
        }

        override suspend fun decrypt(
            cek: ByteArray,
            iv: ByteArray,
            ciphertext: ByteArray,
            tag: ByteArray,
            aad: ByteArray
        ): ByteArray {
            val half = cek.size / 2
            val macKey = cek.copyOfRange(0, half)
            val encKey = cek.copyOfRange(half, cek.size)

            val expectedTag = computeCbcHmacTag(macKey, aad, iv, ciphertext)
            require(expectedTag.contentEquals(tag)) {
                "JWE authentication tag verification failed"
            }

            val aesKey = CryptographyProvider.Default.get(AES.CBC)
                .keyDecoder()
                .decodeFromByteArray(AES.Key.Format.RAW, encKey)
            return aesKey.cipher().decryptWithIv(iv, ciphertext)
        }

        private suspend fun computeCbcHmacTag(
            macKey: ByteArray,
            aad: ByteArray,
            iv: ByteArray,
            ciphertext: ByteArray,
        ): ByteArray {
            // MAC input: AAD || IV || Ciphertext || AL (RFC 7516 §5.2.2.1)
            val al = aad.size.toLong() * 8
            val alBytes = ByteArray(8) { i -> ((al shr (56 - i * 8)) and 0xFF).toByte() }
            val macInput = aad + iv + ciphertext + alBytes

            val (hmacDigest, tagLen) = when (this) {
                A128CbcHs256 -> Pair(SHA256, 16)
                A192CbcHs384 -> Pair(SHA384, 24)
                A256CbcHs512 -> Pair(SHA512, 32)
            }

            val hmacKey = CryptographyProvider.Default.get(HMAC)
                .keyDecoder(hmacDigest)
                .decodeFromByteArray(HMAC.Key.Format.RAW, macKey)
            val fullMac = hmacKey.signatureGenerator().generateSignature(macInput)

            // Per RFC 7516: truncate to the first T_LEN bytes
            return fullMac.copyOfRange(0, tagLen)
        }
    }

    override fun toString(): String = id

    internal fun generateCek(): ByteArray =
        Random.nextBytes(
            when (this) {
                A128GCM -> 16
                A192GCM -> 24
                A256GCM -> 32
                A128CbcHs256 -> 32 // 16 mac + 16 enc
                A192CbcHs384 -> 48 // 24 mac + 24 enc
                A256CbcHs512 -> 64 // 32 mac + 32 enc
            }
        )

    companion object {
        internal val entries: List<EncryptionContentAlgorithm> by lazy {
            listOf(
                A128GCM,
                A192GCM,
                A256GCM,
                A128CbcHs256,
                A192CbcHs384,
                A256CbcHs512,
            )
        }

        fun fromId(id: String): EncryptionContentAlgorithm =
            requireNotNull(entries.firstOrNull { it.id == id }) {
                "Unknown JWE content algorithm: '$id'"
            }
    }
}

internal data class JweEncryptResult(
    val encryptedKey: ByteArray,
    val iv: ByteArray,
    val ciphertext: ByteArray,
    val tag: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JweEncryptResult

        if (!encryptedKey.contentEquals(other.encryptedKey)) return false
        if (!iv.contentEquals(other.iv)) return false
        if (!ciphertext.contentEquals(other.ciphertext)) return false
        if (!tag.contentEquals(other.tag)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = encryptedKey.contentHashCode()
        result = 31 * result + iv.contentHashCode()
        result = 31 * result + ciphertext.contentHashCode()
        result = 31 * result + tag.contentHashCode()
        return result
    }
}
