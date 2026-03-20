@file:OptIn(DelicateCryptographyApi::class)

package co.touchlab.kjwt.model.algorithm

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.DelicateCryptographyApi
import dev.whyoleg.cryptography.algorithms.AES
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.algorithms.SHA384
import dev.whyoleg.cryptography.algorithms.SHA512
import kotlin.random.Random

public sealed class EncryptionContentAlgorithm(public val id: String) {
    /** AES-128 in GCM mode (`A128GCM`) content encryption algorithm. */
    public data object A128GCM : AesGCMBased("A128GCM")

    /** AES-192 in GCM mode (`A192GCM`) content encryption algorithm. */
    public data object A192GCM : AesGCMBased("A192GCM")

    /** AES-256 in GCM mode (`A256GCM`) content encryption algorithm. */
    public data object A256GCM : AesGCMBased("A256GCM")

    /** AES-128 CBC with HMAC-SHA-256 (`A128CBC-HS256`) content encryption algorithm. */
    public data object A128CbcHs256 : AesCBCBased("A128CBC-HS256")

    /** AES-192 CBC with HMAC-SHA-384 (`A192CBC-HS384`) content encryption algorithm. */
    public data object A192CbcHs384 : AesCBCBased("A192CBC-HS384")

    /** AES-256 CBC with HMAC-SHA-512 (`A256CBC-HS512`) content encryption algorithm. */
    public data object A256CbcHs512 : AesCBCBased("A256CBC-HS512")

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

    /**
     * Base class for AES GCM content encryption algorithms (A128GCM, A192GCM, A256GCM).
     *
     * Uses AES in Galois/Counter Mode, which provides both confidentiality and integrity.
     */
    public sealed class AesGCMBased(id: String) : EncryptionContentAlgorithm(id) {
        public companion object {
            private const val GCM_IV_SIZE = 12
            private const val GCM_TAG_SIZE = 16
        }

        override suspend fun encrypt(
            cek: ByteArray,
            plaintext: ByteArray,
            aad: ByteArray,
            encryptedKey: ByteArray
        ): JweEncryptResult {
            val aesKey = CryptographyProvider.Companion.Default.get(AES.GCM)
                .keyDecoder()
                .decodeFromByteArray(AES.Key.Format.RAW, cek)

            val cipher = aesKey.cipher()
            val iv = Random.Default.nextBytes(GCM_IV_SIZE)

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
            val aesKey = CryptographyProvider.Companion.Default.get(AES.GCM)
                .keyDecoder()
                .decodeFromByteArray(AES.Key.Format.RAW, cek)
            // Recombine ciphertext || tag before passing to the cipher
            return aesKey.cipher().decryptWithIv(iv, ciphertext + tag, aad)
        }
    }

    /**
     * Base class for AES CBC + HMAC content encryption algorithms (A128CBC-HS256, A192CBC-HS384, A256CBC-HS512).
     *
     * Uses AES in CBC mode combined with an HMAC tag for authenticated encryption per RFC 7516.
     */
    public sealed class AesCBCBased(id: String) : EncryptionContentAlgorithm(id) {
        public companion object {
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

            val iv = Random.Default.nextBytes(CBC_IV_SIZE)

            val aesKey = CryptographyProvider.Companion.Default.get(AES.CBC)
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

            val aesKey = CryptographyProvider.Companion.Default.get(AES.CBC)
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

            val hmacKey = CryptographyProvider.Companion.Default.get(HMAC.Companion)
                .keyDecoder(hmacDigest)
                .decodeFromByteArray(HMAC.Key.Format.RAW, macKey)
            val fullMac = hmacKey.signatureGenerator().generateSignature(macInput)

            // Per RFC 7516: truncate to the first T_LEN bytes
            return fullMac.copyOfRange(0, tagLen)
        }
    }

    override fun toString(): String = id

    /**
     * Generates a random Content Encryption Key (CEK) of the appropriate byte length for this algorithm.
     *
     * @return a freshly generated random CEK as a [ByteArray]
     */
    internal fun generateCek(): ByteArray =
        Random.Default.nextBytes(
            when (this) {
                A128GCM -> 16
                A192GCM -> 24
                A256GCM -> 32
                A128CbcHs256 -> 32 // 16 mac + 16 enc
                A192CbcHs384 -> 48 // 24 mac + 24 enc
                A256CbcHs512 -> 64 // 32 mac + 32 enc
            }
        )

    public companion object {
        /**
         * List of all supported [EncryptionContentAlgorithm] instances.
         */
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

        /**
         * Returns the [EncryptionContentAlgorithm] whose [id] matches the given string.
         *
         * @param id the JWE content algorithm identifier to look up (e.g. `"A256GCM"`)
         * @return the matching [EncryptionContentAlgorithm] instance
         * @throws IllegalArgumentException if no algorithm with the given [id] is registered
         */
        public fun fromId(id: String): EncryptionContentAlgorithm =
            requireNotNull(entries.firstOrNull { it.id == id }) {
                "Unknown JWE content algorithm: '$id'"
            }
    }
}
