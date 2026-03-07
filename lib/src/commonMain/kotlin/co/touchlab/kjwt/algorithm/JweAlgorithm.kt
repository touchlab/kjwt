@file:OptIn(dev.whyoleg.cryptography.DelicateCryptographyApi::class)


package co.touchlab.kjwt.algorithm

import co.touchlab.kjwt.cryptography.SimpleKey
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.AES
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.algorithms.SHA384
import dev.whyoleg.cryptography.algorithms.SHA512
import dev.whyoleg.cryptography.materials.key.Key
import kotlin.jvm.JvmStatic
import kotlin.random.Random

sealed class JweKeyAlgorithm<PublicKey : Key, PrivateKey : Key>(val id: String) {
    internal suspend fun encrypt(
        key: PublicKey,
        contentAlgorithm: JweContentAlgorithm,
        plaintext: ByteArray,
        aad: ByteArray,
    ): JweEncryptResult {
        val (cek, encryptedKey) = generateContentEncryptionKey(key, contentAlgorithm)

        return when (contentAlgorithm) {
            JweContentAlgorithm.A128GCM,
            JweContentAlgorithm.A192GCM,
            JweContentAlgorithm.A256GCM,
                -> aesGcmEncrypt(cek, plaintext, aad, encryptedKey)

            JweContentAlgorithm.A128CbcHs256,
            JweContentAlgorithm.A192CbcHs384,
            JweContentAlgorithm.A256CbcHs512,
                -> aesCbcHmacEncrypt(cek, plaintext, aad, contentAlgorithm, encryptedKey)
        }
    }

    internal suspend fun decrypt(
        key: PrivateKey,
        contentAlgorithm: JweContentAlgorithm,
        encryptedKey: ByteArray,
        iv: ByteArray,
        ciphertext: ByteArray,
        tag: ByteArray,
        aad: ByteArray,
    ): ByteArray {
        val cek = getContentEncryptionKey(key, encryptedKey)

        return when (contentAlgorithm) {
            JweContentAlgorithm.A128GCM,
            JweContentAlgorithm.A192GCM,
            JweContentAlgorithm.A256GCM,
                -> aesGcmDecrypt(cek, iv, ciphertext, tag, aad)

            JweContentAlgorithm.A128CbcHs256,
            JweContentAlgorithm.A192CbcHs384,
            JweContentAlgorithm.A256CbcHs512,
                -> aesCbcHmacDecrypt(cek, iv, ciphertext, tag, aad, contentAlgorithm)
        }
    }

    internal abstract suspend fun generateContentEncryptionKey(
        key: PublicKey,
        contentAlgorithm: JweContentAlgorithm,
    ): Pair<ByteArray, ByteArray>

    internal abstract suspend fun getContentEncryptionKey(
        key: PrivateKey,
        encryptedKey: ByteArray,
    ): ByteArray

    sealed class OAEPBased(id: String) : JweKeyAlgorithm<RSA.OAEP.PublicKey, RSA.OAEP.PrivateKey>(id) {
        override suspend fun generateContentEncryptionKey(
            key: RSA.OAEP.PublicKey,
            contentAlgorithm: JweContentAlgorithm,
        ): Pair<ByteArray, ByteArray> {
            val cek = generateCek(contentAlgorithm)
            val encKey = key.encryptor().encrypt(cek)
            return Pair(cek, encKey)
        }

        override suspend fun getContentEncryptionKey(
            key: RSA.OAEP.PrivateKey,
            encryptedKey: ByteArray
        ): ByteArray = key.decryptor().decrypt(encryptedKey)
    }

    /** Direct use of a shared symmetric CEK — no key wrapping. */
    data object Dir : JweKeyAlgorithm<SimpleKey, SimpleKey>("dir") {
        override suspend fun generateContentEncryptionKey(
            key: SimpleKey,
            contentAlgorithm: JweContentAlgorithm,
        ): Pair<ByteArray, ByteArray> = Pair(key.value, ByteArray(0))

        override suspend fun getContentEncryptionKey(
            key: SimpleKey,
            encryptedKey: ByteArray
        ): ByteArray = key.value
    }

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

    override fun toString(): String = id

    companion object {
        private val all by lazy { listOf(Dir, RsaOaep, RsaOaep256) }

        fun fromId(id: String): JweKeyAlgorithm<*, *> =
            all.firstOrNull { it.id == id }
                ?: throw IllegalArgumentException("Unknown JWE key algorithm: '$id'")
    }
}

sealed class JweContentAlgorithm(val id: String) {
    data object A128GCM : JweContentAlgorithm("A128GCM")
    data object A192GCM : JweContentAlgorithm("A192GCM")
    data object A256GCM : JweContentAlgorithm("A256GCM")

    data object A128CbcHs256 : JweContentAlgorithm("A128CBC-HS256")
    data object A192CbcHs384 : JweContentAlgorithm("A192CBC-HS384")
    data object A256CbcHs512 : JweContentAlgorithm("A256CBC-HS512")

    override fun toString(): String = id

    companion object {
        @JvmStatic
        private val entries: List<JweContentAlgorithm> by lazy {
            listOf(
                A128GCM, A192GCM, A256GCM,
                A128CbcHs256, A192CbcHs384, A256CbcHs512,
            )
        }

        @JvmStatic
        fun fromId(id: String): JweContentAlgorithm =
            entries.firstOrNull { it.id == id }
                ?: throw IllegalArgumentException("Unknown JWE content algorithm: '$id'")
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

private fun generateCek(contentAlgorithm: JweContentAlgorithm): ByteArray =
    Random.nextBytes(cekSizeBytes(contentAlgorithm))

private fun cekSizeBytes(contentAlgorithm: JweContentAlgorithm): Int = when (contentAlgorithm) {
    JweContentAlgorithm.A128GCM -> 16
    JweContentAlgorithm.A192GCM -> 24
    JweContentAlgorithm.A256GCM -> 32
    JweContentAlgorithm.A128CbcHs256 -> 32  // 16 mac + 16 enc
    JweContentAlgorithm.A192CbcHs384 -> 48  // 24 mac + 24 enc
    JweContentAlgorithm.A256CbcHs512 -> 64  // 32 mac + 32 enc
}
// ---- AES-GCM ----
// AES.GCM.Key.cipher() returns AES.IvAuthenticatedCipher.
// encryptWithIv returns ciphertext || tag (tag = last GCM_TAG_SIZE bytes).

private const val GCM_IV_SIZE = 12
private const val GCM_TAG_SIZE = 16

private suspend fun aesGcmEncrypt(
    cek: ByteArray,
    plaintext: ByteArray,
    aad: ByteArray,
    encryptedKey: ByteArray,
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

private suspend fun aesGcmDecrypt(
    cek: ByteArray,
    iv: ByteArray,
    ciphertext: ByteArray,
    tag: ByteArray,
    aad: ByteArray,
): ByteArray {
    val aesKey = CryptographyProvider.Default.get(AES.GCM)
        .keyDecoder()
        .decodeFromByteArray(AES.Key.Format.RAW, cek)
    // Recombine ciphertext || tag before passing to the cipher
    return aesKey.cipher().decryptWithIv(iv, ciphertext + tag, aad)
}

// ---- AES-CBC + HMAC (RFC 7516 Appendix B) ----
// CEK first half = MAC key, second half = AES enc key.
// MAC input: AAD || IV || Ciphertext || AL (64-bit big-endian AAD length in bits)
// The resulting MAC is truncated: take first half as the JWE auth tag.

private const val CBC_IV_SIZE = 16

private suspend fun aesCbcHmacEncrypt(
    cek: ByteArray,
    plaintext: ByteArray,
    aad: ByteArray,
    contentAlgorithm: JweContentAlgorithm,
    encryptedKey: ByteArray,
): JweEncryptResult {
    val half = cek.size / 2
    val macKey = cek.copyOfRange(0, half)
    val encKey = cek.copyOfRange(half, cek.size)

    val iv = Random.nextBytes(CBC_IV_SIZE)

    val aesKey = CryptographyProvider.Default.get(AES.CBC)
        .keyDecoder()
        .decodeFromByteArray(AES.Key.Format.RAW, encKey)
    val ciphertext = aesKey.cipher().encryptWithIv(iv, plaintext)

    val tag = computeCbcHmacTag(macKey, aad, iv, ciphertext, contentAlgorithm)

    return JweEncryptResult(encryptedKey, iv, ciphertext, tag)
}

private suspend fun aesCbcHmacDecrypt(
    cek: ByteArray,
    iv: ByteArray,
    ciphertext: ByteArray,
    tag: ByteArray,
    aad: ByteArray,
    contentAlgorithm: JweContentAlgorithm,
): ByteArray {
    val half = cek.size / 2
    val macKey = cek.copyOfRange(0, half)
    val encKey = cek.copyOfRange(half, cek.size)

    val expectedTag = computeCbcHmacTag(macKey, aad, iv, ciphertext, contentAlgorithm)
    if (!expectedTag.contentEquals(tag)) {
        throw IllegalArgumentException("JWE authentication tag verification failed")
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
    contentAlgorithm: JweContentAlgorithm,
): ByteArray {
    // MAC input: AAD || IV || Ciphertext || AL (RFC 7516 §5.2.2.1)
    val al = aad.size.toLong() * 8
    val alBytes = ByteArray(8) { i -> ((al shr (56 - i * 8)) and 0xFF).toByte() }
    val macInput = aad + iv + ciphertext + alBytes

    val (hmacDigest, tagLen) = when (contentAlgorithm) {
        JweContentAlgorithm.A128CbcHs256 -> Pair(SHA256, 16)
        JweContentAlgorithm.A192CbcHs384 -> Pair(SHA384, 24)
        JweContentAlgorithm.A256CbcHs512 -> Pair(SHA512, 32)
        else -> error("Not a CBC-HMAC algorithm: $contentAlgorithm")
    }

    val hmacKey = CryptographyProvider.Default.get(HMAC)
        .keyDecoder(hmacDigest)
        .decodeFromByteArray(HMAC.Key.Format.RAW, macKey)
    val fullMac = hmacKey.signatureGenerator().generateSignature(macInput)

    // Per RFC 7516: truncate to the first T_LEN bytes
    return fullMac.copyOfRange(0, tagLen)
}