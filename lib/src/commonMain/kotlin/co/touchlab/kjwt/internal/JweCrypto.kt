@file:OptIn(dev.whyoleg.cryptography.DelicateCryptographyApi::class)

package co.touchlab.kjwt.internal

import co.touchlab.kjwt.algorithm.JweContentAlgorithm
import co.touchlab.kjwt.algorithm.JweKeyAlgorithm
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.AES
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.algorithms.SHA384
import dev.whyoleg.cryptography.algorithms.SHA512
import kotlin.random.Random

internal data class JweEncryptResult(
    val encryptedKey: ByteArray,
    val iv: ByteArray,
    val ciphertext: ByteArray,
    val tag: ByteArray,
)

/**
 * Encrypts [plaintext] according to the JWE compact serialization process.
 *
 * [aad] is the ASCII bytes of the base64url-encoded JWE header.
 *
 * Key types by [keyAlgorithm]:
 * - Dir           → [ByteArray] (raw CEK bytes, length must match [contentAlgorithm])
 * - RSA-OAEP      → [RSA.OAEP.PublicKey] (key created with SHA-1)
 * - RSA-OAEP-256  → [RSA.OAEP.PublicKey] (key created with SHA-256)
 */
internal suspend fun jweEncrypt(
    key: Any,
    keyAlgorithm: JweKeyAlgorithm,
    contentAlgorithm: JweContentAlgorithm,
    plaintext: ByteArray,
    aad: ByteArray,
): JweEncryptResult {
    val provider = CryptographyProvider.Default

    val (cek, encryptedKey) = when (keyAlgorithm) {
        JweKeyAlgorithm.Dir -> {
            val cek = key as ByteArray
            Pair(cek, ByteArray(0))
        }
        JweKeyAlgorithm.RsaOaep,
        JweKeyAlgorithm.RsaOaep256,
        -> {
            val cek = generateCek(contentAlgorithm)
            val publicKey = key as RSA.OAEP.PublicKey
            val encKey = publicKey.encryptor().encrypt(cek)
            Pair(cek, encKey)
        }
    }

    return when (contentAlgorithm) {
        JweContentAlgorithm.A128GCM,
        JweContentAlgorithm.A192GCM,
        JweContentAlgorithm.A256GCM,
        -> aesGcmEncrypt(provider, cek, plaintext, aad, encryptedKey)

        JweContentAlgorithm.A128CbcHs256,
        JweContentAlgorithm.A192CbcHs384,
        JweContentAlgorithm.A256CbcHs512,
        -> aesCbcHmacEncrypt(provider, cek, plaintext, aad, contentAlgorithm, encryptedKey)
    }
}

/**
 * Decrypts a JWE. [aad] is the ASCII bytes of the raw base64url header string.
 *
 * Key types mirror [jweEncrypt].
 */
internal suspend fun jweDecrypt(
    key: Any,
    keyAlgorithm: JweKeyAlgorithm,
    contentAlgorithm: JweContentAlgorithm,
    encryptedKey: ByteArray,
    iv: ByteArray,
    ciphertext: ByteArray,
    tag: ByteArray,
    aad: ByteArray,
): ByteArray {
    val provider = CryptographyProvider.Default

    val cek = when (keyAlgorithm) {
        JweKeyAlgorithm.Dir -> key as ByteArray
        JweKeyAlgorithm.RsaOaep,
        JweKeyAlgorithm.RsaOaep256,
        -> {
            val privateKey = key as RSA.OAEP.PrivateKey
            privateKey.decryptor().decrypt(encryptedKey)
        }
    }

    return when (contentAlgorithm) {
        JweContentAlgorithm.A128GCM,
        JweContentAlgorithm.A192GCM,
        JweContentAlgorithm.A256GCM,
        -> aesGcmDecrypt(provider, cek, iv, ciphertext, tag, aad)

        JweContentAlgorithm.A128CbcHs256,
        JweContentAlgorithm.A192CbcHs384,
        JweContentAlgorithm.A256CbcHs512,
        -> aesCbcHmacDecrypt(provider, cek, iv, ciphertext, tag, aad, contentAlgorithm)
    }
}

// ---- CEK generation ----

private fun generateCek(contentAlgorithm: JweContentAlgorithm): ByteArray =
    Random.Default.nextBytes(cekSizeBytes(contentAlgorithm))

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
    provider: CryptographyProvider,
    cek: ByteArray,
    plaintext: ByteArray,
    aad: ByteArray,
    encryptedKey: ByteArray,
): JweEncryptResult {
    val aesKey = provider.get(AES.GCM).keyDecoder().decodeFromByteArray(AES.Key.Format.RAW, cek)
    val cipher = aesKey.cipher()
    val iv = Random.Default.nextBytes(GCM_IV_SIZE)

    // encryptWithIv returns ciphertext || auth_tag
    val combined = cipher.encryptWithIv(iv, plaintext, aad)
    val ctLen = combined.size - GCM_TAG_SIZE
    val ciphertext = combined.copyOfRange(0, ctLen)
    val tag = combined.copyOfRange(ctLen, combined.size)

    return JweEncryptResult(encryptedKey, iv, ciphertext, tag)
}

private suspend fun aesGcmDecrypt(
    provider: CryptographyProvider,
    cek: ByteArray,
    iv: ByteArray,
    ciphertext: ByteArray,
    tag: ByteArray,
    aad: ByteArray,
): ByteArray {
    val aesKey = provider.get(AES.GCM).keyDecoder().decodeFromByteArray(AES.Key.Format.RAW, cek)
    // Recombine ciphertext || tag before passing to the cipher
    return aesKey.cipher().decryptWithIv(iv, ciphertext + tag, aad)
}

// ---- AES-CBC + HMAC (RFC 7516 Appendix B) ----
// CEK first half = MAC key, second half = AES enc key.
// MAC input: AAD || IV || Ciphertext || AL (64-bit big-endian AAD length in bits)
// The resulting MAC is truncated: take first half as the JWE auth tag.

private const val CBC_IV_SIZE = 16

private suspend fun aesCbcHmacEncrypt(
    provider: CryptographyProvider,
    cek: ByteArray,
    plaintext: ByteArray,
    aad: ByteArray,
    contentAlgorithm: JweContentAlgorithm,
    encryptedKey: ByteArray,
): JweEncryptResult {
    val half = cek.size / 2
    val macKey = cek.copyOfRange(0, half)
    val encKey = cek.copyOfRange(half, cek.size)

    val iv = Random.Default.nextBytes(CBC_IV_SIZE)

    val aesKey = provider.get(AES.CBC).keyDecoder().decodeFromByteArray(AES.Key.Format.RAW, encKey)
    val ciphertext = aesKey.cipher().encryptWithIv(iv, plaintext)

    val tag = computeCbcHmacTag(provider, macKey, aad, iv, ciphertext, contentAlgorithm)

    return JweEncryptResult(encryptedKey, iv, ciphertext, tag)
}

private suspend fun aesCbcHmacDecrypt(
    provider: CryptographyProvider,
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

    val expectedTag = computeCbcHmacTag(provider, macKey, aad, iv, ciphertext, contentAlgorithm)
    if (!expectedTag.contentEquals(tag)) {
        throw IllegalArgumentException("JWE authentication tag verification failed")
    }

    val aesKey = provider.get(AES.CBC).keyDecoder().decodeFromByteArray(AES.Key.Format.RAW, encKey)
    return aesKey.cipher().decryptWithIv(iv, ciphertext)
}

private suspend fun computeCbcHmacTag(
    provider: CryptographyProvider,
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

    val hmacKey = provider.get(HMAC).keyDecoder(hmacDigest).decodeFromByteArray(HMAC.Key.Format.RAW, macKey)
    val fullMac = hmacKey.signatureGenerator().generateSignature(macInput)

    // Per RFC 7516: truncate to the first T_LEN bytes
    return fullMac.copyOfRange(0, tagLen)
}
