@file:OptIn(DelicateCryptographyApi::class)

package co.touchlab.kjwt.cryptography.processors

import co.touchlab.kjwt.cryptography.SimpleKey
import co.touchlab.kjwt.cryptography.registry.EncryptionKey
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.EncryptionContentAlgorithm
import co.touchlab.kjwt.model.algorithm.JweEncryptResult
import co.touchlab.kjwt.processor.JweProcessor
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.DelicateCryptographyApi
import dev.whyoleg.cryptography.algorithms.AES
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.algorithms.SHA384
import dev.whyoleg.cryptography.algorithms.SHA512
import dev.whyoleg.cryptography.materials.key.Key
import kotlin.random.Random

public class CryptographyKotlinEncryptionProcessor<PublicKey : Key, PrivateKey : Key>(
    internal val key: EncryptionKey<PublicKey, PrivateKey>,
) : JweProcessor {
    internal constructor(
        key: EncryptionKey<PublicKey, PrivateKey>,
        previous: JweProcessor?,
    ) : this(
        key.mergeWith((previous as? CryptographyKotlinEncryptionProcessor<PublicKey, PrivateKey>)?.key)
    )

    override val algorithm: EncryptionAlgorithm
        get() = key.identifier.algorithm

    override suspend fun encrypt(
        data: ByteArray,
        aad: ByteArray,
        contentAlgorithm: EncryptionContentAlgorithm,
    ): JweEncryptResult {
        val publicKey = key.publicKey
        val algorithm = key.identifier.algorithm

        return when (publicKey) {
            is RSA.OAEP.PublicKey if (algorithm is EncryptionAlgorithm.OAEPBased) -> {
                val cek = generateCek(contentAlgorithm)
                val encryptedKey = publicKey.encryptor().encrypt(cek)
                encryptContent(contentAlgorithm, cek, data, aad, encryptedKey)
            }

            is SimpleKey if (algorithm is EncryptionAlgorithm.Dir) -> {
                val cek = publicKey.value
                encryptContent(contentAlgorithm, cek, data, aad, ByteArray(0))
            }

            else -> {
                error("The keys provided for encryption are not valid for the ${algorithm.id}.")
            }
        }
    }

    override suspend fun decrypt(
        aad: ByteArray,
        encryptedKey: ByteArray,
        iv: ByteArray,
        data: ByteArray,
        tag: ByteArray,
        contentAlgorithm: EncryptionContentAlgorithm,
    ): ByteArray {
        val privateKey = key.privateKey
        val algorithm = key.identifier.algorithm

        return when (privateKey) {
            is RSA.OAEP.PrivateKey if (algorithm is EncryptionAlgorithm.OAEPBased) -> {
                val cek = privateKey.decryptor().decrypt(encryptedKey)
                decryptContent(contentAlgorithm, cek, iv, data, tag, aad)
            }

            is SimpleKey if (algorithm is EncryptionAlgorithm.Dir) -> {
                val cek = privateKey.value
                decryptContent(contentAlgorithm, cek, iv, data, tag, aad)
            }

            else -> {
                error("The keys provided for decryption are not valid for the ${algorithm.id}.")
            }
        }
    }
}

private fun generateCek(contentAlgorithm: EncryptionContentAlgorithm): ByteArray =
    Random.nextBytes(
        when (contentAlgorithm) {
            EncryptionContentAlgorithm.A128GCM -> 16

            EncryptionContentAlgorithm.A192GCM -> 24

            EncryptionContentAlgorithm.A256GCM -> 32

            EncryptionContentAlgorithm.A128CbcHs256 -> 32

            // 16 mac + 16 enc
            EncryptionContentAlgorithm.A192CbcHs384 -> 48

            // 24 mac + 24 enc
            EncryptionContentAlgorithm.A256CbcHs512 -> 64 // 32 mac + 32 enc
        },
    )

private suspend fun encryptContent(
    contentAlgorithm: EncryptionContentAlgorithm,
    cek: ByteArray,
    plaintext: ByteArray,
    aad: ByteArray,
    encryptedKey: ByteArray,
): JweEncryptResult =
    when (contentAlgorithm) {
        is EncryptionContentAlgorithm.AesGCMBased -> {
            val aesKey =
                CryptographyProvider.Default
                    .get(AES.GCM)
                    .keyDecoder()
                    .decodeFromByteArray(AES.Key.Format.RAW, cek)

            val cipher = aesKey.cipher()
            val iv = Random.nextBytes(GCM_IV_SIZE)

            // encryptWithIv returns ciphertext || auth_tag
            val combined = cipher.encryptWithIv(iv, plaintext, aad)
            val ctLen = combined.size - GCM_TAG_SIZE
            val ciphertext = combined.copyOfRange(0, ctLen)
            val tag = combined.copyOfRange(ctLen, combined.size)

            JweEncryptResult(encryptedKey, iv, ciphertext, tag)
        }

        is EncryptionContentAlgorithm.AesCBCBased -> {
            val half = cek.size / 2
            val macKey = cek.copyOfRange(0, half)
            val encKey = cek.copyOfRange(half, cek.size)

            val iv = Random.nextBytes(CBC_IV_SIZE)

            val aesKey =
                CryptographyProvider.Default
                    .get(AES.CBC)
                    .keyDecoder()
                    .decodeFromByteArray(AES.Key.Format.RAW, encKey)
            val ciphertext = aesKey.cipher().encryptWithIv(iv, plaintext)

            val tag = computeCbcHmacTag(contentAlgorithm, macKey, aad, iv, ciphertext)

            JweEncryptResult(encryptedKey, iv, ciphertext, tag)
        }
    }

private suspend fun decryptContent(
    contentAlgorithm: EncryptionContentAlgorithm,
    cek: ByteArray,
    iv: ByteArray,
    ciphertext: ByteArray,
    tag: ByteArray,
    aad: ByteArray,
): ByteArray =
    when (contentAlgorithm) {
        is EncryptionContentAlgorithm.AesGCMBased -> {
            val aesKey =
                CryptographyProvider.Default
                    .get(AES.GCM)
                    .keyDecoder()
                    .decodeFromByteArray(AES.Key.Format.RAW, cek)
            // Recombine ciphertext || tag before passing to the cipher
            aesKey.cipher().decryptWithIv(iv, ciphertext + tag, aad)
        }

        is EncryptionContentAlgorithm.AesCBCBased -> {
            val half = cek.size / 2
            val macKey = cek.copyOfRange(0, half)
            val encKey = cek.copyOfRange(half, cek.size)

            val expectedTag = computeCbcHmacTag(contentAlgorithm, macKey, aad, iv, ciphertext)
            require(expectedTag.contentEquals(tag)) {
                "JWE authentication tag verification failed"
            }

            val aesKey =
                CryptographyProvider.Default
                    .get(AES.CBC)
                    .keyDecoder()
                    .decodeFromByteArray(AES.Key.Format.RAW, encKey)
            aesKey.cipher().decryptWithIv(iv, ciphertext)
        }
    }

private suspend fun computeCbcHmacTag(
    contentAlgorithm: EncryptionContentAlgorithm.AesCBCBased,
    macKey: ByteArray,
    aad: ByteArray,
    iv: ByteArray,
    ciphertext: ByteArray,
): ByteArray {
    // MAC input: AAD || IV || Ciphertext || AL (RFC 7516 §5.2.2.1)
    val al = aad.size.toLong() * 8
    val alBytes = ByteArray(8) { i -> ((al shr (56 - i * 8)) and 0xFF).toByte() }
    val macInput = aad + iv + ciphertext + alBytes

    val (hmacDigest, tagLen) =
        when (contentAlgorithm) {
            EncryptionContentAlgorithm.A128CbcHs256 -> Pair(SHA256, 16)
            EncryptionContentAlgorithm.A192CbcHs384 -> Pair(SHA384, 24)
            EncryptionContentAlgorithm.A256CbcHs512 -> Pair(SHA512, 32)
        }

    val hmacKey =
        CryptographyProvider.Default
            .get(HMAC)
            .keyDecoder(hmacDigest)
            .decodeFromByteArray(HMAC.Key.Format.RAW, macKey)
    val fullMac = hmacKey.signatureGenerator().generateSignature(macInput)

    // Per RFC 7516: truncate to the first T_LEN bytes
    return fullMac.copyOfRange(0, tagLen)
}

private const val GCM_IV_SIZE = 12
private const val GCM_TAG_SIZE = 16
private const val CBC_IV_SIZE = 16
