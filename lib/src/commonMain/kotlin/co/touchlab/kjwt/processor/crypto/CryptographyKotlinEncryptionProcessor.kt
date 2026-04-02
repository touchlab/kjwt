@file:OptIn(DelicateCryptographyApi::class)

package co.touchlab.kjwt.processor.crypto

import co.touchlab.kjwt.cryptography.SimpleKey
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.EncryptionContentAlgorithm
import co.touchlab.kjwt.model.algorithm.JweEncryptResult
import co.touchlab.kjwt.model.registry.EncryptionKey
import co.touchlab.kjwt.processor.JweProcessor
import dev.whyoleg.cryptography.DelicateCryptographyApi
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.materials.key.Key

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
                val cek = contentAlgorithm.generateCek()
                val encryptedKey = publicKey.encryptor().encrypt(cek)
                contentAlgorithm.encrypt(cek, data, aad, encryptedKey)
            }

            is SimpleKey if (algorithm is EncryptionAlgorithm.Dir) -> {
                val cek = publicKey.value
                contentAlgorithm.encrypt(cek, data, aad, ByteArray(0))
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
                contentAlgorithm.decrypt(cek, iv, data, tag, aad)
            }

            is SimpleKey if (algorithm is EncryptionAlgorithm.Dir) -> {
                val cek = privateKey.value
                contentAlgorithm.decrypt(cek, iv, data, tag, aad)
            }

            else -> {
                error("The keys provided for decryption are not valid for the ${algorithm.id}.")
            }
        }
    }
}
