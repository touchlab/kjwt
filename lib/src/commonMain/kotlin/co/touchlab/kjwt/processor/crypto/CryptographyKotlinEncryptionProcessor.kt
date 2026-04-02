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
    ): JweEncryptResult =
        when (key.identifier.algorithm) {
            is EncryptionAlgorithm.OAEPBased -> {
                @Suppress("UNCHECKED_CAST")
                val publicKey = key.publicKey as RSA.OAEP.PublicKey
                val cek = contentAlgorithm.generateCek()
                val encryptedKey = publicKey.encryptor().encrypt(cek)
                contentAlgorithm.encrypt(cek, data, aad, encryptedKey)
            }
            EncryptionAlgorithm.Dir -> {
                @Suppress("UNCHECKED_CAST")
                val cek = (key.publicKey as SimpleKey).value
                contentAlgorithm.encrypt(cek, data, aad, ByteArray(0))
            }
        }

    override suspend fun decrypt(
        aad: ByteArray,
        encryptedKey: ByteArray,
        iv: ByteArray,
        data: ByteArray,
        tag: ByteArray,
        contentAlgorithm: EncryptionContentAlgorithm,
    ): ByteArray =
        when (key.identifier.algorithm) {
            is EncryptionAlgorithm.OAEPBased -> {
                @Suppress("UNCHECKED_CAST")
                val privateKey = key.privateKey as RSA.OAEP.PrivateKey
                val cek = privateKey.decryptor().decrypt(encryptedKey)
                contentAlgorithm.decrypt(cek, iv, data, tag, aad)
            }
            EncryptionAlgorithm.Dir -> {
                @Suppress("UNCHECKED_CAST")
                val cek = (key.privateKey as SimpleKey).value
                contentAlgorithm.decrypt(cek, iv, data, tag, aad)
            }
        }
}
