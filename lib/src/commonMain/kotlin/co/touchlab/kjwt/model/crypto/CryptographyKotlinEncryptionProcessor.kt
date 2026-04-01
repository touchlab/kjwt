package co.touchlab.kjwt.model.crypto

import co.touchlab.kjwt.cryptography.JweProcessor
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.EncryptionContentAlgorithm
import co.touchlab.kjwt.model.algorithm.JweEncryptResult
import co.touchlab.kjwt.model.registry.EncryptionKey
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

    override val algorithm: EncryptionAlgorithm<*, *>
        get() = key.identifier.algorithm

    override suspend fun encrypt(
        data: ByteArray,
        aad: ByteArray,
        contentAlgorithm: EncryptionContentAlgorithm,
    ): JweEncryptResult = key.encrypt(contentAlgorithm, data, aad)

    override suspend fun decrypt(
        aad: ByteArray,
        encryptedKey: ByteArray,
        iv: ByteArray,
        data: ByteArray,
        tag: ByteArray,
        contentAlgorithm: EncryptionContentAlgorithm,
    ): ByteArray = key.decrypt(
        contentAlgorithm = contentAlgorithm,
        encryptedKey = encryptedKey,
        iv = iv,
        ciphertext = data,
        tag = tag,
        aad = aad,
    )
}
