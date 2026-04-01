package co.touchlab.kjwt.model.crypto

import co.touchlab.kjwt.cryptography.JwsProcessor
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import co.touchlab.kjwt.model.registry.SigningKey
import dev.whyoleg.cryptography.materials.key.Key

public class CryptographyKotlinIntegrityProcessor<PublicKey : Key, PrivateKey : Key>(
    internal val key: SigningKey<PublicKey, PrivateKey>,
) : JwsProcessor {
    internal constructor(
        key: SigningKey<PublicKey, PrivateKey>,
        previous: JwsProcessor?,
    ) : this(
        key.mergeWith((previous as? CryptographyKotlinIntegrityProcessor<PublicKey, PrivateKey>)?.key)
    )

    override val algorithm: SigningAlgorithm<*, *>
        get() = key.identifier.algorithm

    override suspend fun sign(data: ByteArray): ByteArray =
        key.sign(data)

    override suspend fun verify(data: ByteArray, signature: ByteArray): Boolean =
        key.verify(data, signature)
}
