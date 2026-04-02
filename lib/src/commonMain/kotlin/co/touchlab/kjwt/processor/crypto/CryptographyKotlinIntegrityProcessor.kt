package co.touchlab.kjwt.processor.crypto

import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import co.touchlab.kjwt.model.registry.SigningKey
import co.touchlab.kjwt.processor.JwsProcessor
import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.RSA
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

    override val algorithm: SigningAlgorithm
        get() = key.identifier.algorithm

    override suspend fun sign(data: ByteArray): ByteArray =
        when (val algorithm = key.identifier.algorithm) {
            is SigningAlgorithm.MACBased -> {
                @Suppress("UNCHECKED_CAST")
                (key.privateKey as HMAC.Key).signatureGenerator().generateSignature(data)
            }
            is SigningAlgorithm.PKCS1Based -> {
                @Suppress("UNCHECKED_CAST")
                (key.privateKey as RSA.PKCS1.PrivateKey).signatureGenerator().generateSignature(data)
            }
            is SigningAlgorithm.PSSBased -> {
                @Suppress("UNCHECKED_CAST")
                (key.privateKey as RSA.PSS.PrivateKey).signatureGenerator().generateSignature(data)
            }
            is SigningAlgorithm.ECDSABased -> {
                @Suppress("UNCHECKED_CAST")
                (key.privateKey as ECDSA.PrivateKey)
                    .signatureGenerator(algorithm.digest, ECDSA.SignatureFormat.RAW)
                    .generateSignature(data)
            }
            SigningAlgorithm.None -> ByteArray(0)
        }

    override suspend fun verify(data: ByteArray, signature: ByteArray): Boolean =
        try {
            when (val algorithm = key.identifier.algorithm) {
                is SigningAlgorithm.MACBased -> {
                    @Suppress("UNCHECKED_CAST")
                    (key.publicKey as HMAC.Key).signatureVerifier().verifySignature(data, signature)
                }
                is SigningAlgorithm.PKCS1Based -> {
                    @Suppress("UNCHECKED_CAST")
                    (key.publicKey as RSA.PKCS1.PublicKey).signatureVerifier().verifySignature(data, signature)
                }
                is SigningAlgorithm.PSSBased -> {
                    @Suppress("UNCHECKED_CAST")
                    (key.publicKey as RSA.PSS.PublicKey).signatureVerifier().verifySignature(data, signature)
                }
                is SigningAlgorithm.ECDSABased -> {
                    @Suppress("UNCHECKED_CAST")
                    (key.publicKey as ECDSA.PublicKey)
                        .signatureVerifier(algorithm.digest, ECDSA.SignatureFormat.RAW)
                        .verifySignature(data, signature)
                }
                SigningAlgorithm.None -> true
            }
            true
        } catch (_: Throwable) {
            false
        }
}
