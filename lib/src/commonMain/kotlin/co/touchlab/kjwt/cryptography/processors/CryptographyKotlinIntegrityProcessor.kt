package co.touchlab.kjwt.cryptography.processors

import co.touchlab.kjwt.cryptography.toCryptographyKotlin
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

    override suspend fun sign(data: ByteArray): ByteArray {
        val privateKey = key.privateKey
        val algorithm = key.identifier.algorithm

        return when (privateKey) {
            is HMAC.Key if (algorithm is SigningAlgorithm.MACBased) -> {
                privateKey.signatureGenerator().generateSignature(data)
            }

            is RSA.PKCS1.PrivateKey if (algorithm is SigningAlgorithm.PKCS1Based) -> {
                privateKey.signatureGenerator().generateSignature(data)
            }

            is RSA.PSS.PrivateKey if (algorithm is SigningAlgorithm.PSSBased) -> {
                privateKey.signatureGenerator().generateSignature(data)
            }

            is ECDSA.PrivateKey if (algorithm is SigningAlgorithm.ECDSABased) -> {
                privateKey
                    .signatureGenerator(algorithm.digest.toCryptographyKotlin(), ECDSA.SignatureFormat.RAW)
                    .generateSignature(data)
            }

            else -> {
                when (algorithm) {
                    SigningAlgorithm.None -> {
                        ByteArray(0)
                    }

                    else -> {
                        error("The keys provided for signing are not valid for the ${algorithm.id}.")
                    }
                }
            }
        }
    }

    override suspend fun verify(data: ByteArray, signature: ByteArray): Boolean =
        try {
            val publicKey = key.publicKey
            val algorithm = key.identifier.algorithm

            when (publicKey) {
                is HMAC.Key if (algorithm is SigningAlgorithm.MACBased) -> {
                    publicKey.signatureVerifier().verifySignature(data, signature)
                    true
                }

                is RSA.PKCS1.PublicKey if (algorithm is SigningAlgorithm.PKCS1Based) -> {
                    publicKey.signatureVerifier().verifySignature(data, signature)
                    true
                }

                is RSA.PSS.PublicKey if (algorithm is SigningAlgorithm.PSSBased) -> {
                    publicKey.signatureVerifier().verifySignature(data, signature)
                    true
                }

                is ECDSA.PublicKey if (algorithm is SigningAlgorithm.ECDSABased) -> {
                    publicKey
                        .signatureVerifier(algorithm.digest.toCryptographyKotlin(), ECDSA.SignatureFormat.RAW)
                        .verifySignature(data, signature)
                    true
                }

                else -> {
                    when (algorithm) {
                        SigningAlgorithm.None -> {
                            signature.isEmpty()
                        }

                        else -> {
                            null
                        }
                    }
                }
            }
        } catch (_: Throwable) {
            false
        } ?: error("The keys provided for verification are not valid for the ${algorithm.id}.")
}
