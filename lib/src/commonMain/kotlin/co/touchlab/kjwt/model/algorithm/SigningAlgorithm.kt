package co.touchlab.kjwt.model.algorithm

import co.touchlab.kjwt.cryptography.SimpleKey
import co.touchlab.kjwt.serializers.SigningAlgorithmSerializer
import dev.whyoleg.cryptography.CryptographyAlgorithmId
import dev.whyoleg.cryptography.algorithms.Digest
import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.algorithms.SHA384
import dev.whyoleg.cryptography.algorithms.SHA512
import dev.whyoleg.cryptography.materials.key.Key
import kotlinx.serialization.Serializable

@Serializable(SigningAlgorithmSerializer::class)
sealed class SigningAlgorithm<PublicKey : Key, PrivateKey : Key>(
    override val id: String,
) : Jwa<PublicKey, PrivateKey> {
    internal abstract suspend fun sign(key: PrivateKey, signingInput: ByteArray): ByteArray
    internal abstract suspend fun verify(key: PublicKey, signingInput: ByteArray, signature: ByteArray): Boolean

    data object HS256 : HashBased("HS256")
    data object HS384 : HashBased("HS384")
    data object HS512 : HashBased("HS512")

    data object RS256 : PKCS1Based("RS256")
    data object RS384 : PKCS1Based("RS384")
    data object RS512 : PKCS1Based("RS512")

    data object PS256 : PSSBased("PS256")
    data object PS384 : PSSBased("PS384")
    data object PS512 : PSSBased("PS512")

    data object ES256 : ECDSABased("ES256")
    data object ES384 : ECDSABased("ES384")
    data object ES512 : ECDSABased("ES512")

    sealed class HashBased(
        id: String,
    ) : SigningAlgorithm<HMAC.Key, HMAC.Key>(id), Jwa.UsesHashingAlgorithm {
        override val digest: CryptographyAlgorithmId<Digest>
            get() = when (this) {
                HS256 -> SHA256
                HS384 -> SHA384
                HS512 -> SHA512
            }

        override suspend fun sign(key: HMAC.Key, signingInput: ByteArray): ByteArray =
            key.signatureGenerator().generateSignature(signingInput)

        override suspend fun verify(key: HMAC.Key, signingInput: ByteArray, signature: ByteArray): Boolean {
            key.signatureVerifier().verifySignature(signingInput, signature)
            return true
        }
    }

    sealed class PKCS1Based(
        id: String,
    ) : SigningAlgorithm<RSA.PKCS1.PublicKey, RSA.PKCS1.PrivateKey>(id), Jwa.UsesHashingAlgorithm {
        override val digest: CryptographyAlgorithmId<Digest>
            get() = when (this) {
                RS256 -> SHA256
                RS384 -> SHA384
                RS512 -> SHA512
            }

        override suspend fun sign(key: RSA.PKCS1.PrivateKey, signingInput: ByteArray): ByteArray =
            key.signatureGenerator().generateSignature(signingInput)

        override suspend fun verify(key: RSA.PKCS1.PublicKey, signingInput: ByteArray, signature: ByteArray): Boolean {
            key.signatureVerifier().verifySignature(signingInput, signature)
            return true
        }
    }

    sealed class PSSBased(
        id: String,
    ) : SigningAlgorithm<RSA.PSS.PublicKey, RSA.PSS.PrivateKey>(id), Jwa.UsesHashingAlgorithm {
        override val digest: CryptographyAlgorithmId<Digest>
            get() = when (this) {
                PS256 -> SHA256
                PS384 -> SHA384
                PS512 -> SHA512
            }

        override suspend fun sign(key: RSA.PSS.PrivateKey, signingInput: ByteArray): ByteArray =
            key.signatureGenerator().generateSignature(signingInput)

        override suspend fun verify(key: RSA.PSS.PublicKey, signingInput: ByteArray, signature: ByteArray): Boolean {
            key.signatureVerifier().verifySignature(signingInput, signature)
            return true
        }
    }

    sealed class ECDSABased(
        id: String,
    ) : SigningAlgorithm<ECDSA.PublicKey, ECDSA.PrivateKey>(id), Jwa.UsesHashingAlgorithm {
        override val digest: CryptographyAlgorithmId<Digest>
            get() = when (this) {
                ES256 -> SHA256
                ES384 -> SHA384
                ES512 -> SHA512
            }

        override suspend fun sign(key: ECDSA.PrivateKey, signingInput: ByteArray): ByteArray =
            key.signatureGenerator(digest, ECDSA.SignatureFormat.RAW).generateSignature(signingInput)

        override suspend fun verify(key: ECDSA.PublicKey, signingInput: ByteArray, signature: ByteArray): Boolean {
            key.signatureVerifier(digest, ECDSA.SignatureFormat.RAW).verifySignature(signingInput, signature)
            return true
        }
    }

    /** Unsecured JWT — opt-in only. Rejected by parser unless `allowUnsecured(true)`. */
    data object None : SigningAlgorithm<SimpleKey, SimpleKey>("none") {
        override suspend fun sign(key: SimpleKey, signingInput: ByteArray): ByteArray = ByteArray(0)
        override suspend fun verify(key: SimpleKey, signingInput: ByteArray, signature: ByteArray): Boolean = true
    }

    override fun toString(): String = id

    companion object {
        internal val entries: List<SigningAlgorithm<*, *>> by lazy {
            listOf(
                HS256, HS384, HS512,
                RS256, RS384, RS512,
                PS256, PS384, PS512,
                ES256, ES384, ES512,
                None,
            )
        }

        fun fromId(id: String): SigningAlgorithm<*, *> =
            requireNotNull(entries.firstOrNull { it.id == id }) {
                "Unknown JWS algorithm: '$id'"
            }
    }
}
