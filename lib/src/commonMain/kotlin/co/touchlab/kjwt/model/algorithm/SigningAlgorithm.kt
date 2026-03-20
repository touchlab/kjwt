package co.touchlab.kjwt.model.algorithm

import co.touchlab.kjwt.cryptography.SimpleKey
import co.touchlab.kjwt.model.registry.SigningKey
import co.touchlab.kjwt.serializers.SigningAlgorithmSerializer
import dev.whyoleg.cryptography.CryptographyAlgorithmId
import dev.whyoleg.cryptography.algorithms.Digest
import dev.whyoleg.cryptography.algorithms.EC
import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.algorithms.SHA384
import dev.whyoleg.cryptography.algorithms.SHA512
import dev.whyoleg.cryptography.materials.key.Key
import kotlinx.serialization.Serializable

@Serializable(SigningAlgorithmSerializer::class)
public sealed class SigningAlgorithm<PublicKey : Key, PrivateKey : Key>(
    override val id: String,
) : Jwa<PublicKey, PrivateKey> {
    internal abstract suspend fun sign(key: PrivateKey, signingInput: ByteArray): ByteArray
    internal abstract suspend fun verify(key: PublicKey, signingInput: ByteArray, signature: ByteArray): Boolean

    internal fun identifier(keyId: String?) = SigningKey.Identifier(this, keyId)

    /** HMAC with SHA-256 (`HS256`) signing algorithm using a symmetric [HMAC.Key]. */
    public data object HS256 : HashBased("HS256")

    /** HMAC with SHA-384 (`HS384`) signing algorithm using a symmetric [HMAC.Key]. */
    public data object HS384 : HashBased("HS384")

    /** HMAC with SHA-512 (`HS512`) signing algorithm using a symmetric [HMAC.Key]. */
    public data object HS512 : HashBased("HS512")

    /** RSA PKCS#1 v1.5 with SHA-256 (`RS256`) signing algorithm using RSA key pairs. */
    public data object RS256 : PKCS1Based("RS256")

    /** RSA PKCS#1 v1.5 with SHA-384 (`RS384`) signing algorithm using RSA key pairs. */
    public data object RS384 : PKCS1Based("RS384")

    /** RSA PKCS#1 v1.5 with SHA-512 (`RS512`) signing algorithm using RSA key pairs. */
    public data object RS512 : PKCS1Based("RS512")

    /** RSA PSS with SHA-256 (`PS256`) signing algorithm using RSA key pairs. */
    public data object PS256 : PSSBased("PS256")

    /** RSA PSS with SHA-384 (`PS384`) signing algorithm using RSA key pairs. */
    public data object PS384 : PSSBased("PS384")

    /** RSA PSS with SHA-512 (`PS512`) signing algorithm using RSA key pairs. */
    public data object PS512 : PSSBased("PS512")

    /** ECDSA with SHA-256 (`ES256`) signing algorithm using elliptic-curve key pairs. */
    public data object ES256 : ECDSABased("ES256")

    /** ECDSA with SHA-384 (`ES384`) signing algorithm using elliptic-curve key pairs. */
    public data object ES384 : ECDSABased("ES384")

    /** ECDSA with SHA-512 (`ES512`) signing algorithm using elliptic-curve key pairs. */
    public data object ES512 : ECDSABased("ES512")

    /**
     * Groups the HMAC-based signing algorithms (HS256, HS384, HS512).
     *
     * All members use a symmetric [HMAC.Key] for signing and verification.
     */
    public sealed class HashBased(
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

    /**
     * Groups the RSA PKCS#1 v1.5 signing algorithms (RS256, RS384, RS512).
     *
     * All members use [RSA.PKCS1] key pairs for signing and verification.
     */
    public sealed class PKCS1Based(
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

    /**
     * Groups the RSA PSS signing algorithms (PS256, PS384, PS512).
     *
     * All members use [RSA.PSS] key pairs for signing and verification.
     */
    public sealed class PSSBased(
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

    /**
     * Groups the ECDSA signing algorithms (ES256, ES384, ES512).
     *
     * All members use [ECDSA] key pairs and produce raw-format signatures.
     */
    public sealed class ECDSABased(
        id: String,
    ) : SigningAlgorithm<ECDSA.PublicKey, ECDSA.PrivateKey>(id), Jwa.UsesHashingAlgorithm {
        override val digest: CryptographyAlgorithmId<Digest>
            get() = when (this) {
                ES256 -> SHA256
                ES384 -> SHA384
                ES512 -> SHA512
            }

        public val curve: EC.Curve
            get() = when (this) {
                ES256 -> EC.Curve.P256
                ES384 -> EC.Curve.P384
                ES512 -> EC.Curve.P521
            }

        override suspend fun sign(key: ECDSA.PrivateKey, signingInput: ByteArray): ByteArray =
            key.signatureGenerator(digest, ECDSA.SignatureFormat.RAW).generateSignature(signingInput)

        override suspend fun verify(key: ECDSA.PublicKey, signingInput: ByteArray, signature: ByteArray): Boolean {
            key.signatureVerifier(digest, ECDSA.SignatureFormat.RAW).verifySignature(signingInput, signature)
            return true
        }
    }

    /** Unsecured JWT — opt-in only. Rejected by parser unless `allowUnsecured(true)`. */
    public data object None : SigningAlgorithm<SimpleKey, SimpleKey>("none") {
        override suspend fun sign(key: SimpleKey, signingInput: ByteArray): ByteArray = ByteArray(0)
        override suspend fun verify(key: SimpleKey, signingInput: ByteArray, signature: ByteArray): Boolean = true
    }

    override fun toString(): String = id

    public companion object {
        /**
         * List of all supported [SigningAlgorithm] instances, including [None].
         */
        internal val entries: List<SigningAlgorithm<*, *>> by lazy {
            listOf(
                HS256, HS384, HS512,
                RS256, RS384, RS512,
                PS256, PS384, PS512,
                ES256, ES384, ES512,
                None,
            )
        }

        /**
         * Returns the [SigningAlgorithm] whose [id] matches the given string.
         *
         * @param id the JWS algorithm identifier to look up (e.g. `"RS256"`)
         * @return the matching [SigningAlgorithm] instance
         * @throws IllegalArgumentException if no algorithm with the given [id] is registered
         */
        public fun fromId(id: String): SigningAlgorithm<*, *> =
            requireNotNull(entries.firstOrNull { it.id == id }) {
                "Unknown JWS algorithm: '$id'"
            }
    }
}
