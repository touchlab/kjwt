@file:OptIn(DelicateCryptographyApi::class)

package co.touchlab.kjwt.cryptography

import co.touchlab.kjwt.annotations.DelicateKJWTApi
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import co.touchlab.kjwt.processor.BaseJwsProcessor
import co.touchlab.kjwt.processor.JwsProcessor
import co.touchlab.kjwt.processor.JwsSigner
import co.touchlab.kjwt.processor.JwsVerifier
import dev.whyoleg.cryptography.DelicateCryptographyApi
import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.algorithms.EdDSA
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.RSA

/**
 * Represents a cryptographic key (or key pair) used for JWS signing and/or verification.
 *
 * Instances are identified by a ([SigningAlgorithm], optional key ID) pair captured in
 * [identifier]. Depending on which key material is available, a [SigningKey] may be:
 * - [SigningOnlyKey] — holds only a private key; used by [co.touchlab.kjwt.builder.JwtBuilder]
 *   to produce signatures.
 * - [VerifyOnlyKey] — holds only a public key; used by [co.touchlab.kjwt.parser.JwtParser] to
 *   verify signatures.
 * - [SigningKeyPair] — holds both keys; supports both signing and verification.
 *
 * Complementary keys that share the same [Identifier] can be merged into a [SigningKeyPair] via
 * [mergeWith]. This happens automatically when both are registered with the same
 * [co.touchlab.kjwt.model.registry.DefaultJwtProcessorRegistry].
 *
 * Each subtype directly implements the appropriate processor interface ([JwsSigner], [JwsVerifier],
 * or [JwsProcessor]) and carries the cryptographic logic for its role.
 *
 * @see co.touchlab.kjwt.model.registry.DefaultJwtProcessorRegistry
 * @see co.touchlab.kjwt.parser.JwtParserBuilder.verifyWith
 */
public sealed class SigningKey : BaseJwsProcessor {
    /** The algorithm and key ID that identify this key within a registry. */
    public abstract val identifier: Identifier

    /** The public key material used for signature verification; throws on subtypes that do not hold a public key. */
    public abstract val publicKey: Any

    /** The private key material used for signing; throws on subtypes that do not hold a private key. */
    public abstract val privateKey: Any

    override val algorithm: SigningAlgorithm get() = identifier.algorithm
    override val keyId: String? get() = identifier.keyId

    /**
     * Identifies a [SigningKey] within a [co.touchlab.kjwt.model.registry.DefaultJwtProcessorRegistry] by
     * algorithm and optional key ID.
     *
     * The combination of [algorithm] and [keyId] must be unique within a registry. When [keyId]
     * is `null` the key acts as a catch-all for its algorithm (matched after any exact-`kid` key
     * during look-up).
     *
     * @property algorithm the JWS algorithm this key is associated with
     * @property keyId the optional `kid` header value used to select this key; `null` matches any
     *   token for the given algorithm that has no more specific key registered
     */
    public data class Identifier(
        val algorithm: SigningAlgorithm,
        val keyId: String?,
    ) {
        public companion object {
            /** Sentinel identifier used for unsigned (`alg=none`) tokens. */
            public val None: Identifier = Identifier(SigningAlgorithm.None, null)
        }
    }

    /**
     * A signing-only key that holds only the private key material, implementing [JwsSigner].
     *
     * Used when a token must be signed but signature verification is not performed by the same
     * key holder (e.g. asymmetric algorithms where only the private key is available). Accessing
     * [publicKey] on this type throws.
     */
    public class SigningOnlyKey @DelicateKJWTApi constructor(
        override val identifier: Identifier,
        override val privateKey: Any,
    ) : SigningKey(), JwsSigner {
        @Deprecated("SigningOnlyKey does not have a public key", level = DeprecationLevel.ERROR)
        override val publicKey: Any
            get() = error("SigningOnlyKey does not have a public key")

        override suspend fun sign(data: ByteArray): ByteArray = privateKey.sign(identifier.algorithm, data)

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as SigningOnlyKey

            if (identifier != other.identifier) return false
            if (privateKey != other.privateKey) return false

            return true
        }

        override fun hashCode(): Int {
            var result = identifier.hashCode()
            result = 31 * result + privateKey.hashCode()
            return result
        }

        override fun toString(): String = "SigningOnlyKey(identifier=$identifier, privateKey=$privateKey)"
    }

    /**
     * A verify-only key that holds only the public key material, implementing [JwsVerifier].
     *
     * Used when tokens must be verified but signing is not required (e.g. a service that only
     * consumes tokens). Accessing [privateKey] on this type throws.
     */
    public class VerifyOnlyKey @DelicateKJWTApi constructor(
        override val identifier: Identifier,
        override val publicKey: Any,
    ) : SigningKey(), JwsVerifier {
        @Deprecated("VerifyOnlyKey does not have a private key", level = DeprecationLevel.ERROR)
        override val privateKey: Any
            get() = error("VerifyOnlyKey does not have a private key")

        override suspend fun verify(data: ByteArray, signature: ByteArray): Boolean =
            publicKey.verify(identifier.algorithm, data, signature)

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as VerifyOnlyKey

            if (identifier != other.identifier) return false
            if (publicKey != other.publicKey) return false

            return true
        }

        override fun hashCode(): Int {
            var result = identifier.hashCode()
            result = 31 * result + publicKey.hashCode()
            return result
        }

        override fun toString(): String = "VerifyOnlyKey(publicKey=$publicKey, identifier=$identifier)"
    }

    /**
     * A complete key pair that holds both private and public key material, implementing [JwsProcessor].
     *
     * Produced automatically by [mergeWith] when a [SigningOnlyKey] and a [VerifyOnlyKey] with
     * the same [Identifier] are both registered in a
     * [co.touchlab.kjwt.model.registry.DefaultJwtProcessorRegistry]. Supports both signing and
     * verification.
     */
    public class SigningKeyPair @DelicateKJWTApi constructor(
        override val identifier: Identifier,
        override val publicKey: Any,
        override val privateKey: Any,
    ) : SigningKey(), JwsProcessor {
        override suspend fun sign(data: ByteArray): ByteArray = privateKey.sign(identifier.algorithm, data)

        override suspend fun verify(data: ByteArray, signature: ByteArray): Boolean =
            publicKey.verify(identifier.algorithm, data, signature)

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as SigningKeyPair

            if (identifier != other.identifier) return false
            if (publicKey != other.publicKey) return false
            if (privateKey != other.privateKey) return false

            return true
        }

        override fun hashCode(): Int {
            var result = identifier.hashCode()
            result = 31 * result + publicKey.hashCode()
            result = 31 * result + privateKey.hashCode()
            return result
        }

        override fun toString(): String =
            "SigningKeyPair(identifier=$identifier, publicKey=$publicKey, privateKey=$privateKey)"
    }

    @OptIn(DelicateKJWTApi::class)
    internal fun mergeWith(other: SigningKey?): SigningKey {
        if (other == null) return this

        require(identifier == other.identifier) { "Cannot merge keys with different identifiers" }
        require(this::class != other::class) { "Cannot merge keys of the same type" }
        require(this !is SigningKeyPair || other !is SigningKeyPair) { "Cannot merge when one key is complete" }

        return when (this) {
            is SigningOnlyKey if other is VerifyOnlyKey -> {
                SigningKeyPair(identifier, other.publicKey, privateKey)
            }

            is VerifyOnlyKey if other is SigningOnlyKey -> {
                SigningKeyPair(identifier, publicKey, other.privateKey)
            }

            else -> {
                error("Cannot merge given keys")
            }
        }
    }
}

private suspend fun Any.sign(algorithm: SigningAlgorithm, data: ByteArray): ByteArray =
    when (this) {
        is HMAC.Key if (algorithm is SigningAlgorithm.MACBased) -> {
            signatureGenerator().generateSignature(data)
        }

        is RSA.PKCS1.PrivateKey if (algorithm is SigningAlgorithm.PKCS1Based) -> {
            signatureGenerator().generateSignature(data)
        }

        is RSA.PSS.PrivateKey if (algorithm is SigningAlgorithm.PSSBased) -> {
            signatureGenerator().generateSignature(data)
        }

        is ECDSA.PrivateKey if (algorithm is SigningAlgorithm.ECDSABased) -> {
            signatureGenerator(algorithm.digest.toCryptographyKotlin(), ECDSA.SignatureFormat.RAW)
                .generateSignature(data)
        }

        is EdDSA.PrivateKey if (algorithm is SigningAlgorithm.EdDSABased) -> {
            signatureGenerator().generateSignature(data)
        }

        else -> {
            when (algorithm) {
                SigningAlgorithm.None -> ByteArray(0)
                else -> error("The keys provided for signing are not valid for the ${algorithm.id}.")
            }
        }
    }

private suspend fun Any.verify(algorithm: SigningAlgorithm, data: ByteArray, signature: ByteArray): Boolean =
    try {
        when (this) {
            is HMAC.Key if (algorithm is SigningAlgorithm.MACBased) -> {
                signatureVerifier().verifySignature(data, signature)
                true
            }

            is RSA.PKCS1.PublicKey if (algorithm is SigningAlgorithm.PKCS1Based) -> {
                signatureVerifier().verifySignature(data, signature)
                true
            }

            is RSA.PSS.PublicKey if (algorithm is SigningAlgorithm.PSSBased) -> {
                signatureVerifier().verifySignature(data, signature)
                true
            }

            is ECDSA.PublicKey if (algorithm is SigningAlgorithm.ECDSABased) -> {
                signatureVerifier(algorithm.digest.toCryptographyKotlin(), ECDSA.SignatureFormat.RAW)
                    .verifySignature(data, signature)
                true
            }

            is EdDSA.PublicKey if (algorithm is SigningAlgorithm.EdDSABased) -> {
                signatureVerifier().verifySignature(data, signature)
                true
            }

            else -> {
                when (algorithm) {
                    SigningAlgorithm.None -> signature.isEmpty()
                    else -> null
                }
            }
        }
    } catch (_: Throwable) {
        false
    } ?: error("The keys provided for verification are not valid for the ${algorithm.id}.")
