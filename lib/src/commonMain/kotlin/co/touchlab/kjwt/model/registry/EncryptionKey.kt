package co.touchlab.kjwt.model.registry

import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import dev.whyoleg.cryptography.materials.key.Key

/**
 * Represents a cryptographic key (or key pair) used for JWE encryption and/or decryption.
 *
 * Instances are identified by a ([EncryptionAlgorithm], optional key ID) pair captured in
 * [identifier]. Depending on which key material is available, an [EncryptionKey] may be:
 * - [EncryptionOnlyKey] — holds only the public key; used by [co.touchlab.kjwt.builder.JwtBuilder]
 *   to encrypt tokens.
 * - [DecryptionOnlyKey] — holds only the private key; used by [co.touchlab.kjwt.parser.JwtParser]
 *   to decrypt tokens.
 * - [EncryptionKeyPair] — holds both keys; supports both encryption and decryption.
 *
 * Complementary keys that share the same [Identifier] can be merged into an [EncryptionKeyPair]
 * via [mergeWith]. This happens automatically when both are registered with the same
 * [CryptographyKotlinJwtKeyRegistry].
 *
 * @see CryptographyKotlinJwtKeyRegistry
 * @see co.touchlab.kjwt.parser.JwtParserBuilder.decryptWith
 */
public sealed class EncryptionKey<PublicKey : Key, PrivateKey : Key> {
    public abstract val identifier: Identifier
    public abstract val publicKey: PublicKey
    public abstract val privateKey: PrivateKey

    /**
     * Identifies an [EncryptionKey] within a [CryptographyKotlinJwtKeyRegistry] by algorithm and optional key ID.
     *
     * The combination of [algorithm] and [keyId] must be unique within a registry. When [keyId]
     * is `null` the key acts as a catch-all for its algorithm (matched after any exact-`kid` key
     * during look-up).
     *
     * @property algorithm the JWE key-encryption algorithm this key is associated with
     * @property keyId the optional `kid` header value used to select this key; `null` matches any
     *   token for the given algorithm that has no more specific key registered
     */
    public data class Identifier(
        val algorithm: EncryptionAlgorithm,
        val keyId: String?,
    ) {
        public companion object;
    }

    /**
     * An encryption-only key that holds only the public key material.
     *
     * Used when a token must be encrypted but decryption is not performed by the same key holder
     * (e.g. asymmetric algorithms where only the public key is available). Accessing [privateKey]
     * on this type throws.
     */
    public class EncryptionOnlyKey<PublicKey : Key, PrivateKey : Key> internal constructor(
        override val identifier: Identifier,
        override val publicKey: PublicKey,
    ) : EncryptionKey<PublicKey, PrivateKey>() {
        @Deprecated("EncryptionOnlyKey does not have a private key", level = DeprecationLevel.ERROR)
        override val privateKey: PrivateKey
            get() = error("EncryptionOnlyKey does not have a private key")

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as EncryptionOnlyKey<*, *>

            if (identifier != other.identifier) return false
            if (publicKey != other.publicKey) return false

            return true
        }

        override fun hashCode(): Int {
            var result = identifier.hashCode()
            result = 31 * result + publicKey.hashCode()
            return result
        }

        override fun toString(): String = "EncryptionOnlyKey(identifier=$identifier, publicKey=$publicKey)"
    }

    /**
     * A decryption-only key that holds only the private key material.
     *
     * Used when tokens must be decrypted but encryption is not required (e.g. a service that only
     * consumes encrypted tokens). Accessing [publicKey] on this type throws.
     */
    public class DecryptionOnlyKey<PublicKey : Key, PrivateKey : Key> internal constructor(
        override val identifier: Identifier,
        override val privateKey: PrivateKey,
    ) : EncryptionKey<PublicKey, PrivateKey>() {
        @Deprecated("DecryptionOnlyKey does not have a public key", level = DeprecationLevel.ERROR)
        override val publicKey: PublicKey
            get() = error("DecryptionOnlyKey does not have a public key")

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as DecryptionOnlyKey<*, *>

            if (identifier != other.identifier) return false
            if (privateKey != other.privateKey) return false

            return true
        }

        override fun hashCode(): Int {
            var result = identifier.hashCode()
            result = 31 * result + privateKey.hashCode()
            return result
        }

        override fun toString(): String = "DecryptionOnlyKey(identifier=$identifier, privateKey=$privateKey)"
    }

    /**
     * A complete key pair that holds both public and private key material.
     *
     * Produced automatically by [mergeWith] when an [EncryptionOnlyKey] and a [DecryptionOnlyKey]
     * with the same [Identifier] are both registered in a [CryptographyKotlinJwtKeyRegistry]. Supports both
     * encryption and decryption.
     */
    public class EncryptionKeyPair<PublicKey : Key, PrivateKey : Key> internal constructor(
        override val identifier: Identifier,
        override val publicKey: PublicKey,
        override val privateKey: PrivateKey,
    ) : EncryptionKey<PublicKey, PrivateKey>() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as EncryptionKeyPair<*, *>

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
            "EncryptionKeyPair(identifier=$identifier, publicKey=$publicKey, privateKey=$privateKey)"
    }

    internal fun mergeWith(other: EncryptionKey<PublicKey, PrivateKey>?): EncryptionKey<PublicKey, PrivateKey> {
        if (other == null) return this

        require(identifier == other.identifier) { "Cannot merge keys with different identifiers" }
        require(this::class != other::class) { "Cannot merge keys of the same type" }
        require(this !is EncryptionKeyPair || other !is EncryptionKeyPair) { "Cannot merge when one key is complete" }

        return when (this) {
            is EncryptionOnlyKey if other is DecryptionOnlyKey -> {
                EncryptionKeyPair(identifier, publicKey, other.privateKey)
            }

            is DecryptionOnlyKey if other is EncryptionKeyPair -> {
                EncryptionKeyPair(identifier, other.publicKey, privateKey)
            }

            else -> {
                error("Cannot merge given keys")
            }
        }
    }
}
