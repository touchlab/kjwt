package co.touchlab.kjwt.cryptography.registry

import co.touchlab.kjwt.annotations.ExperimentalKJWTApi
import co.touchlab.kjwt.cryptography.processors.CryptographyKotlinEncryptionProcessor
import co.touchlab.kjwt.cryptography.processors.CryptographyKotlinIntegrityProcessor
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import co.touchlab.kjwt.model.registry.JwtKeyRegistry
import co.touchlab.kjwt.processor.JweProcessor
import co.touchlab.kjwt.processor.JwsProcessor
import dev.whyoleg.cryptography.materials.key.Key

/**
 * Creates a new in-memory [CryptographyKotlinJwtKeyRegistry].
 *
 * The returned registry stores all keys in memory for the lifetime of the object. It supports
 * both signing and encryption keys, key-ID–based look-up, algorithm-only fallback, and
 * delegation to another registry via [co.touchlab.kjwt.model.registry.JwtKeyRegistry.delegateTo].
 *
 * @return a new, empty [CryptographyKotlinJwtKeyRegistry] backed by in-memory storage
 */
@ExperimentalKJWTApi
@Suppress("detekt:FunctionNaming", "ktlint:standard:function-naming")
public fun CryptographyKotlinJwtKeyRegistry(): CryptographyKotlinJwtKeyRegistry = MemoryJwtKeyRegistry()

public interface CryptographyKotlinJwtKeyRegistry : JwtKeyRegistry {
    /**
     * Registers a [SigningKey] in this registry.
     *
     * Keys are stored by their [SigningKey.Identifier] (algorithm + optional key ID).
     * If a key with the same identifier already exists and the new key is its complement — a
     * [SigningKey.SigningOnlyKey] paired with a
     * [SigningKey.VerifyOnlyKey] or vice-versa — the two are automatically merged into
     * a [SigningKey.SigningKeyPair].
     *
     * @param key the signing key to register
     * @throws IllegalArgumentException if a key with the same identifier is already registered
     *   and the two keys cannot be merged (e.g. two verify-only keys for the same identifier)
     */
    public fun <PublicKey : Key, PrivateKey : Key> registerSigningKey(key: SigningKey<PublicKey, PrivateKey>)

    /**
     * Registers an [EncryptionKey] in this registry.
     *
     * Keys are stored by their [EncryptionKey.Identifier] (algorithm + optional key
     * ID). If a key with the same identifier already exists and the new key is its complement — an
     * [EncryptionKey.EncryptionOnlyKey] paired with a
     * [EncryptionKey.DecryptionOnlyKey] or vice-versa — the two are automatically
     * merged into an [EncryptionKey.EncryptionKeyPair].
     *
     * @param key the encryption key to register
     * @throws IllegalArgumentException if a key with the same identifier is already registered
     *   and the two keys cannot be merged (e.g. two decryption-only keys for the same identifier)
     */
    public fun <PublicKey : Key, PrivateKey : Key> registerEncryptionKey(key: EncryptionKey<PublicKey, PrivateKey>)
}

internal class MemoryJwtKeyRegistry : CryptographyKotlinJwtKeyRegistry {
    override var delegateKeyRegistry: JwtKeyRegistry? = null
    private val signingKeys = mutableMapOf<SigningKey.Identifier, JwsProcessor>()
    private val encryptionKeys = mutableMapOf<EncryptionKey.Identifier, JweProcessor>()

    override fun <PublicKey : Key, PrivateKey : Key> registerSigningKey(key: SigningKey<PublicKey, PrivateKey>) {
        signingKeys[key.identifier] =
            try {
                CryptographyKotlinIntegrityProcessor(key, signingKeys[key.identifier])
            } catch (error: IllegalArgumentException) {
                throw IllegalArgumentException(
                    "Signing key with for '${key.identifier.algorithm.id}' " +
                        "identified by '${key.identifier.keyId}' already registered",
                    error,
                )
            }
    }

    override fun <PublicKey : Key, PrivateKey : Key> registerEncryptionKey(key: EncryptionKey<PublicKey, PrivateKey>) {
        encryptionKeys[key.identifier] =
            try {
                CryptographyKotlinEncryptionProcessor(key, encryptionKeys[key.identifier])
            } catch (error: IllegalArgumentException) {
                throw IllegalArgumentException(
                    "Decryption key with for '${key.identifier.algorithm.id}' " +
                        "identified by '${key.identifier.keyId}' already registered",
                    error,
                )
            }
    }

    override fun delegateTo(other: JwtKeyRegistry) {
        var cursor: JwtKeyRegistry? = other
        while (cursor != null) {
            require(cursor !== this) {
                "Cyclic delegation detected: this registry is already in the delegate chain of the target"
            }
            cursor = cursor.delegateKeyRegistry
        }
        delegateKeyRegistry = other
    }

    override fun findBestJwsProcessor(
        algorithm: SigningAlgorithm,
        keyId: String?,
    ): JwsProcessor? {
        signingKeys[SigningKey.Identifier(algorithm, keyId)]?.let {
            return it
        }

        if (keyId != null) {
            signingKeys[SigningKey.Identifier(algorithm, null)]?.let {
                return it
            }
        }

        return delegateKeyRegistry?.findBestJwsProcessor(algorithm, keyId)
    }

    override fun findBestJweProcessor(
        algorithm: EncryptionAlgorithm,
        keyId: String?,
    ): JweProcessor? {
        encryptionKeys[EncryptionKey.Identifier(algorithm, keyId)]?.let {
            return it
        }

        if (keyId != null) {
            encryptionKeys[EncryptionKey.Identifier(algorithm, null)]?.let {
                return it
            }
        }

        return delegateKeyRegistry?.findBestJweProcessor(algorithm, keyId)
    }
}
