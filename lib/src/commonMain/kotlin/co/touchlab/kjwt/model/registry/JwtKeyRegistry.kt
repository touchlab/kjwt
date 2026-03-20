package co.touchlab.kjwt.model.registry

import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import dev.whyoleg.cryptography.materials.key.Key

/**
 * A centralised store of signing and encryption keys shared across [co.touchlab.kjwt.builder.JwtBuilder]
 * and [co.touchlab.kjwt.parser.JwtParser] instances.
 *
 * A [JwtKeyRegistry] decouples key management from individual builder and parser configurations.
 * Populate it once, then reuse it across multiple call sites:
 * - Pass it to [co.touchlab.kjwt.builder.JwtBuilder.signWith] or
 *   [co.touchlab.kjwt.builder.JwtBuilder.encryptWith] to sign or encrypt tokens using the
 *   registered keys.
 * - Pass it to [co.touchlab.kjwt.parser.JwtParserBuilder.useKeysFrom] so one or more parsers
 *   delegate key look-up to it.
 *
 * ### Key lookup order
 *
 * When a key is requested the registry searches in this order:
 * 1. **Exact match** — a key registered in this registry whose algorithm and key ID both match
 *    the request.
 * 2. **Algorithm-only fallback** — if the request includes a key ID that has no exact match, a
 *    key registered *without* a key ID for the same algorithm is used as a catch-all.
 * 3. **Delegate registry** — if no local key is found and a delegate was configured (via
 *    [co.touchlab.kjwt.parser.JwtParserBuilder.useKeysFrom]), the delegate is searched last.
 *
 * This means locally registered keys always take precedence over the delegate. For signing-key
 * lookups an additional `alg=none` sentinel is tried first when insecure mode is active (used
 * internally by [co.touchlab.kjwt.parser.JwtParserBuilder.noVerify]).
 *
 * ### Example
 *
 * ```kotlin
 * val registry = JwtKeyRegistry()
 * // populate via JwtParserBuilder and share the reference, or
 * // register signing keys directly (see registerSigningKey)
 *
 * val token = Jwt.builder()
 *     .subject("user-123")
 *     .signWith(JwsAlgorithm.HS256, registry)
 *
 * val parser = Jwt.parser()
 *     .useKeysFrom(registry)
 *     .build()
 * ```
 *
 * @see co.touchlab.kjwt.parser.JwtParserBuilder.useKeysFrom
 * @see co.touchlab.kjwt.builder.JwtBuilder.signWith
 * @see co.touchlab.kjwt.builder.JwtBuilder.encryptWith
 */
public class JwtKeyRegistry {
    private var delegateKeyRegistry: JwtKeyRegistry? = null
    private val signingKeys = mutableMapOf<SigningKey.Identifier<*, *>, SigningKey<*, *>>()
    private val encryptionKeys = mutableMapOf<EncryptionKey.Identifier<*, *>, EncryptionKey<*, *>>()

    /**
     * Registers a [SigningKey] in this registry.
     *
     * Keys are stored by their [SigningKey.Identifier] (algorithm + optional key ID). If a key
     * with the same identifier already exists and the new key is its complement — a
     * [SigningKey.SigningOnlyKey] paired with a [SigningKey.VerifyOnlyKey] or vice-versa — the
     * two are automatically merged into a [SigningKey.SigningKeyPair].
     *
     * @param key the signing key to register
     * @throws IllegalArgumentException if a key with the same identifier is already registered
     *   and the two keys cannot be merged (e.g. two verify-only keys for the same identifier)
     */
    public fun <PublicKey : Key, PrivateKey : Key> registerSigningKey(key: SigningKey<PublicKey, PrivateKey>) {
        signingKeys[key.identifier] = try {
            key.mergeWith(signingKeys[key.identifier] as? SigningKey<PublicKey, PrivateKey>)
        } catch (error: IllegalArgumentException) {
            throw IllegalArgumentException(
                "Signing key with for '${key.identifier.algorithm.id}' " +
                    "identified by '${key.identifier.keyId}' already registered",
                error
            )
        }
    }

    /**
     * Registers an [EncryptionKey] in this registry.
     *
     * Keys are stored by their [EncryptionKey.Identifier] (algorithm + optional key ID). If a key
     * with the same identifier already exists and the new key is its complement — an
     * [EncryptionKey.EncryptionOnlyKey] paired with a [EncryptionKey.DecryptionOnlyKey] or
     * vice-versa — the two are automatically merged into an [EncryptionKey.EncryptionKeyPair].
     *
     * @param key the encryption key to register
     * @throws IllegalArgumentException if a key with the same identifier is already registered
     *   and the two keys cannot be merged (e.g. two decryption-only keys for the same identifier)
     */
    internal fun <PublicKey : Key, PrivateKey : Key> registerEncryptionKey(key: EncryptionKey<PublicKey, PrivateKey>) {
        encryptionKeys[key.identifier] = try {
            key.mergeWith(encryptionKeys[key.identifier] as? EncryptionKey<PublicKey, PrivateKey>)
        } catch (error: IllegalArgumentException) {
            throw IllegalArgumentException(
                "Decryption key with for '${key.identifier.algorithm.id}' " +
                    "identified by '${key.identifier.keyId}' already registered",
                error
            )
        }
    }

    internal fun delegateTo(other: JwtKeyRegistry) {
        var cursor: JwtKeyRegistry? = other
        while (cursor != null) {
            require(cursor !== this) {
                "Cyclic delegation detected: this registry is already in the delegate chain of the target"
            }
            cursor = cursor.delegateKeyRegistry
        }
        delegateKeyRegistry = other
    }

    internal fun <PublicKey : Key, PrivateKey : Key> findBestSigningKey(
        algorithm: SigningAlgorithm<PublicKey, PrivateKey>,
        keyId: String?,
    ): SigningKey<PublicKey, PrivateKey>? {
        signingKeys[SigningKey.Identifier(algorithm, keyId)]?.let {
            return it as SigningKey<PublicKey, PrivateKey>
        }

        if (keyId != null) {
            signingKeys[SigningKey.Identifier(algorithm, null)]?.let {
                return it as SigningKey<PublicKey, PrivateKey>
            }
        }

        return delegateKeyRegistry?.findBestSigningKey(algorithm, keyId)
    }

    internal fun <PublicKey : Key, PrivateKey : Key> findBestEncryptionKey(
        algorithm: EncryptionAlgorithm<PublicKey, PrivateKey>,
        keyId: String?,
    ): EncryptionKey<PublicKey, PrivateKey>? {
        encryptionKeys[EncryptionKey.Identifier(algorithm, keyId)]?.let {
            return it as EncryptionKey<PublicKey, PrivateKey>
        }

        if (keyId != null) {
            encryptionKeys[EncryptionKey.Identifier(algorithm, null)]?.let {
                return it as EncryptionKey<PublicKey, PrivateKey>
            }
        }

        return delegateKeyRegistry?.findBestEncryptionKey(algorithm, keyId)
    }
}
