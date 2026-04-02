package co.touchlab.kjwt.model.registry

import co.touchlab.kjwt.annotations.ExperimentalKJWTApi
import co.touchlab.kjwt.annotations.InternalKJWTApi
import co.touchlab.kjwt.cryptography.JweProcessor
import co.touchlab.kjwt.cryptography.JwsProcessor
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import co.touchlab.kjwt.model.crypto.CryptographyKotlinEncryptionProcessor
import co.touchlab.kjwt.model.crypto.CryptographyKotlinIntegrityProcessor
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
@ExperimentalKJWTApi
public interface JwtKeyRegistry {
    /**
     * The registry to fall back to when a key is not found locally.
     *
     * When set, [findBestJwsProcessor] and [findBestJweProcessor] forward the look-up to this
     * registry after exhausting all locally registered keys. Use [delegateTo] to set this value
     * safely — it guards against cyclic delegation chains.
     */
    @InternalKJWTApi
    public var delegateKeyRegistry: JwtKeyRegistry?

    /**
     * Sets [other] as the delegate registry for this registry.
     *
     * After this call, any key look-up that finds no local match will be forwarded to [other]
     * (and transitively to its own delegate, if any). The entire delegation chain is checked for
     * cycles before the delegate is assigned.
     *
     * @param other the registry to delegate to
     * @throws IllegalArgumentException if adding [other] as a delegate would create a cycle
     */
    public fun delegateTo(other: JwtKeyRegistry)

    /**
     * Returns the best available signing key for [algorithm] and the optional [keyId].
     *
     * Look-up order:
     * 1. A key registered with both [algorithm] and [keyId] (exact match).
     * 2. A key registered with [algorithm] and no key ID (algorithm-only fallback), when [keyId]
     *    is non-null and has no exact match.
     * 3. The [delegateKeyRegistry], if one is set.
     *
     * @param algorithm the signing algorithm the key must support
     * @param keyId optional key ID to narrow the look-up
     * @return the matching [SigningKey], or `null` if none is found
     */
    public fun findBestJwsProcessor(
        algorithm: SigningAlgorithm,
        keyId: String?,
    ): JwsProcessor?

    /**
     * Returns the best available encryption key for [algorithm] and the optional [keyId].
     *
     * Look-up order:
     * 1. A key registered with both [algorithm] and [keyId] (exact match).
     * 2. A key registered with [algorithm] and no key ID (algorithm-only fallback), when [keyId]
     *    is non-null and has no exact match.
     * 3. The [delegateKeyRegistry], if one is set.
     *
     * @param algorithm the encryption algorithm the key must support
     * @param keyId optional key ID to narrow the look-up
     * @return the matching [EncryptionKey], or `null` if none is found
     */
    public fun findBestJweProcessor(
        algorithm: EncryptionAlgorithm,
        keyId: String?,
    ): JweProcessor?
}

public interface MutableJwtKeyRegistry : JwtKeyRegistry {
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
    public fun <PublicKey : Key, PrivateKey : Key> registerSigningKey(key: SigningKey<PublicKey, PrivateKey>)

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
    public fun <PublicKey : Key, PrivateKey : Key> registerEncryptionKey(key: EncryptionKey<PublicKey, PrivateKey>)
}

/**
 * Creates a new in-memory [JwtKeyRegistry].
 *
 * The returned registry stores all keys in memory for the lifetime of the object. It supports
 * both signing and encryption keys, key-ID–based look-up, algorithm-only fallback, and
 * delegation to another registry via [JwtKeyRegistry.delegateTo].
 *
 * @return a new, empty [JwtKeyRegistry] backed by in-memory storage
 */
@ExperimentalKJWTApi
@Suppress("detekt:FunctionNaming", "ktlint:standard:function-naming")
public fun JwtKeyRegistry(): MutableJwtKeyRegistry = MemoryJwtKeyRegistry()

internal class MemoryJwtKeyRegistry : MutableJwtKeyRegistry {
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
