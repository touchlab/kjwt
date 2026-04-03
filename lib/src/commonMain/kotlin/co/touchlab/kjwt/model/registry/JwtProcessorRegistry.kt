package co.touchlab.kjwt.model.registry

import co.touchlab.kjwt.annotations.ExperimentalKJWTApi
import co.touchlab.kjwt.annotations.InternalKJWTApi
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import co.touchlab.kjwt.processor.BaseJweProcessor
import co.touchlab.kjwt.processor.BaseJwsProcessor

/**
 * A centralised store of signing and encryption keys shared across [co.touchlab.kjwt.builder.JwtBuilder]
 * and [co.touchlab.kjwt.parser.JwtParser] instances.
 *
 * A [JwtProcessorRegistry] decouples key management from individual builder and parser configurations.
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
 * val registry = JwtProcessorRegistry()
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
public interface JwtProcessorRegistry {
    /**
     * The registry to fall back to when a key is not found locally.
     *
     * When set, [findBestJwsProcessor] and [findBestJweProcessor] forward the look-up to this
     * registry after exhausting all locally registered keys. Use [delegateTo] to set this value
     * safely — it guards against cyclic delegation chains.
     */
    @InternalKJWTApi
    public var delegateKeyRegistry: JwtProcessorRegistry?

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
    public fun delegateTo(other: JwtProcessorRegistry)

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
     * @return the matching [co.touchlab.kjwt.cryptography.processors.SigningKey], or `null` if none is found
     */
    public fun findBestJwsProcessor(
        algorithm: SigningAlgorithm,
        keyId: String?,
    ): BaseJwsProcessor?

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
     * @return the matching [co.touchlab.kjwt.cryptography.processors.EncryptionKey], or `null` if none is found
     */
    public fun findBestJweProcessor(
        algorithm: EncryptionAlgorithm,
        keyId: String?,
    ): BaseJweProcessor?

    /**
     * Registers a [BaseJwsProcessor] in this registry under its algorithm and optional [keyId].
     *
     * If a processor for the same algorithm and key ID is already registered, the two are merged
     * into a combined [co.touchlab.kjwt.processor.JwsProcessor] via
     * [co.touchlab.kjwt.ext.mergeWith].
     *
     * @param processor the processor to register
     * @param keyId optional key ID; `null` acts as a catch-all for the given algorithm
     */
    public fun registerJwsProcessor(processor: BaseJwsProcessor, keyId: String? = processor.keyId)

    /**
     * Registers a [BaseJweProcessor] in this registry under its algorithm and optional [keyId].
     *
     * If a processor for the same algorithm and key ID is already registered, the two are merged
     * into a combined [co.touchlab.kjwt.processor.JweProcessor] via
     * [co.touchlab.kjwt.ext.mergeWith].
     *
     * @param processor the processor to register
     * @param keyId optional key ID; `null` acts as a catch-all for the given algorithm
     */
    public fun registerJweProcessor(processor: BaseJweProcessor, keyId: String? = processor.keyId)
}
