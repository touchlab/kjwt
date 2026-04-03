package co.touchlab.kjwt.model.registry

import co.touchlab.kjwt.annotations.ExperimentalKJWTApi
import co.touchlab.kjwt.annotations.InternalKJWTApi
import co.touchlab.kjwt.ext.mergeWith
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import co.touchlab.kjwt.processor.BaseJweProcessor
import co.touchlab.kjwt.processor.BaseJwsProcessor

/**
 * Default in-memory implementation of [JwtProcessorRegistry].
 *
 * Signing processors are keyed by ([SigningAlgorithm], optional key ID) and encryption processors
 * by ([EncryptionAlgorithm], optional key ID). Look-up follows the order defined by
 * [JwtProcessorRegistry]: exact match, algorithm-only fallback, then delegate.
 *
 * @see JwtProcessorRegistry
 */
@ExperimentalKJWTApi
@OptIn(InternalKJWTApi::class)
public class DefaultJwtProcessorRegistry : JwtProcessorRegistry {
    @InternalKJWTApi
    override var delegateKeyRegistry: JwtProcessorRegistry? = null

    private val signingProcessors = mutableMapOf<Pair<SigningAlgorithm, String?>, BaseJwsProcessor>()
    private val encryptionProcessors = mutableMapOf<Pair<EncryptionAlgorithm, String?>, BaseJweProcessor>()

    override fun delegateTo(other: JwtProcessorRegistry) {
        var cursor: JwtProcessorRegistry? = other
        while (cursor != null) {
            require(cursor !== this) {
                "Cyclic delegation detected: this registry is already in the delegate chain of the target"
            }
            cursor = cursor.delegateKeyRegistry
        }
        delegateKeyRegistry = other
    }

    /**
     * Registers [processor] under its algorithm and [keyId], merging with any existing entry.
     *
     * If a processor for the same (algorithm, keyId) pair is already present, it is merged with
     * [processor] via [co.touchlab.kjwt.ext.mergeWith] to produce a combined
     * [co.touchlab.kjwt.processor.JwsProcessor].
     */
    override fun registerJwsProcessor(processor: BaseJwsProcessor, keyId: String?) {
        signingProcessors[Pair(processor.algorithm, keyId)] =
            processor.mergeWith(signingProcessors[Pair(processor.algorithm, keyId)])
    }

    /**
     * Registers [processor] under its algorithm and [keyId], merging with any existing entry.
     *
     * If a processor for the same (algorithm, keyId) pair is already present, it is merged with
     * [processor] via [co.touchlab.kjwt.ext.mergeWith] to produce a combined
     * [co.touchlab.kjwt.processor.JweProcessor].
     */
    override fun registerJweProcessor(processor: BaseJweProcessor, keyId: String?) {
        encryptionProcessors[Pair(processor.algorithm, keyId)] =
            processor.mergeWith(encryptionProcessors[Pair(processor.algorithm, keyId)])
    }

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
    override fun findBestJwsProcessor(
        algorithm: SigningAlgorithm,
        keyId: String?,
    ): BaseJwsProcessor? {
        return signingProcessors[Pair(algorithm, keyId)]
            ?: signingProcessors[Pair(algorithm, null)]
            ?: delegateKeyRegistry?.findBestJwsProcessor(algorithm, keyId)
    }

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
    override fun findBestJweProcessor(
        algorithm: EncryptionAlgorithm,
        keyId: String?,
    ): BaseJweProcessor? {
        return encryptionProcessors[Pair(algorithm, keyId)]
            ?: encryptionProcessors[Pair(algorithm, null)]?.let { return it }
            ?: delegateKeyRegistry?.findBestJweProcessor(algorithm, keyId)
    }
}
