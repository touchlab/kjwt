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

    override fun registerJwsProcessor(processor: BaseJwsProcessor, keyId: String?) {
        signingProcessors[Pair(processor.algorithm, keyId)] =
            processor.mergeWith(signingProcessors[Pair(processor.algorithm, keyId)])
    }

    override fun registerJweProcessor(processor: BaseJweProcessor, keyId: String?) {
        encryptionProcessors[Pair(processor.algorithm, keyId)] =
            processor.mergeWith(encryptionProcessors[Pair(processor.algorithm, keyId)])
    }

    override fun findBestJwsProcessor(
        algorithm: SigningAlgorithm,
        keyId: String?,
    ): BaseJwsProcessor? {
        return signingProcessors[Pair(algorithm, keyId)]
            ?: signingProcessors[Pair(algorithm, null)]
            ?: delegateKeyRegistry?.findBestJwsProcessor(algorithm, keyId)
    }

    override fun findBestJweProcessor(
        algorithm: EncryptionAlgorithm,
        keyId: String?,
    ): BaseJweProcessor? {
        return encryptionProcessors[Pair(algorithm, keyId)]
            ?: encryptionProcessors[Pair(algorithm, null)]?.let { return it }
            ?: delegateKeyRegistry?.findBestJweProcessor(algorithm, keyId)
    }
}
