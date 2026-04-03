package co.touchlab.kjwt.cryptography.ext

import co.touchlab.kjwt.annotations.DelicateKJWTApi
import co.touchlab.kjwt.cryptography.processors.EncryptionKey
import co.touchlab.kjwt.cryptography.processors.SigningKey
import co.touchlab.kjwt.ext.mergeWith
import co.touchlab.kjwt.model.registry.JwtProcessorRegistry
import co.touchlab.kjwt.processor.BaseJweProcessor
import co.touchlab.kjwt.processor.BaseJwsProcessor

/**
 * Registers a [SigningKey] in this registry, merging it with any existing processor for the same
 * algorithm and key ID.
 *
 * @param key the signing key to register
 * @throws IllegalArgumentException if a key of the same type is already registered for the same
 *   algorithm and key ID
 */
@OptIn(DelicateKJWTApi::class)
public fun JwtProcessorRegistry.registerSigningKey(key: SigningKey) {
    registerJwsProcessor(key)
}

/**
 * Looks up the existing [BaseJwsProcessor] for the algorithm and key ID in [key]'s identifier,
 * then merges [key] with that existing processor.
 *
 * When the existing processor is also a [SigningKey], the merge is performed at the key level,
 * producing a [SigningKey.SigningKeyPair]. Otherwise the generic processor combining mechanism is
 * used.
 *
 * @param key the signing key whose algorithm and key ID are used to locate an existing processor
 * @return a [BaseJwsProcessor] incorporating the new key, merged with any previously registered key
 * @throws IllegalArgumentException if a signing key of the same type is already registered for
 *   the same algorithm and key ID
 */
@DelicateKJWTApi
public fun JwtProcessorRegistry.findBestJwsProcessorAndMerge(
    key: SigningKey,
): BaseJwsProcessor {
    val previous = findBestJwsProcessor(key.identifier.algorithm, key.identifier.keyId)
    return try {
        when (previous) {
            null -> key
            is SigningKey -> key.mergeWith(previous)
            else -> (key as BaseJwsProcessor).mergeWith(previous)
        }
    } catch (error: IllegalArgumentException) {
        throw IllegalArgumentException(
            "Signing key for '${key.identifier.algorithm.id}' " +
                "identified by '${key.identifier.keyId}' already registered",
            error,
        )
    }
}

/**
 * Registers an [EncryptionKey] in this registry, merging it with any existing processor for the
 * same algorithm and key ID.
 *
 * @param key the encryption key to register
 * @throws IllegalArgumentException if a key of the same type is already registered for the same
 *   algorithm and key ID
 */
@OptIn(DelicateKJWTApi::class)
public fun JwtProcessorRegistry.registerEncryptionKey(key: EncryptionKey) {
    registerJweProcessor(key)
}

/**
 * Looks up the existing [BaseJweProcessor] for the algorithm and key ID in [key]'s identifier,
 * then merges [key] with that existing processor.
 *
 * When the existing processor is also an [EncryptionKey], the merge is performed at the key level,
 * producing an [EncryptionKey.EncryptionKeyPair]. Otherwise the generic processor combining
 * mechanism is used.
 *
 * @param key the encryption key whose algorithm and key ID are used to locate an existing processor
 * @return a [BaseJweProcessor] incorporating the new key, merged with any previously registered key
 * @throws IllegalArgumentException if an encryption key of the same type is already registered for
 *   the same algorithm and key ID
 */
@DelicateKJWTApi
public fun JwtProcessorRegistry.findBestJweProcessorAndMerge(
    key: EncryptionKey,
): BaseJweProcessor {
    val previous = findBestJweProcessor(key.identifier.algorithm, key.identifier.keyId)
    return try {
        when (previous) {
            null -> key
            is EncryptionKey -> key.mergeWith(previous)
            else -> (key as BaseJweProcessor).mergeWith(previous)
        }
    } catch (error: IllegalArgumentException) {
        throw IllegalArgumentException(
            "Encryption key for '${key.identifier.algorithm.id}' " +
                "identified by '${key.identifier.keyId}' already registered",
            error,
        )
    }
}
