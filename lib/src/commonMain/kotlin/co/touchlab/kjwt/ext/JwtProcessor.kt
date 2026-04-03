package co.touchlab.kjwt.ext

import co.touchlab.kjwt.processor.BaseJweProcessor
import co.touchlab.kjwt.processor.BaseJwsProcessor
import co.touchlab.kjwt.processor.JweDecryptor
import co.touchlab.kjwt.processor.JweEncryptor
import co.touchlab.kjwt.processor.JweProcessor
import co.touchlab.kjwt.processor.JwsProcessor
import co.touchlab.kjwt.processor.JwsSigner
import co.touchlab.kjwt.processor.JwsVerifier

/**
 * Merges this [BaseJwsProcessor] with [other], producing a combined [JwsProcessor] that supports
 * both signing and verification.
 *
 * Returns `this` unchanged when [other] is `null`. The two processors must share the same
 * [algorithm], be of different runtime types, and neither may already be a full [JwsProcessor].
 * Merging a [JwsSigner] with a [JwsVerifier] (or vice versa) yields a [JwsProcessor] via
 * [JwsProcessor.combining].
 *
 * @param other the complementary processor to merge with, or `null` to skip merging
 * @return the merged [JwsProcessor], or `this` if [other] is `null`
 * @throws IllegalArgumentException if the algorithms differ, the types are the same, or either
 *   processor already implements both operations
 */
public fun BaseJwsProcessor.mergeWith(other: BaseJwsProcessor?): BaseJwsProcessor {
    if (other == null) return this

    require(algorithm == other.algorithm) { "Cannot merge keys with different identifiers" }
    require(this::class != other::class) { "Cannot merge keys of the same type" }
    require(
        this !is JwsProcessor && other !is JwsProcessor
    ) { "Cannot merge when one of the keys already support both operations" }

    return when (this) {
        is JwsSigner if other is JwsVerifier -> {
            JwsProcessor.combining(this, other)
        }

        is JwsVerifier if other is JwsSigner -> {
            JwsProcessor.combining(other, this)
        }

        else -> {
            error("Cannot merge given keys")
        }
    }
}

/**
 * Merges this [BaseJweProcessor] with [other], producing a combined [JweProcessor] that supports
 * both encryption and decryption.
 *
 * Returns `this` unchanged when [other] is `null`. The two processors must share the same
 * [algorithm], be of different runtime types, and neither may already be a full [JweProcessor].
 * Merging a [JweEncryptor] with a [JweDecryptor] (or vice versa) yields a [JweProcessor] via
 * [JweProcessor.combining].
 *
 * @param other the complementary processor to merge with, or `null` to skip merging
 * @return the merged [JweProcessor], or `this` if [other] is `null`
 * @throws IllegalArgumentException if the algorithms differ, the types are the same, or either
 *   processor already implements both operations
 */
public fun BaseJweProcessor.mergeWith(other: BaseJweProcessor?): BaseJweProcessor {
    if (other == null) return this

    require(algorithm == other.algorithm) { "Cannot merge keys with different identifiers" }
    require(this::class != other::class) { "Cannot merge keys of the same type" }
    require(
        this !is JweProcessor && other !is JweProcessor
    ) { "Cannot merge when one of the keys already support both operations" }

    return when (this) {
        is JweEncryptor if other is JweDecryptor -> {
            JweProcessor.combining(this, other)
        }

        is JweDecryptor if other is JweEncryptor -> {
            JweProcessor.combining(other, this)
        }

        else -> {
            error("Cannot merge given keys")
        }
    }
}
