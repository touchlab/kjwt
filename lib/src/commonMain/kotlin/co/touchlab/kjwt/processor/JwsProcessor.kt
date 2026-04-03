package co.touchlab.kjwt.processor

import co.touchlab.kjwt.model.algorithm.SigningAlgorithm

/**
 * Common base for all JWS processor types, carrying the [algorithm] and optional [keyId] that
 * identify the key material used for signing or verification.
 *
 * Subtypes specialise into [JwsSigner] (signing only), [JwsVerifier] (verification only), or the
 * combined [JwsProcessor].
 *
 * @see JwsSigner
 * @see JwsVerifier
 * @see JwsProcessor
 */
public interface BaseJwsProcessor {
    /** The JWS signing algorithm this processor implements. */
    public val algorithm: SigningAlgorithm

    /** The optional key ID (`kid`) associated with the key material used by this processor. */
    public val keyId: String?

    public companion object;
}

/**
 * Core abstraction for JWS (signed JWT) signing and verification.
 *
 * Combines the [JwsSigner] and [JwsVerifier] functional interfaces and associates them with a
 * [SigningAlgorithm] and an optional key ID. Implementations are supplied to
 * [co.touchlab.kjwt.builder.JwtBuilder] for signing and to
 * [co.touchlab.kjwt.parser.JwtParserBuilder] for verification.
 *
 * @see BaseJwsProcessor
 * @see JwsSigner
 * @see JwsVerifier
 */
public interface JwsProcessor : BaseJwsProcessor, JwsSigner, JwsVerifier {
    public companion object {
        /**
         * Creates a [JwsProcessor] that delegates signing to [signer] and verification to [verifier].
         *
         * Both must share the same algorithm; [signer]'s algorithm and key ID are used for the
         * combined processor.
         *
         * @param signer the [JwsSigner] that performs signing
         * @param verifier the [JwsVerifier] that performs verification
         * @return a [JwsProcessor] combining both operations
         */
        public fun combining(
            signer: JwsSigner,
            verifier: JwsVerifier,
        ): JwsProcessor = object : JwsProcessor, JwsSigner by signer, JwsVerifier by verifier {
            override val algorithm: SigningAlgorithm = signer.algorithm
            override val keyId: String? = signer.keyId
        }
    }
}

/**
 * Functional interface for producing a JWS signature over raw byte data.
 *
 * @see JwsProcessor
 */
public interface JwsSigner : BaseJwsProcessor {
    /**
     * Signs [data] and returns the raw signature bytes.
     *
     * @param data the data to sign
     * @return the raw signature bytes produced by the signing operation
     */
    public suspend fun sign(data: ByteArray): ByteArray

    public companion object;
}

/**
 * Functional interface for verifying a JWS signature against raw byte data.
 *
 * @see JwsProcessor
 */
public interface JwsVerifier : BaseJwsProcessor {
    /**
     * Verifies that [signature] is a valid signature over [data].
     *
     * @param data the data that was originally signed
     * @param signature the raw signature bytes to verify
     * @return `true` if the signature is valid, `false` otherwise
     */
    public suspend fun verify(data: ByteArray, signature: ByteArray): Boolean

    public companion object;
}
