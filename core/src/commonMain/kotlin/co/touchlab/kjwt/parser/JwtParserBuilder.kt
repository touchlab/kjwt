package co.touchlab.kjwt.parser

import co.touchlab.kjwt.annotations.InternalKJWTApi
import co.touchlab.kjwt.exception.IncorrectClaimException
import co.touchlab.kjwt.exception.MissingClaimException
import co.touchlab.kjwt.ext.audienceOrNull
import co.touchlab.kjwt.ext.getClaimOrNull
import co.touchlab.kjwt.ext.issuerOrNull
import co.touchlab.kjwt.ext.subjectOrNull
import co.touchlab.kjwt.model.JwtHeader
import co.touchlab.kjwt.model.JwtPayload
import co.touchlab.kjwt.model.registry.DefaultJwtProcessorRegistry
import co.touchlab.kjwt.model.registry.JwtProcessorRegistry
import co.touchlab.kjwt.model.registry.MutableJwtProcessorRegistry
import co.touchlab.kjwt.processor.JweProcessor
import co.touchlab.kjwt.processor.JwsProcessor
import kotlinx.serialization.json.Json

/**
 * Configures and builds a [JwtParser].
 *
 * Example:
 * ```kotlin
 * val signingKey = SigningAlgorithm.HS256.newKey()
 * val parser = Jwt.parser()
 *     .verifyWith(signingKey)
 *     .requireIssuer("myapp")
 *     .clockSkew(30L)
 *     .build()
 * val jws = parser.parse(token)
 * ```
 */
public class JwtParserBuilder(
    internal val jsonInstance: Json,
) {
    /** The processor registry used by the built [JwtParser] to look up signing and encryption keys. */
    @InternalKJWTApi
    public val processorRegistry: MutableJwtProcessorRegistry = DefaultJwtProcessorRegistry()

    @PublishedApi
    internal val validators: MutableList<(JwtPayload, JwtHeader) -> Unit> = mutableListOf()
    internal var clockSkewSeconds: Long = 0L
    internal var allowUnsecured: Boolean = false
    internal var skipVerification: Boolean = false

    /**
     * Disables signature verification entirely, accepting any token regardless of its signature.
     *
     * **Warning:** This is unsafe and should never be used in production. It is intended only
     * for debugging or testing scenarios where signature validation is not required.
     *
     * @return this builder for chaining
     */
    public fun noVerify(): JwtParserBuilder =
        apply {
            allowUnsecured = true
            skipVerification = true
        }

    /**
     * Delegates key look-up to the given [registry] before consulting this parser's own keys.
     *
     * Keys registered directly on this builder (via [verifyWith] or [decryptWith]) take
     * precedence; the [registry] is only consulted when no local key matches. This makes it easy
     * to share a central key store across multiple parsers while still allowing each parser to
     * override individual keys locally.
     *
     * ```kotlin
     * val sharedRegistry = JwtProcessorRegistry()
     * // keys are added to sharedRegistry elsewhere
     *
     * val parser = Jwt.parser()
     *     .useKeysFrom(sharedRegistry)
     *     .requireIssuer("my-app")
     *     .build()
     * ```
     *
     * @param registry the [JwtProcessorRegistry] to fall back to when no local key matches
     * @return this builder for chaining
     * @see DefaultJwtProcessorRegistry
     */
    public fun useKeysFrom(registry: JwtProcessorRegistry): JwtParserBuilder =
        apply {
            processorRegistry.delegateTo(registry)
        }

    /**
     * Registers a [JwsProcessor] to use for signature verification.
     *
     * The processor is keyed by its [JwsProcessor.algorithm] and [JwsProcessor.keyId]; at parse
     * time the parser selects the best matching processor from the registry.
     *
     * @param processor the [JwsProcessor] that performs signature verification
     * @return this builder for chaining
     * @see co.touchlab.kjwt.builder.JwtBuilder.signWith
     */
    public fun verifyWith(
        processor: JwsProcessor,
    ): JwtParserBuilder = apply { processorRegistry.registerJwsProcessor(processor) }

    /**
     * Registers a [JweProcessor] to use for token decryption.
     *
     * The processor is keyed by its [JweProcessor.algorithm] and [JweProcessor.keyId]; at parse
     * time the parser selects the best matching processor from the registry.
     *
     * @param processor the [JweProcessor] that performs key unwrapping and payload decryption
     * @return this builder for chaining
     * @see co.touchlab.kjwt.builder.JwtBuilder.encryptWithJweProcessor
     */
    public fun decryptWith(
        processor: JweProcessor,
    ): JwtParserBuilder = apply { processorRegistry.registerJweProcessor(processor) }

    /**
     * Adds a validator that requires the `iss` claim to equal the given value.
     *
     * @param iss the expected issuer string
     * @param ignoreCase when `true`, the comparison is case-insensitive; defaults to `false`
     * @return this builder for chaining
     * @throws MissingClaimException if the `iss` claim is absent during parsing
     * @throws IncorrectClaimException if the `iss` claim does not match the expected value
     */
    public fun requireIssuer(
        iss: String,
        ignoreCase: Boolean = false,
    ): JwtParserBuilder =
        apply {
            validators.add { payload, _ ->
                val currentValue = payload.issuerOrNull ?: throw MissingClaimException(JwtPayload.ISS)
                if (!currentValue.equals(iss, ignoreCase)) {
                    throw IncorrectClaimException(JwtPayload.ISS, iss, currentValue)
                }
            }
        }

    /**
     * Adds a validator that requires the `sub` claim to equal the given value.
     *
     * @param sub the expected subject string
     * @return this builder for chaining
     * @throws MissingClaimException if the `sub` claim is absent during parsing
     * @throws IncorrectClaimException if the `sub` claim does not match the expected value
     */
    public fun requireSubject(sub: String): JwtParserBuilder =
        apply {
            validators.add { payload, _ ->
                val currentValue = payload.subjectOrNull ?: throw MissingClaimException(JwtPayload.SUB)
                if (currentValue != sub) {
                    throw IncorrectClaimException(JwtPayload.SUB, sub, currentValue)
                }
            }
        }

    /**
     * Adds a validator that requires the `aud` claim to contain the given value.
     *
     * @param aud the audience value that must be present in the token's `aud` claim
     * @return this builder for chaining
     * @throws MissingClaimException if the `aud` claim is absent during parsing
     * @throws IncorrectClaimException if the `aud` claim does not contain the expected value
     */
    public fun requireAudience(aud: String): JwtParserBuilder =
        apply {
            validators.add { payload, _ ->
                val currentValue = payload.audienceOrNull ?: throw MissingClaimException(JwtPayload.AUD)

                if (currentValue.contains(aud).not()) {
                    throw IncorrectClaimException(JwtPayload.AUD, aud, currentValue)
                }
            }
        }

    /**
     * Adds a validator that requires the named claim to equal the given value.
     *
     * @param claimName the name of the claim to validate
     * @param value the expected value for the claim
     * @return this builder for chaining
     * @throws MissingClaimException if the claim is absent during parsing
     * @throws IncorrectClaimException if the claim does not match the expected value
     */
    public inline fun <reified T> requireClaim(
        claimName: String,
        value: T,
    ): JwtParserBuilder =
        apply {
            validators.add { payload, _ ->
                val currentValue = payload.getClaimOrNull<T>(claimName) ?: throw MissingClaimException(claimName)
                if (currentValue != value) {
                    throw IncorrectClaimException(claimName, value, currentValue)
                }
            }
        }

    /**
     * Sets the acceptable clock skew when validating time-based claims (`exp`, `nbf`, `iat`).
     *
     * @param seconds the number of seconds of permitted clock skew
     * @return this builder for chaining
     */
    public fun clockSkew(seconds: Long): JwtParserBuilder =
        apply {
            clockSkewSeconds = seconds
        }

    /**
     * Configures whether tokens with `alg=none` (unsecured JWTs) are accepted.
     *
     * Unsecured tokens carry no signature and are rejected by default. Pass `true` only when the
     * token source is fully trusted and signature validation is intentionally not required
     * (RFC 7515 §6). Passing `false` re-enables signature verification if [noVerify] had previously
     * disabled it.
     *
     * @param allow `true` to permit `alg=none` tokens; `false` to reject them (the default)
     * @return this builder for chaining
     * @see noVerify
     */
    public fun allowUnsecured(allow: Boolean): JwtParserBuilder =
        apply {
            allowUnsecured = allow
            if (!allow) skipVerification = false
        }

    /**
     * Builds the configured [JwtParser].
     *
     * @return a [JwtParser] ready to parse and validate tokens
     */
    public fun build(): JwtParser = JwtParser(this)
}
