package co.touchlab.kjwt.parser

import co.touchlab.kjwt.exception.IncorrectClaimException
import co.touchlab.kjwt.exception.MissingClaimException
import co.touchlab.kjwt.ext.audienceOrNull
import co.touchlab.kjwt.ext.getClaimOrNull
import co.touchlab.kjwt.ext.issuerOrNull
import co.touchlab.kjwt.ext.subjectOrNull
import co.touchlab.kjwt.model.JwtHeader
import co.touchlab.kjwt.model.JwtPayload
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import co.touchlab.kjwt.model.registry.EncryptionKey
import co.touchlab.kjwt.model.registry.JwtKeyRegistry
import co.touchlab.kjwt.model.registry.SigningKey
import dev.whyoleg.cryptography.materials.key.Key

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
public class JwtParserBuilder {
    internal val keyRegistry = JwtKeyRegistry()

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
    public fun noVerify(): JwtParserBuilder = apply {
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
     * val sharedRegistry = JwtKeyRegistry()
     * // keys are added to sharedRegistry elsewhere
     *
     * val parser = Jwt.parser()
     *     .useKeysFrom(sharedRegistry)
     *     .requireIssuer("my-app")
     *     .build()
     * ```
     *
     * @param registry the [JwtKeyRegistry] to fall back to when no local key matches
     * @return this builder for chaining
     * @see JwtKeyRegistry
     */
    public fun useKeysFrom(registry: JwtKeyRegistry): JwtParserBuilder = apply {
        keyRegistry.delegateTo(registry)
    }

    /**
     * Sets the algorithm and public key used to verify JWS token signatures.
     *
     * @param algorithm the signing algorithm to use for verification
     * @param key the public key (or symmetric key) for signature verification
     * @param keyId optional key ID to associate with this verifier; when set, the parser will
     *   only use this key if the token's `kid` header matches. Defaults to `null` (matches any token).
     * @return this builder for chaining
     */
    public fun <PublicKey : Key, PrivateKey : Key> verifyWith(
        algorithm: SigningAlgorithm<PublicKey, PrivateKey>,
        key: PublicKey,
        keyId: String? = null,
    ): JwtParserBuilder = apply {
        keyRegistry.registerSigningKey(
            SigningKey.VerifyOnlyKey(
                identifier = SigningKey.Identifier(algorithm, keyId),
                publicKey = key
            )
        )
    }

    /**
     * Registers a pre-built [SigningKey.VerifyOnlyKey] for JWS signature verification.
     *
     * The algorithm and `kid` are taken from [key]'s [SigningKey.Identifier].
     *
     * @param key the verify-only signing key to register
     * @return this builder for chaining
     */
    public fun <PublicKey : Key, PrivateKey : Key> verifyWith(
        key: SigningKey.VerifyOnlyKey<PublicKey, PrivateKey>,
    ): JwtParserBuilder = apply { keyRegistry.registerSigningKey(key) }

    /**
     * Registers a pre-built [SigningKey.SigningKeyPair] for JWS signature verification.
     *
     * The algorithm and `kid` are taken from [key]'s [SigningKey.Identifier]. Both the public and
     * private key material are stored, but only the public key is used for verification.
     *
     * @param key the signing key pair to register
     * @return this builder for chaining
     */
    public fun <PublicKey : Key, PrivateKey : Key> verifyWith(
        key: SigningKey.SigningKeyPair<PublicKey, PrivateKey>,
    ): JwtParserBuilder = apply { keyRegistry.registerSigningKey(key) }

    /**
     * Sets the algorithm and private key used to decrypt JWE tokens.
     *
     * @param algorithm the key encryption algorithm used to unwrap the content encryption key
     * @param privateKey the private key for decrypting the JWE token
     * @param keyId optional key ID to associate with this decryptor; when set, the parser will
     *   only use this key if the token's `kid` header matches. Defaults to `null` (matches any token).
     * @return this builder for chaining
     */
    public fun <PublicKey : Key, PrivateKey : Key> decryptWith(
        algorithm: EncryptionAlgorithm<PublicKey, PrivateKey>,
        privateKey: PrivateKey,
        keyId: String? = null,
    ): JwtParserBuilder = apply {
        keyRegistry.registerEncryptionKey(
            EncryptionKey.DecryptionOnlyKey(
                identifier = EncryptionKey.Identifier(algorithm, keyId),
                privateKey = privateKey,
            )
        )
    }

    /**
     * Registers a pre-built [EncryptionKey.DecryptionOnlyKey] for JWE token decryption.
     *
     * The algorithm and `kid` are taken from [key]'s [EncryptionKey.Identifier].
     *
     * @param key the decryption-only encryption key to register
     * @return this builder for chaining
     */
    public fun <PublicKey : Key, PrivateKey : Key> decryptWith(
        key: EncryptionKey.DecryptionOnlyKey<PublicKey, PrivateKey>,
    ): JwtParserBuilder = apply { keyRegistry.registerEncryptionKey(key) }

    /**
     * Registers a pre-built [EncryptionKey.EncryptionKeyPair] for JWE token decryption.
     *
     * The algorithm and `kid` are taken from [key]'s [EncryptionKey.Identifier]. Both the public
     * and private key material are stored, but only the private key is used for decryption.
     *
     * @param key the encryption key pair to register
     * @return this builder for chaining
     */
    public fun <PublicKey : Key, PrivateKey : Key> decryptWith(
        key: EncryptionKey.EncryptionKeyPair<PublicKey, PrivateKey>,
    ): JwtParserBuilder = apply { keyRegistry.registerEncryptionKey(key) }

    /**
     * Adds a validator that requires the `iss` claim to equal the given value.
     *
     * @param iss the expected issuer string
     * @param ignoreCase when `true`, the comparison is case-insensitive; defaults to `false`
     * @return this builder for chaining
     * @throws MissingClaimException if the `iss` claim is absent during parsing
     * @throws IncorrectClaimException if the `iss` claim does not match the expected value
     */
    public fun requireIssuer(iss: String, ignoreCase: Boolean = false): JwtParserBuilder = apply {
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
    public fun requireSubject(sub: String): JwtParserBuilder = apply {
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
    public fun requireAudience(aud: String): JwtParserBuilder = apply {
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
    public inline fun <reified T> requireClaim(claimName: String, value: T): JwtParserBuilder = apply {
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
    public fun clockSkew(seconds: Long): JwtParserBuilder = apply {
        clockSkewSeconds = seconds
    }

    /**
     * Allow unsigned ("none" algorithm) JWTs. Disabled by default for security.
     */
    public fun allowUnsecured(allow: Boolean): JwtParserBuilder = apply {
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
