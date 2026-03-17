package co.touchlab.kjwt.parser

import co.touchlab.kjwt.cryptography.SimpleKey
import co.touchlab.kjwt.exception.IncorrectClaimException
import co.touchlab.kjwt.exception.MissingClaimException
import co.touchlab.kjwt.ext.audienceOrNull
import co.touchlab.kjwt.ext.getClaimOrNull
import co.touchlab.kjwt.ext.issuerOrNull
import co.touchlab.kjwt.ext.subjectOrNull
import co.touchlab.kjwt.model.JwtHeader
import co.touchlab.kjwt.model.JwtPayload
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.EncryptionContentAlgorithm
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import dev.whyoleg.cryptography.materials.key.Key

/**
 * Configures and builds a [JwtParser].
 *
 * Example:
 * ```kotlin
 * val parser = Jwt.parser()
 *     .verifyWith(JwsAlgorithm.HS256, hmacKey)
 *     .requireIssuer("myapp")
 *     .clockSkew(DateTimePeriod(seconds = 30))
 *     .build()
 * val jws = parser.parse(token)
 * ```
 */
public class JwtParserBuilder {
    internal var jwsKeyVerifier: JwsKeyVerifier<*, *>? = null
    internal var jweKeyDecryptor: JweKeyDecryptor<*, *>? = null

    @PublishedApi
    internal val validators: MutableList<(JwtPayload, JwtHeader) -> Unit> = mutableListOf()
    internal var clockSkewSeconds: Long = 0L
    internal var allowUnsecured: Boolean = false

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
        jwsKeyVerifier = JwsKeyVerifier(SigningAlgorithm.None, SimpleKey.Empty)
    }

    /**
     * Sets the algorithm and public key used to verify JWS token signatures.
     *
     * @param algorithm the signing algorithm to use for verification
     * @param key the public key (or symmetric key) for signature verification
     * @return this builder for chaining
     */
    public fun <PublicKey : Key, PrivateKey : Key> verifyWith(
        algorithm: SigningAlgorithm<PublicKey, PrivateKey>,
        key: PublicKey
    ): JwtParserBuilder = apply {
        jwsKeyVerifier = JwsKeyVerifier(algorithm, key)
    }

    /**
     * Sets the algorithm and private key used to decrypt JWE tokens.
     *
     * @param algorithm the key encryption algorithm used to unwrap the content encryption key
     * @param privateKey the private key for decrypting the JWE token
     * @return this builder for chaining
     */
    public fun <PublicKey : Key, PrivateKey : Key> decryptWith(
        algorithm: EncryptionAlgorithm<PublicKey, PrivateKey>,
        privateKey: PrivateKey
    ): JwtParserBuilder = apply {
        jweKeyDecryptor = JweKeyDecryptor(algorithm, privateKey)
    }

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
    }

    /**
     * Builds the configured [JwtParser].
     *
     * @return a [JwtParser] ready to parse and validate tokens
     */
    public fun build(): JwtParser = JwtParser(this)
}

internal data class JwsKeyVerifier<PublicKey : Key, PrivateKey : Key>(
    val algorithm: SigningAlgorithm<PublicKey, PrivateKey>,
    val publicKey: PublicKey,
) {
    suspend fun verify(signingInput: ByteArray, signature: ByteArray): Boolean = try {
        algorithm.verify(publicKey, signingInput, signature)
    } catch (_: Throwable) {
        false
    }
}

internal data class JweKeyDecryptor<PublicKey : Key, PrivateKey : Key>(
    val algorithm: EncryptionAlgorithm<PublicKey, PrivateKey>,
    val privateKey: PrivateKey,
) {
    suspend fun decrypt(
        contentAlgorithm: EncryptionContentAlgorithm,
        encryptedKey: ByteArray,
        iv: ByteArray,
        ciphertext: ByteArray,
        tag: ByteArray,
        aad: ByteArray,
    ): ByteArray = algorithm.decrypt(privateKey, contentAlgorithm, encryptedKey, iv, ciphertext, tag, aad)
}
