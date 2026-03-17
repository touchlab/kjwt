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

    public fun noVerify(): JwtParserBuilder = apply {
        allowUnsecured = true
        jwsKeyVerifier = JwsKeyVerifier(SigningAlgorithm.None, SimpleKey.Empty)
    }

    public fun <PublicKey : Key, PrivateKey : Key> verifyWith(
        algorithm: SigningAlgorithm<PublicKey, PrivateKey>,
        key: PublicKey
    ): JwtParserBuilder = apply {
        jwsKeyVerifier = JwsKeyVerifier(algorithm, key)
    }

    public fun <PublicKey : Key, PrivateKey : Key> decryptWith(
        algorithm: EncryptionAlgorithm<PublicKey, PrivateKey>,
        privateKey: PrivateKey
    ): JwtParserBuilder = apply {
        jweKeyDecryptor = JweKeyDecryptor(algorithm, privateKey)
    }

    public fun requireIssuer(iss: String, ignoreCase: Boolean = false): JwtParserBuilder = apply {
        validators.add { payload, _ ->
            val currentValue = payload.issuerOrNull ?: throw MissingClaimException(JwtPayload.ISS)
            if (!currentValue.equals(iss, ignoreCase)) {
                throw IncorrectClaimException(JwtPayload.ISS, iss, currentValue)
            }
        }
    }

    public fun requireSubject(sub: String): JwtParserBuilder = apply {
        validators.add { payload, _ ->
            val currentValue = payload.subjectOrNull ?: throw MissingClaimException(JwtPayload.SUB)
            if (currentValue != sub) {
                throw IncorrectClaimException(JwtPayload.SUB, sub, currentValue)
            }
        }
    }

    public fun requireAudience(aud: String): JwtParserBuilder = apply {
        validators.add { payload, _ ->
            val currentValue = payload.audienceOrNull ?: throw MissingClaimException(JwtPayload.AUD)

            if (currentValue.contains(aud).not()) {
                throw IncorrectClaimException(JwtPayload.AUD, aud, currentValue)
            }
        }
    }

    public inline fun <reified T> requireClaim(claimName: String, value: T): JwtParserBuilder = apply {
        validators.add { payload, _ ->
            val currentValue = payload.getClaimOrNull<T>(claimName) ?: throw MissingClaimException(claimName)
            if (currentValue != value) {
                throw IncorrectClaimException(claimName, value, currentValue)
            }
        }
    }

    public fun clockSkew(seconds: Long): JwtParserBuilder = apply {
        clockSkewSeconds = seconds
    }

    /**
     * Allow unsigned ("none" algorithm) JWTs. Disabled by default for security.
     */
    public fun allowUnsecured(allow: Boolean): JwtParserBuilder = apply {
        allowUnsecured = allow
    }

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
