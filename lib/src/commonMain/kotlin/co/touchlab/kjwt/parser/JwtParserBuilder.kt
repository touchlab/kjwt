package co.touchlab.kjwt.parser

import co.touchlab.kjwt.algorithm.JweContentAlgorithm
import co.touchlab.kjwt.algorithm.JweKeyAlgorithm
import co.touchlab.kjwt.algorithm.JwsAlgorithm
import co.touchlab.kjwt.cryptography.SimpleKey
import co.touchlab.kjwt.exception.IncorrectClaimException
import co.touchlab.kjwt.ext.audience
import co.touchlab.kjwt.ext.getClaim
import co.touchlab.kjwt.ext.issuer
import co.touchlab.kjwt.ext.subject
import co.touchlab.kjwt.model.JwtPayload
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
 * val jws = parser.parseSignedClaims(token)
 * ```
 */
class JwtParserBuilder {
    internal var jwsKeyVerifier: JwsKeyVerifier<*, *>? = null
    internal var jweKeyDecryptor: JweKeyDecryptor<*, *>? = null

    @PublishedApi
    internal val validators: MutableList<(JwtPayload) -> Unit> = mutableListOf()
    internal var clockSkewSeconds: Long = 0L
    internal var allowUnsecured: Boolean = false

    fun noVerify(): JwtParserBuilder = apply {
        allowUnsecured = true
        jwsKeyVerifier = JwsKeyVerifier(JwsAlgorithm.None, SimpleKey.Empty)
    }

    fun <PublicKey : Key, PrivateKey : Key> verifyWith(
        algorithm: JwsAlgorithm<PublicKey, PrivateKey>,
        key: PublicKey
    ): JwtParserBuilder = apply {
        jwsKeyVerifier = JwsKeyVerifier(algorithm, key)
    }

    fun <PublicKey : Key, PrivateKey : Key> decryptWith(
        algorithm: JweKeyAlgorithm<PublicKey, PrivateKey>,
        privateKey: PrivateKey
    ): JwtParserBuilder = apply {
        jweKeyDecryptor = JweKeyDecryptor(algorithm, privateKey)
    }

    fun requireIssuer(iss: String): JwtParserBuilder = apply {
        validators.add {
            val currentValue = it.issuer
            if (currentValue != iss) {
                throw IncorrectClaimException(JwtPayload.ISS, iss, currentValue)
            }
        }
    }

    fun requireSubject(sub: String): JwtParserBuilder = apply {
        validators.add {
            val currentValue = it.subject
            if (currentValue != sub) {
                throw IncorrectClaimException(JwtPayload.SUB, sub, currentValue)
            }
        }
    }

    fun requireAudience(aud: String): JwtParserBuilder = apply {
        validators.add {
            val currentValue = it.audience
            if (currentValue.contains(aud).not()) {
                throw IncorrectClaimException(JwtPayload.AUD, aud, currentValue)
            }
        }
    }

    inline fun <reified T> require(claimName: String, value: T): JwtParserBuilder = apply {
        validators.add {
            val currentValue = it.getClaim<T>(claimName)
            if (currentValue != value) {
                throw IncorrectClaimException(claimName, value, currentValue)
            }
        }
    }

    fun clockSkew(seconds: Long): JwtParserBuilder = apply {
        clockSkewSeconds = seconds
    }

    /**
     * Allow unsigned ("none" algorithm) JWTs. Disabled by default for security.
     */
    fun allowUnsecured(allow: Boolean): JwtParserBuilder = apply {
        allowUnsecured = allow
    }

    fun build(): JwtParser = JwtParser(this)
}

internal data class JwsKeyVerifier<PublicKey : Key, PrivateKey : Key>(
    val algorithm: JwsAlgorithm<PublicKey, PrivateKey>,
    val publicKey: PublicKey,
) {
    suspend fun verify(signingInput: ByteArray, signature: ByteArray): Boolean = try {
        algorithm.verify(publicKey, signingInput, signature)
    } catch (_: Exception) {
        false
    }
}

internal data class JweKeyDecryptor<PublicKey : Key, PrivateKey : Key>(
    val algorithm: JweKeyAlgorithm<PublicKey, PrivateKey>,
    val privateKey: PrivateKey,
) {
    suspend fun decrypt(
        contentAlgorithm: JweContentAlgorithm,
        encryptedKey: ByteArray,
        iv: ByteArray,
        ciphertext: ByteArray,
        tag: ByteArray,
        aad: ByteArray,
    ): ByteArray = algorithm.decrypt(privateKey, contentAlgorithm, encryptedKey, iv, ciphertext, tag, aad)
}
