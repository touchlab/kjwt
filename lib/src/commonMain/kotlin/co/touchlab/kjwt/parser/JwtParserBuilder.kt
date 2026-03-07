package co.touchlab.kjwt.parser

import co.touchlab.kjwt.algorithm.JweContentAlgorithm
import co.touchlab.kjwt.algorithm.JweKeyAlgorithm
import co.touchlab.kjwt.algorithm.JwsAlgorithm
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
    internal var jwsKeyHolder: MutableList<JwsKeyVerifier<*, *>> = mutableListOf()
    internal var jweKeyHolder: MutableList<JweKeyDecryptor<*, *>> = mutableListOf()
    internal val requiredClaims: MutableMap<String, Any> = mutableMapOf()
    internal var clockSkewSeconds: Long = 0L
    internal var allowUnsecured: Boolean = false

    fun <PublicKey : Key, PrivateKey : Key> verifyWith(
        algorithm: JwsAlgorithm<PublicKey, PrivateKey>,
        key: PublicKey
    ): JwtParserBuilder = apply {
        jwsKeyHolder.add(JwsKeyVerifier(algorithm, key))
    }

    fun <PublicKey : Key, PrivateKey : Key> decryptWith(
        algorithm: JweKeyAlgorithm<PublicKey, PrivateKey>,
        privateKey: PrivateKey
    ): JwtParserBuilder = apply {
        jweKeyHolder.add(JweKeyDecryptor(algorithm, privateKey))
    }

    internal fun <PublicKey : Key, PrivateKey : Key> verifierForAlgorithm(
        algorithm: JwsAlgorithm<PublicKey, PrivateKey>
    ): JwsKeyVerifier<PublicKey, PrivateKey>? {
        @Suppress("UNCHECKED_CAST")
        return jwsKeyHolder.firstOrNull { it.algorithm == algorithm } as? JwsKeyVerifier<PublicKey, PrivateKey>
    }

    internal fun <PublicKey : Key, PrivateKey : Key> decryptorForAlgorithm(
        algorithm: JweKeyAlgorithm<PublicKey, PrivateKey>
    ): JweKeyDecryptor<PublicKey, PrivateKey>? {
        @Suppress("UNCHECKED_CAST")
        return jweKeyHolder.firstOrNull { it.algorithm == algorithm } as? JweKeyDecryptor<PublicKey, PrivateKey>
    }

    fun requireIssuer(iss: String): JwtParserBuilder = apply {
        requiredClaims["iss"] = iss
    }

    fun requireSubject(sub: String): JwtParserBuilder = apply {
        requiredClaims["sub"] = sub
    }

    fun requireAudience(aud: String): JwtParserBuilder = apply {
        requiredClaims["aud"] = aud
    }

    fun require(claimName: String, value: Any): JwtParserBuilder = apply {
        requiredClaims[claimName] = value
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