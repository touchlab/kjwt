package co.touchlab.kjwt.parser

import co.touchlab.kjwt.algorithm.JweKeyAlgorithm
import co.touchlab.kjwt.algorithm.JwsAlgorithm
import dev.whyoleg.cryptography.materials.key.EncodableKey
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
    internal var jwsKeyHolder: MutableList<JwtKeyHolder<*>> = mutableListOf()
    internal var jweKeyHolder: MutableList<JweKeyHolder<*, *>> = mutableListOf()
    internal val requiredClaims: MutableMap<String, Any> = mutableMapOf()
    internal var clockSkewSeconds: Long = 0L
    internal var allowUnsecured: Boolean = false

    fun <T : EncodableKey<*>> verifyWith(algorithm: JwsAlgorithm<T>, key: T): JwtParserBuilder = apply {
        jwsKeyHolder.add(JwtKeyHolder(algorithm, key))
    }

    fun <PublicKey : Key, PrivateKey : Key> decryptWith(
        algorithm: JweKeyAlgorithm<PublicKey, PrivateKey>,
        privateKey: PrivateKey
    ): JwtParserBuilder = apply {
        jweKeyHolder.add(JweKeyHolder(algorithm, privateKey))
    }

    internal fun <T : Key> definedKeyForAlgorithm(algorithm: JwsAlgorithm<T>): T? {
        @Suppress("UNCHECKED_CAST")
        return jwsKeyHolder.firstOrNull { it.jwsAlgorithm == algorithm }?.jwsKey as? T
    }

    internal fun <PublicKey : Key, PrivateKey : Key> definedKeyForAlgorithm(algorithm: JweKeyAlgorithm<PublicKey, PrivateKey>): PrivateKey? {
        @Suppress("UNCHECKED_CAST")
        return jweKeyHolder.firstOrNull { it.jweAlgorithm == algorithm }?.jwiPrivateKey as? PrivateKey
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

internal data class JwtKeyHolder<out T : EncodableKey<*>>(
    val jwsAlgorithm: JwsAlgorithm<T>,
    val jwsKey: T,
)

internal data class JweKeyHolder<out PublicKey : Key, out PrivateKey : Key>(
    val jweAlgorithm: JweKeyAlgorithm<PublicKey, PrivateKey>,
    val jwiPrivateKey: PublicKey,
)