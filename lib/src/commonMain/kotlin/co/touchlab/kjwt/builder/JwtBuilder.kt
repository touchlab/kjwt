package co.touchlab.kjwt.builder

import co.touchlab.kjwt.algorithm.JweContentAlgorithm
import co.touchlab.kjwt.algorithm.JweKeyAlgorithm
import co.touchlab.kjwt.algorithm.JwsAlgorithm
import co.touchlab.kjwt.cryptography.SimpleKey
import co.touchlab.kjwt.internal.JwtJson
import co.touchlab.kjwt.internal.encodeBase64Url
import co.touchlab.kjwt.internal.encodeToBase64Url
import co.touchlab.kjwt.model.Claims
import co.touchlab.kjwt.model.JwtHeader
import dev.whyoleg.cryptography.materials.key.Key
import kotlin.time.Instant
import kotlinx.serialization.json.JsonElement

/**
 * Fluent builder for creating JWS (signed) and JWE (encrypted) compact tokens.
 *
 * Example — signed:
 * ```kotlin
 * val token = Jwt.builder()
 *     .subject("user123")
 *     .issuer("myapp")
 *     .expiration(Clock.System.now() + 1.hours)
 *     .signWith(JwsAlgorithm.HS256, hmacKey)
 * ```
 *
 * Example — encrypted:
 * ```kotlin
 * val token = Jwt.builder()
 *     .subject("user123")
 *     .encryptWith(rsaPublicKey, JweKeyAlgorithm.RsaOaep256, JweContentAlgorithm.A256GCM)
 * ```
 */
class JwtBuilder {
    @PublishedApi
    internal val claimsBuilder = Claims.Builder()
    private val headerBuilder = JwtHeader.Builder()

    fun issuer(iss: String): JwtBuilder = apply { claimsBuilder.issuer = iss }
    fun subject(sub: String): JwtBuilder = apply { claimsBuilder.subject = sub }
    fun audience(vararg aud: String): JwtBuilder = apply { claimsBuilder.audience = aud.toSet() }
    fun expiration(exp: Instant): JwtBuilder = apply { claimsBuilder.expiration = exp }
    fun notBefore(nbf: Instant): JwtBuilder = apply { claimsBuilder.notBefore = nbf }
    fun issuedAt(iat: Instant): JwtBuilder = apply { claimsBuilder.issuedAt = iat }
    fun id(jti: String): JwtBuilder = apply { claimsBuilder.jwtId = jti }

    fun claim(name: String, value: JsonElement): JwtBuilder = apply { claimsBuilder.claim(name, value) }
    inline fun <reified T> claim(name: String, value: T): JwtBuilder = apply { claimsBuilder.claim(name, value) }

    fun claims(block: Claims.Builder.() -> Unit): JwtBuilder = apply { claimsBuilder.block() }

    fun header(block: JwtHeader.Builder.() -> Unit): JwtBuilder = apply { headerBuilder.block() }
    fun keyId(kid: String): JwtBuilder = apply { headerBuilder.keyId = kid }

    /**
     * Builds and returns a JWS compact serialization: `header.payload.signature`.
     *
     * For [JwsAlgorithm.None] the signature part is empty, producing `header.payload.`
     */
    suspend fun <PublicKey : Key, PrivateKey : Key> signWith(
        algorithm: JwsAlgorithm<PublicKey, PrivateKey>,
        key: PrivateKey
    ): String {
        val header = headerBuilder.build(algorithm)
        val claims = claimsBuilder.build()

        val headerB64 = JwtJson.encodeToBase64Url(header)
        val payloadB64 = JwtJson.encodeToBase64Url(claims)

        val signingInput = "$headerB64.$payloadB64".encodeToByteArray()
        val signature = algorithm.sign(key, signingInput)
        return "$headerB64.$payloadB64.${signature.encodeBase64Url()}"
    }

    suspend fun signWith(algorithm: JwsAlgorithm.None): String =
        signWith(algorithm, SimpleKey.Empty)

    /**
     * Builds and returns a JWE compact serialization:
     * `header.encryptedKey.iv.ciphertext.tag`
     */
    suspend fun <PublicKey : Key, PrivateKey : Key> encryptWith(
        key: PublicKey,
        keyAlgorithm: JweKeyAlgorithm<PublicKey, PrivateKey>,
        contentAlgorithm: JweContentAlgorithm,
    ): String {
        val header = headerBuilder.build(keyAlgorithm, contentAlgorithm)
        val claims = claimsBuilder.build()

        val headerB64 = JwtJson.encodeToBase64Url(header)
        val aad = headerB64.encodeToByteArray()
        val plaintext = JwtJson.encodeToString(claims).encodeToByteArray()

        val result = keyAlgorithm.encrypt(key, contentAlgorithm, plaintext, aad)

        return buildString {
            append(headerB64)
            append('.')
            append(result.encryptedKey.encodeBase64Url())
            append('.')
            append(result.iv.encodeBase64Url())
            append('.')
            append(result.ciphertext.encodeBase64Url())
            append('.')
            append(result.tag.encodeBase64Url())
        }
    }
}