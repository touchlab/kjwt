package co.touchlab.kjwt.builder

import co.touchlab.kjwt.algorithm.JweContentAlgorithm
import co.touchlab.kjwt.algorithm.JweKeyAlgorithm
import co.touchlab.kjwt.algorithm.JwsAlgorithm
import co.touchlab.kjwt.cryptography.SimpleKey
import co.touchlab.kjwt.internal.encodeBase64Url
import co.touchlab.kjwt.internal.encodeToBase64Url
import co.touchlab.kjwt.internal.jweEncrypt
import co.touchlab.kjwt.internal.jwsSign
import co.touchlab.kjwt.model.ClaimsBuilder
import co.touchlab.kjwt.model.JweHeader
import co.touchlab.kjwt.model.JwsHeaderBuilder
import dev.whyoleg.cryptography.materials.key.Key
import kotlinx.datetime.Instant
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
    internal val claims = ClaimsBuilder()
    private val headerBuilder = JwsHeaderBuilder()

    fun issuer(iss: String): JwtBuilder = apply { claims.issuer = iss }
    fun subject(sub: String): JwtBuilder = apply { claims.subject = sub }
    fun audience(vararg aud: String): JwtBuilder = apply { claims.audience = aud.toSet() }
    fun expiration(exp: Instant): JwtBuilder = apply { claims.expiration = exp }
    fun notBefore(nbf: Instant): JwtBuilder = apply { claims.notBefore = nbf }
    fun issuedAt(iat: Instant): JwtBuilder = apply { claims.issuedAt = iat }
    fun id(jti: String): JwtBuilder = apply { claims.jwtId = jti }

    fun claim(name: String, value: JsonElement): JwtBuilder = apply { claims.claim(name, value) }
    inline fun <reified T> claim(name: String, value: T): JwtBuilder = apply { claims.claim(name, value) }

    fun claims(block: ClaimsBuilder.() -> Unit): JwtBuilder = apply { claims.block() }

    fun header(block: JwsHeaderBuilder.() -> Unit): JwtBuilder = apply { headerBuilder.block() }
    fun keyId(kid: String): JwtBuilder = apply { headerBuilder.keyId = kid }

    /**
     * Builds and returns a JWS compact serialization: `header.payload.signature`.
     *
     * For [JwsAlgorithm.None] the signature part is empty, producing `header.payload.`
     */
    suspend fun <T : Key> signWith(algorithm: JwsAlgorithm<T>, key: T): String {
        val header = headerBuilder.build(algorithm.id)
        val headerB64 = header.toJsonObject().encodeToBase64Url()
        val payloadB64 = claims.toJsonObject().encodeToBase64Url()
        val signingInput = "$headerB64.$payloadB64".encodeToByteArray()
        val signature = jwsSign(algorithm, key, signingInput)
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
        val header = JweHeader(
            algorithm = keyAlgorithm.id,
            encryption = contentAlgorithm.id,
            type = "JWT",
            keyId = headerBuilder.keyId,
        )
        val headerB64 = header.toJsonObject().encodeToBase64Url()
        val aad = headerB64.encodeToByteArray()
        val plaintext = claims.toJsonObject().toString().encodeToByteArray()

        val result = jweEncrypt(key, keyAlgorithm, contentAlgorithm, plaintext, aad)

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