package co.touchlab.kjwt.builder

import co.touchlab.kjwt.cryptography.SimpleKey
import co.touchlab.kjwt.internal.JwtJson
import co.touchlab.kjwt.internal.encodeBase64Url
import co.touchlab.kjwt.internal.encodeToBase64Url
import co.touchlab.kjwt.model.JwtHeader
import co.touchlab.kjwt.model.JwtInstance
import co.touchlab.kjwt.model.JwtPayload
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.EncryptionContentAlgorithm
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import dev.whyoleg.cryptography.materials.key.Key
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.json.JsonElement
import kotlin.time.Duration
import kotlin.time.Instant
import kotlin.uuid.ExperimentalUuidApi

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
public class JwtBuilder {
    @PublishedApi
    internal val payloadBuilder: JwtPayload.Builder = JwtPayload.Builder()
    private val headerBuilder: JwtHeader.Builder = JwtHeader.Builder()

    public fun issuer(iss: String): JwtBuilder = apply { payloadBuilder.issuer = iss }
    public fun subject(sub: String): JwtBuilder = apply { payloadBuilder.subject = sub }
    public fun audience(vararg aud: String): JwtBuilder = apply { payloadBuilder.audience = aud.toSet() }
    public fun expiration(exp: Instant): JwtBuilder = apply { payloadBuilder.expiration = exp }
    public fun expiresIn(duration: Duration): JwtBuilder = apply { payloadBuilder.expiresIn(duration) }
    public fun notBefore(nbf: Instant): JwtBuilder = apply { payloadBuilder.notBefore = nbf }
    public fun notBeforeNow(): JwtBuilder = apply { payloadBuilder.notBeforeNow() }
    public fun issuedAt(iat: Instant): JwtBuilder = apply { payloadBuilder.issuedAt = iat }
    public fun issuedNow(): JwtBuilder = apply { payloadBuilder.issuedNow() }
    public fun id(jti: String): JwtBuilder = apply { payloadBuilder.id = jti }

    @ExperimentalUuidApi
    public fun randomId(): JwtBuilder = apply { payloadBuilder.randomId() }

    public fun claim(name: String, value: JsonElement): JwtBuilder =
        apply { payloadBuilder.claim(name, value) }

    public fun <T> claim(name: String, serializer: SerializationStrategy<T>, value: T?): JwtBuilder =
        apply { payloadBuilder.claim(name, serializer, value) }

    public inline fun <reified T> claim(name: String, value: T): JwtBuilder =
        apply { payloadBuilder.claim(name, value) }

    public fun claims(block: JwtPayload.Builder.() -> Unit): JwtBuilder =
        apply { payloadBuilder.block() }

    public fun header(block: JwtHeader.Builder.() -> Unit): JwtBuilder =
        apply { headerBuilder.block() }

    public fun keyId(kid: String): JwtBuilder =
        apply { headerBuilder.keyId = kid }

    /**
     * Builds and returns a JWS compact serialization: `header.payload.signature`.
     *
     * For [SigningAlgorithm.None] the signature part is empty, producing `header.payload.`
     */
    public suspend fun <PublicKey : Key, PrivateKey : Key> signWith(
        algorithm: SigningAlgorithm<PublicKey, PrivateKey>,
        key: PrivateKey
    ): JwtInstance.Jws {
        val header = headerBuilder.build(algorithm)
        val payload = payloadBuilder.build()

        val signingInput = "$header.$payload".encodeToByteArray()
        val signature = algorithm.sign(key, signingInput)

        return JwtInstance.Jws(header, payload, signature.encodeBase64Url())
    }

    public suspend fun signWith(algorithm: SigningAlgorithm.None): JwtInstance.Jws =
        signWith(algorithm, SimpleKey.Empty)

    /**
     * Builds and returns a JWE compact serialization:
     * `header.encryptedKey.iv.ciphertext.tag`
     */
    public suspend fun <PublicKey : Key, PrivateKey : Key> encryptWith(
        key: PublicKey,
        keyAlgorithm: EncryptionAlgorithm<PublicKey, PrivateKey>,
        contentAlgorithm: EncryptionContentAlgorithm,
    ): JwtInstance.Jwe {
        val header = headerBuilder.build(keyAlgorithm, contentAlgorithm)
        val payload = payloadBuilder.build()

        val headerB64 = JwtJson.encodeToBase64Url(header)
        val aad = headerB64.encodeToByteArray()
        val plaintext = JwtJson.encodeToString(payload).encodeToByteArray()

        val result = keyAlgorithm.encrypt(key, contentAlgorithm, plaintext, aad)

        return JwtInstance.Jwe(
            header = header,
            payload = payload,
            encryptedKey = result.encryptedKey.encodeBase64Url(),
            iv = result.iv.encodeBase64Url(),
            cipherText = result.ciphertext.encodeBase64Url(),
            tag = result.tag.encodeBase64Url()
        )
    }
}
