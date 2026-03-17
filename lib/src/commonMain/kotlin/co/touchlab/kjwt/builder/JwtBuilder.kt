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

    /**
     * Sets the issuer (`iss`) claim.
     *
     * @param iss the issuer identifier
     * @return this builder for chaining
     */
    public fun issuer(iss: String): JwtBuilder = apply { payloadBuilder.issuer = iss }

    /**
     * Sets the subject (`sub`) claim.
     *
     * @param sub the subject identifier
     * @return this builder for chaining
     */
    public fun subject(sub: String): JwtBuilder = apply { payloadBuilder.subject = sub }

    /**
     * Sets the audience (`aud`) claim.
     *
     * @param aud one or more audience identifiers
     * @return this builder for chaining
     */
    public fun audience(vararg aud: String): JwtBuilder = apply { payloadBuilder.audience = aud.toSet() }

    /**
     * Sets the expiration time (`exp`) claim.
     *
     * @param exp the absolute instant at which the token expires
     * @return this builder for chaining
     */
    public fun expiration(exp: Instant): JwtBuilder = apply { payloadBuilder.expiration = exp }

    /**
     * Sets the expiration time (`exp`) claim relative to the current time.
     *
     * @param duration the duration from now until the token expires
     * @return this builder for chaining
     */
    public fun expiresIn(duration: Duration): JwtBuilder = apply { payloadBuilder.expiresIn(duration) }

    /**
     * Sets the not-before (`nbf`) claim.
     *
     * @param nbf the absolute instant before which the token must not be accepted
     * @return this builder for chaining
     */
    public fun notBefore(nbf: Instant): JwtBuilder = apply { payloadBuilder.notBefore = nbf }

    /**
     * Sets the not-before (`nbf`) claim to the current time.
     *
     * @return this builder for chaining
     */
    public fun notBeforeNow(): JwtBuilder = apply { payloadBuilder.notBeforeNow() }

    /**
     * Sets the issued-at (`iat`) claim.
     *
     * @param iat the instant at which the token was issued
     * @return this builder for chaining
     */
    public fun issuedAt(iat: Instant): JwtBuilder = apply { payloadBuilder.issuedAt = iat }

    /**
     * Sets the issued-at (`iat`) claim to the current time.
     *
     * @return this builder for chaining
     */
    public fun issuedNow(): JwtBuilder = apply { payloadBuilder.issuedNow() }

    /**
     * Sets the JWT ID (`jti`) claim.
     *
     * @param jti the unique identifier for this token
     * @return this builder for chaining
     */
    public fun id(jti: String): JwtBuilder = apply { payloadBuilder.id = jti }

    /**
     * Sets the JWT ID (`jti`) claim to a randomly generated UUID.
     *
     * @return this builder for chaining
     */
    @ExperimentalUuidApi
    public fun randomId(): JwtBuilder = apply { payloadBuilder.randomId() }

    /**
     * Sets a raw claim using a pre-built [JsonElement].
     *
     * @param name the claim name
     * @param value the claim value as a [JsonElement]
     * @return this builder for chaining
     */
    public fun claim(name: String, value: JsonElement): JwtBuilder =
        apply { payloadBuilder.claim(name, value) }

    /**
     * Sets a typed claim using an explicit [SerializationStrategy].
     *
     * @param name the claim name
     * @param serializer the serialization strategy for [T]
     * @param value the claim value, or `null` to remove the claim
     * @return this builder for chaining
     */
    public fun <T> claim(name: String, serializer: SerializationStrategy<T>, value: T?): JwtBuilder =
        apply { payloadBuilder.claim(name, serializer, value) }

    /**
     * Sets a typed claim, inferring the serializer from the reified type [T].
     *
     * @param name the claim name
     * @param value the claim value
     * @return this builder for chaining
     */
    public inline fun <reified T> claim(name: String, value: T): JwtBuilder =
        apply { payloadBuilder.claim(name, value) }

    /**
     * Configures multiple claims at once using a DSL block applied to [JwtPayload.Builder].
     *
     * @param block the configuration block
     * @return this builder for chaining
     */
    public fun claims(block: JwtPayload.Builder.() -> Unit): JwtBuilder =
        apply { payloadBuilder.block() }

    /**
     * Configures JOSE header fields using a DSL block applied to [JwtHeader.Builder].
     *
     * @param block the configuration block
     * @return this builder for chaining
     */
    public fun header(block: JwtHeader.Builder.() -> Unit): JwtBuilder =
        apply { headerBuilder.block() }

    /**
     * Sets the key ID (`kid`) header parameter.
     *
     * @param kid the key identifier
     * @return this builder for chaining
     */
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

    /**
     * Builds and returns an unsecured JWS token with `alg=none` and an empty signature.
     *
     * @param algorithm the [SigningAlgorithm.None] sentinel value
     * @return the resulting [JwtInstance.Jws] with an empty signature segment
     * @see co.touchlab.kjwt.parser.JwtParserBuilder.allowUnsecured
     */
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
