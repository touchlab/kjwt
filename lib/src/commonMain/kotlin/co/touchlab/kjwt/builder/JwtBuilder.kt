package co.touchlab.kjwt.builder

import co.touchlab.kjwt.cryptography.SimpleKey
import co.touchlab.kjwt.cryptography.processors.CryptographyKotlinEncryptionProcessor
import co.touchlab.kjwt.cryptography.processors.CryptographyKotlinIntegrityProcessor
import co.touchlab.kjwt.cryptography.registry.CryptographyKotlinJwtKeyRegistry
import co.touchlab.kjwt.cryptography.registry.EncryptionKey
import co.touchlab.kjwt.cryptography.registry.SigningKey
import co.touchlab.kjwt.cryptography.registry.SigningKey.Identifier
import co.touchlab.kjwt.internal.encodeBase64Url
import co.touchlab.kjwt.internal.encodeToBase64Url
import co.touchlab.kjwt.model.JwtHeader
import co.touchlab.kjwt.model.JwtInstance
import co.touchlab.kjwt.model.JwtPayload
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.EncryptionContentAlgorithm
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import co.touchlab.kjwt.model.registry.JwtKeyRegistry
import co.touchlab.kjwt.processor.JweProcessor
import co.touchlab.kjwt.processor.JwsProcessor
import dev.whyoleg.cryptography.materials.key.Key
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlin.time.Duration
import kotlin.time.Instant
import kotlin.uuid.ExperimentalUuidApi

/**
 * Fluent builder for creating JWS (signed) and JWE (encrypted) compact tokens.
 *
 * Example — signed:
 * ```kotlin
 * val signingKey = SigningAlgorithm.HS256.newKey()
 * val token = Jwt.builder()
 *     .subject("user123")
 *     .issuer("myapp")
 *     .expiration(Clock.System.now() + 1.hours)
 *     .signWith(signingKey)
 * ```
 *
 * Example — encrypted:
 * ```kotlin
 * val encKey = EncryptionAlgorithm.RsaOaep256.newKey()
 * val token = Jwt.builder()
 *     .subject("user123")
 *     .encryptWith(encKey, EncryptionContentAlgorithm.A256GCM)
 * ```
 */
public class JwtBuilder(
    internal val jsonInstance: Json,
) {
    @PublishedApi
    internal val payloadBuilder: JwtPayload.Builder = JwtPayload.Builder()

    @PublishedApi
    internal val headerBuilder: JwtHeader.Builder = JwtHeader.Builder()

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
    public fun claim(
        name: String,
        value: JsonElement,
    ): JwtBuilder = apply { payloadBuilder.claim(name, value) }

    /**
     * Sets a typed claim using an explicit [SerializationStrategy].
     *
     * @param name the claim name
     * @param serializer the serialization strategy for [T]
     * @param value the claim value, or `null` to remove the claim
     * @return this builder for chaining
     */
    public fun <T> claim(
        name: String,
        serializer: SerializationStrategy<T>,
        value: T?,
    ): JwtBuilder = apply { payloadBuilder.claim(name, serializer, value, jsonInstance) }

    /**
     * Sets a typed claim, inferring the serializer from the reified type [T].
     *
     * @param name the claim name
     * @param value the claim value
     * @return this builder for chaining
     */
    public inline fun <reified T> claim(
        name: String,
        value: T,
    ): JwtBuilder = claim(name, kotlinx.serialization.serializer<T>(), value)

    /**
     * Configures multiple claims at once using a DSL block applied to [JwtPayload.Builder].
     *
     * @param block the configuration block
     * @return this builder for chaining
     */
    public fun claims(block: JwtPayload.Builder.() -> Unit): JwtBuilder = apply { payloadBuilder.block() }

    /**
     * Merges all fields from [value] into the payload, encoded using [serializer].
     *
     * The object is serialized to a JSON object and each key-value pair is added to the payload,
     * overwriting any existing claim with the same name.
     *
     * @param serializer the serialization strategy for [T]
     * @param value the object whose fields should be merged into the payload
     * @return this builder for chaining
     */
    public fun <T> payload(
        serializer: SerializationStrategy<T>,
        value: T,
    ): JwtBuilder = apply { payloadBuilder.takeFrom(serializer, value, jsonInstance) }

    /**
     * Merges all fields from [value] into the payload, inferring the serializer from the reified
     * type [T].
     *
     * The object is serialized to a JSON object and each key-value pair is added to the payload,
     * overwriting any existing claim with the same name.
     *
     * @param value the object whose fields should be merged into the payload
     * @return this builder for chaining
     */
    public inline fun <reified T> payload(value: T): JwtBuilder =
        payload(kotlinx.serialization.serializer<T>(), value)

    /**
     * Sets the token type (`typ`) header parameter.
     *
     * @param typ the token type; defaults to `"JWT"`
     * @return this builder for chaining
     */
    public fun type(typ: String): JwtBuilder = apply { headerBuilder.type = typ }

    /**
     * Sets the content type (`cty`) header parameter.
     *
     * @param cty the content type
     * @return this builder for chaining
     */
    public fun contentType(cty: String): JwtBuilder = apply { headerBuilder.contentType = cty }

    /**
     * Sets a raw extra header parameter using a pre-built [JsonElement].
     *
     * @param name the header parameter name
     * @param value the header value as a [JsonElement]
     * @return this builder for chaining
     */
    public fun header(
        name: String,
        value: JsonElement,
    ): JwtBuilder = apply { headerBuilder.extra(name, value) }

    /**
     * Sets a typed extra header parameter using an explicit [SerializationStrategy].
     *
     * @param name the header parameter name
     * @param serializer the serialization strategy for [T]
     * @param value the header value, or `null` to remove the parameter
     * @return this builder for chaining
     */
    public fun <T> header(
        name: String,
        serializer: SerializationStrategy<T>,
        value: T?,
    ): JwtBuilder = apply { headerBuilder.extra(name, serializer, value, jsonInstance) }

    /**
     * Sets a typed extra header parameter, inferring the serializer from the reified type [T].
     *
     * @param name the header parameter name
     * @param value the header value
     * @return this builder for chaining
     */
    public inline fun <reified T> header(
        name: String,
        value: T,
    ): JwtBuilder = header(name, kotlinx.serialization.serializer<T>(), value)

    /**
     * Configures JOSE header fields using a DSL block applied to [JwtHeader.Builder].
     *
     * @param block the configuration block
     * @return this builder for chaining
     */
    public fun header(block: JwtHeader.Builder.() -> Unit): JwtBuilder = apply { headerBuilder.block() }

    /**
     * Merges all fields from [value] into the JOSE header, encoded using [serializer].
     *
     * The object is serialized to a JSON object and each key-value pair is added to the header,
     * overwriting any existing parameter with the same name.
     *
     * @param serializer the serialization strategy for [T]
     * @param value the object whose fields should be merged into the header
     * @return this builder for chaining
     */
    public fun <T> header(
        serializer: SerializationStrategy<T>,
        value: T,
    ): JwtBuilder = apply { headerBuilder.takeFrom(serializer, value, jsonInstance) }

    /**
     * Merges all fields from [value] into the JOSE header, inferring the serializer from the
     * reified type [T].
     *
     * The object is serialized to a JSON object and each key-value pair is added to the header,
     * overwriting any existing parameter with the same name.
     *
     * @param value the object whose fields should be merged into the header
     * @return this builder for chaining
     */
    public inline fun <reified T> header(value: T): JwtBuilder =
        header(kotlinx.serialization.serializer<T>(), value)

    /**
     * Builds and returns a JWS compact serialization: `header.payload.signature`.
     *
     * For [SigningAlgorithm.None] the signature part is empty, producing `header.payload.`
     *
     * @param algorithm the signing algorithm to use
     * @param key the private key (or symmetric key) used to produce the signature
     * @param keyId optional key ID to embed in the JWT header's `kid` field. Defaults to `null`.
     * @return the resulting [JwtInstance.Jws] compact serialization
     */
    public suspend fun <PrivateKey : Key> signWith(
        algorithm: SigningAlgorithm,
        key: PrivateKey,
        keyId: String? = null,
    ): JwtInstance.Jws = signWith(
        SigningKey.SigningOnlyKey<Key, PrivateKey>(Identifier(algorithm, keyId), key),
        keyId,
    )

    /**
     * Looks up the private key from [registry] and builds a JWS compact serialization.
     *
     * The registry is searched using [algorithm] and [keyId] as the look-up criteria (see
     * [CryptographyKotlinJwtKeyRegistry] for the full look-up order). If no matching key is found an
     * [IllegalStateException] is thrown.
     *
     * Passing [co.touchlab.kjwt.model.algorithm.SigningAlgorithm.None] delegates directly to
     * [build] (unsecured token) without consulting the registry.
     *
     * @param algorithm the signing algorithm to use
     * @param registry the key registry to look up the private key from
     * @param keyId optional key ID used for registry look-up and embedded in the JWT header's
     *   `kid` field. Defaults to `null`.
     * @return the resulting [JwtInstance.Jws] compact serialization
     * @throws IllegalStateException if no signing key for [algorithm] (and [keyId]) is found in
     *   [registry]
     * @see CryptographyKotlinJwtKeyRegistry
     */
    public suspend fun signWith(
        algorithm: SigningAlgorithm,
        registry: JwtKeyRegistry,
        keyId: String? = null,
    ): JwtInstance.Jws {
        if (algorithm == SigningAlgorithm.None) {
            return build()
        }

        return try {
            val processor =
                requireNotNull(registry.findBestJwsProcessor(algorithm, keyId)) {
                    "No signing key configured for ${algorithm.id}."
                }
            signWithJwsProcessor(processor, keyId)
        } catch (e: Throwable) {
            throw IllegalArgumentException("The signing key for $keyId does not support signing", e)
        }
    }

    /**
     * Builds and returns a JWS compact serialization using a pre-built [SigningKey.SigningOnlyKey].
     *
     * @param key the signing key (or key pair) used to produce the signature
     * @param keyId optional key ID to embed in the JWT header's `kid` field. Defaults to the
     *   key ID stored in [key]'s identifier.
     * @return the resulting [JwtInstance.Jws] compact serialization
     */
    public suspend fun <PublicKey : Key, PrivateKey : Key> signWith(
        key: SigningKey.SigningOnlyKey<PublicKey, PrivateKey>,
        keyId: String? = key.identifier.keyId,
    ): JwtInstance.Jws = signWithJwsProcessor(CryptographyKotlinIntegrityProcessor(key), keyId)

    /**
     * Builds and returns a JWS compact serialization using a pre-built [SigningKey.SigningKeyPair].
     *
     * @param key the signing key (or key pair) used to produce the signature
     * @param keyId optional key ID to embed in the JWT header's `kid` field. Defaults to the
     *   key ID stored in [key]'s identifier.
     * @return the resulting [JwtInstance.Jws] compact serialization
     */
    public suspend fun <PublicKey : Key, PrivateKey : Key> signWith(
        key: SigningKey.SigningKeyPair<PublicKey, PrivateKey>,
        keyId: String? = key.identifier.keyId,
    ): JwtInstance.Jws = signWithJwsProcessor(CryptographyKotlinIntegrityProcessor(key), keyId)

    private suspend fun signWithJwsProcessor(
        integrityProcessor: JwsProcessor,
        keyId: String? = null,
    ): JwtInstance.Jws {
        val header = headerBuilder.build(integrityProcessor.algorithm, keyId, jsonInstance)
        val payload = payloadBuilder.build(jsonInstance)

        val signingInput = "$header.$payload".encodeToByteArray()
        val signature = if (integrityProcessor.algorithm == SigningAlgorithm.None) {
            ByteArray(0)
        } else {
            integrityProcessor.sign(signingInput)
        }

        return JwtInstance.Jws(header, payload, signature.encodeBase64Url())
    }

    /**
     * Builds and returns an unsecured JWS token with `alg=none` and an empty signature.
     *
     * @return the resulting [JwtInstance.Jws] with an empty signature segment
     * @see co.touchlab.kjwt.parser.JwtParserBuilder.allowUnsecured
     */
    public suspend fun build(): JwtInstance.Jws = signWith(SigningAlgorithm.None, SimpleKey.Empty)

    /**
     * Builds and returns a JWE compact serialization:
     * `header.encryptedKey.iv.ciphertext.tag`
     *
     * @param key the public key used to encrypt the content encryption key
     * @param keyAlgorithm the key encryption algorithm used to wrap the content encryption key
     * @param contentAlgorithm the content encryption algorithm used to encrypt the payload
     * @param keyId optional key ID to embed in the JWE header's `kid` field. Defaults to `null`.
     * @return the resulting [JwtInstance.Jwe] compact serialization
     */
    public suspend fun <PublicKey : Key> encryptWith(
        key: PublicKey,
        keyAlgorithm: EncryptionAlgorithm,
        contentAlgorithm: EncryptionContentAlgorithm,
        keyId: String? = null,
    ): JwtInstance.Jwe =
        encryptWithJweProcessor(
            processor = CryptographyKotlinEncryptionProcessor(
                EncryptionKey.EncryptionOnlyKey<PublicKey, Key>(EncryptionKey.Identifier(keyAlgorithm, keyId), key)
            ),
            contentAlgorithm = contentAlgorithm,
            keyId = keyId,
        )

    /**
     * Looks up the public key from [registry] and builds a JWE compact serialization.
     *
     * The registry is searched using [keyAlgorithm] and [keyId] as the look-up criteria (see
     * [CryptographyKotlinJwtKeyRegistry] for the full look-up order). If no matching key is found an
     * [IllegalStateException] is thrown.
     *
     * @param registry the key registry to look up the public encryption key from
     * @param keyAlgorithm the key encryption algorithm used to wrap the content encryption key
     * @param contentAlgorithm the content encryption algorithm used to encrypt the payload
     * @param keyId optional key ID used for registry look-up and embedded in the JWE header's
     *   `kid` field. Defaults to `null`.
     * @return the resulting [JwtInstance.Jwe] compact serialization
     * @throws IllegalStateException if no encryption key for [keyAlgorithm] (and [keyId]) is
     *   found in [registry]
     * @see CryptographyKotlinJwtKeyRegistry
     */
    public suspend fun encryptWith(
        registry: JwtKeyRegistry,
        keyAlgorithm: EncryptionAlgorithm,
        contentAlgorithm: EncryptionContentAlgorithm,
        keyId: String? = null,
    ): JwtInstance.Jwe = try {
        val processor =
            requireNotNull(registry.findBestJweProcessor(keyAlgorithm, keyId)) {
                "No signing key configured for ${keyAlgorithm.id}."
            }

        encryptWithJweProcessor(processor, contentAlgorithm, keyId)
    } catch (e: Throwable) {
        throw IllegalArgumentException("The signing key for $keyId does not support encryption.", e)
    }

    /**
     * Builds and returns a JWE compact serialization using a pre-built [EncryptionKey.EncryptionOnlyKey].
     *
     * @param key the encryption key used to wrap the content encryption key
     * @param contentAlgorithm the content encryption algorithm used to encrypt the payload
     * @param keyId optional key ID to embed in the JWE header's `kid` field. Defaults to the
     *   key ID stored in [key]'s identifier.
     * @return the resulting [JwtInstance.Jwe] compact serialization
     */
    public suspend fun <PublicKey : Key, PrivateKey : Key> encryptWith(
        key: EncryptionKey.EncryptionOnlyKey<PublicKey, PrivateKey>,
        contentAlgorithm: EncryptionContentAlgorithm,
        keyId: String? = key.identifier.keyId,
    ): JwtInstance.Jwe = encryptWithJweProcessor(CryptographyKotlinEncryptionProcessor(key), contentAlgorithm, keyId)

    /**
     * Builds and returns a JWE compact serialization using a pre-built [EncryptionKey.EncryptionKeyPair].
     *
     * @param key the encryption key used to wrap the content encryption key
     * @param contentAlgorithm the content encryption algorithm used to encrypt the payload
     * @param keyId optional key ID to embed in the JWE header's `kid` field. Defaults to the
     *   key ID stored in [key]'s identifier.
     * @return the resulting [JwtInstance.Jwe] compact serialization
     */
    public suspend fun <PublicKey : Key, PrivateKey : Key> encryptWith(
        key: EncryptionKey.EncryptionKeyPair<PublicKey, PrivateKey>,
        contentAlgorithm: EncryptionContentAlgorithm,
        keyId: String? = key.identifier.keyId,
    ): JwtInstance.Jwe = encryptWithJweProcessor(CryptographyKotlinEncryptionProcessor(key), contentAlgorithm, keyId)

    private suspend fun encryptWithJweProcessor(
        processor: JweProcessor,
        contentAlgorithm: EncryptionContentAlgorithm,
        keyId: String?,
    ): JwtInstance.Jwe {
        val header = headerBuilder.build(processor.algorithm, contentAlgorithm, keyId, jsonInstance)
        val payload = payloadBuilder.build(jsonInstance)

        val headerB64 = jsonInstance.encodeToBase64Url(header)
        val aad = headerB64.encodeToByteArray()
        val plaintext = jsonInstance.encodeToString(payload).encodeToByteArray()

        val result = processor.encrypt(plaintext, aad, contentAlgorithm)

        return JwtInstance.Jwe(
            header = header,
            payload = payload,
            encryptedKey = result.encryptedKey.encodeBase64Url(),
            iv = result.iv.encodeBase64Url(),
            cipherText = result.ciphertext.encodeBase64Url(),
            tag = result.tag.encodeBase64Url(),
        )
    }
}
