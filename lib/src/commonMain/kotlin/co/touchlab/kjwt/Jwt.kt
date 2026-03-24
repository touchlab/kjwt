package co.touchlab.kjwt

import co.touchlab.kjwt.builder.JwtBuilder
import co.touchlab.kjwt.internal.JwtJson
import co.touchlab.kjwt.parser.JwtParserBuilder
import kotlinx.serialization.json.Json

/**
 * Entry point for the KJWT library.
 *
 * **Create a signed JWT (JWS):**
 * ```kotlin
 * val token = Jwt.builder()
 *     .subject("user123")
 *     .issuer("myapp")
 *     .expiration(Clock.System.now() + 1.hours)
 *     .signWith(JwsAlgorithm.HS256, hmacKey)
 * ```
 *
 * **Parse and verify a signed JWT:**
 * ```kotlin
 * val jws = Jwt.parser()
 *     .verifyWith(JwsAlgorithm.HS256, hmacKey)
 *     .requireIssuer("myapp")
 *     .build()
 *     .parseSigned(token)
 * val subject = jws.payload.subject
 * ```
 *
 * **Create an encrypted JWT (JWE):**
 * ```kotlin
 * val token = Jwt.builder()
 *     .subject("user123")
 *     .encryptWith(rsaPublicKey, JweKeyAlgorithm.RsaOaep256, JweContentAlgorithm.A256GCM)
 * ```
 *
 * **Decrypt a JWE:**
 * ```kotlin
 * val jwe = Jwt.parser()
 *     .decryptWith(rsaPrivateKey)
 *     .build()
 *     .parseEncrypted(token)
 * ```
 *
 * **Note:** This library depends on `cryptography-core` interfaces. You must register a
 * `CryptographyProvider` before use. The recommended approach is to add
 * `cryptography-provider-optimal` to your app dependencies — it auto-registers on startup.
 */
public object Jwt {
    /**
     * Creates a new [JwtBuilder] for constructing JWS or JWE tokens.
     *
     * @param jsonInstance the [Json] instance to use for all serialization within this builder;
     *   defaults to the library's internal configuration (`ignoreUnknownKeys = true`,
     *   `explicitNulls = false`)
     * @return a new [JwtBuilder]
     */
    public fun builder(
        jsonInstance: Json = JwtJson,
    ): JwtBuilder = JwtBuilder(jsonInstance)

    /**
     * Creates a new [JwtParserBuilder] for parsing and validating JWS or JWE tokens.
     *
     * @param jsonInstance the [Json] instance to use for all deserialization within this parser;
     *   defaults to the library's internal configuration (`ignoreUnknownKeys = true`,
     *   `explicitNulls = false`)
     * @return a new [JwtParserBuilder]
     */
    public fun parser(
        jsonInstance: Json = JwtJson,
    ): JwtParserBuilder = JwtParserBuilder(jsonInstance)
}
