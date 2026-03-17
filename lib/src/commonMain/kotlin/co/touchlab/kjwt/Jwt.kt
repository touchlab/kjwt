package co.touchlab.kjwt

import co.touchlab.kjwt.builder.JwtBuilder
import co.touchlab.kjwt.parser.JwtParserBuilder

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
    public fun builder(): JwtBuilder = JwtBuilder()
    public fun parser(): JwtParserBuilder = JwtParserBuilder()
}
