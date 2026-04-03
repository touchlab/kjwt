package co.touchlab.kjwt.cryptography.ext

import co.touchlab.kjwt.annotations.DelicateKJWTApi
import co.touchlab.kjwt.annotations.ExperimentalKJWTApi
import co.touchlab.kjwt.cryptography.toCryptographyKotlin
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import co.touchlab.kjwt.model.jwk.Jwk
import co.touchlab.kjwt.parser.JwtParserBuilder
import dev.whyoleg.cryptography.CryptographyProvider

// ---------------------------------------------------------------------------
// verifyWith — HMAC (oct)
// ---------------------------------------------------------------------------

/**
 * Configures the parser to verify JWS signatures using an HMAC key derived from the given [Jwk.Oct] JWK.
 *
 * @param algorithm the HMAC-based signing algorithm (HS256, HS384, or HS512)
 * @param jwk the Oct JWK containing the raw symmetric key material
 * @param keyId optional key ID override; when set, the parser will only use this key if the token's
 *   `kid` header matches. Defaults to the JWK's own `kid` field.
 * @param cryptoProvider the [CryptographyProvider] used to decode the key; defaults to [CryptographyProvider.Default]
 * @return this builder for chaining
 */
@ExperimentalKJWTApi
public suspend fun JwtParserBuilder.verifyWith(
    algorithm: SigningAlgorithm.MACBased,
    jwk: Jwk.Oct,
    keyId: String? = jwk.kid,
    cryptoProvider: CryptographyProvider = CryptographyProvider.Default,
): JwtParserBuilder = verifyWith(
    algorithm,
    jwk.toHmacKey(algorithm.digest.toCryptographyKotlin(), cryptoProvider),
    keyId
)

// ---------------------------------------------------------------------------
// verifyWith — RSA PKCS1 (RS*)
// ---------------------------------------------------------------------------

/**
 * Configures the parser to verify JWS signatures using an RSA PKCS#1 public key derived from the given [Jwk.Rsa] JWK.
 *
 * @param algorithm the RSA PKCS#1-based signing algorithm (RS256, RS384, or RS512)
 * @param jwk the RSA JWK containing the public key parameters `n` and `e`
 * @param keyId optional key ID override; when set, the parser will only use this key if the token's
 *   `kid` header matches. Defaults to the JWK's own `kid` field.
 * @param cryptoProvider the [CryptographyProvider] used to decode the key; defaults to [CryptographyProvider.Default]
 * @return this builder for chaining
 */
@ExperimentalKJWTApi
public suspend fun JwtParserBuilder.verifyWith(
    algorithm: SigningAlgorithm.PKCS1Based,
    jwk: Jwk.Rsa,
    keyId: String? = jwk.kid,
    cryptoProvider: CryptographyProvider = CryptographyProvider.Default,
): JwtParserBuilder = verifyWith(
    algorithm,
    jwk.toRsaPkcs1PublicKey(algorithm.digest.toCryptographyKotlin(), cryptoProvider),
    keyId
)

// ---------------------------------------------------------------------------
// verifyWith — RSA PSS (PS*)
// ---------------------------------------------------------------------------

/**
 * Configures the parser to verify JWS signatures using an RSA PSS public key derived from the given [Jwk.Rsa] JWK.
 *
 * @param algorithm the RSA PSS-based signing algorithm (PS256, PS384, or PS512)
 * @param jwk the RSA JWK containing the public key parameters `n` and `e`
 * @param keyId optional key ID override; when set, the parser will only use this key if the token's
 *   `kid` header matches. Defaults to the JWK's own `kid` field.
 * @param cryptoProvider the [CryptographyProvider] used to decode the key; defaults to [CryptographyProvider.Default]
 * @return this builder for chaining
 */
@ExperimentalKJWTApi
public suspend fun JwtParserBuilder.verifyWith(
    algorithm: SigningAlgorithm.PSSBased,
    jwk: Jwk.Rsa,
    keyId: String? = jwk.kid,
    cryptoProvider: CryptographyProvider = CryptographyProvider.Default,
): JwtParserBuilder = verifyWith(
    algorithm,
    jwk.toRsaPssPublicKey(algorithm.digest.toCryptographyKotlin(), cryptoProvider),
    keyId
)

// ---------------------------------------------------------------------------
// verifyWith — ECDSA (ES*)
// ---------------------------------------------------------------------------

/**
 * Configures the parser to verify JWS signatures using an ECDSA public key derived from the given [Jwk.Ec] JWK.
 *
 * @param algorithm the ECDSA-based signing algorithm (ES256, ES384, or ES512)
 * @param jwk the EC JWK containing the public key parameters `crv`, `x`, and `y`
 * @param keyId optional key ID override; when set, the parser will only use this key if the token's
 *   `kid` header matches. Defaults to the JWK's own `kid` field.
 * @param cryptoProvider the [CryptographyProvider] used to decode the key; defaults to [CryptographyProvider.Default]
 * @return this builder for chaining
 */
@OptIn(DelicateKJWTApi::class)
@ExperimentalKJWTApi
public suspend fun JwtParserBuilder.verifyWith(
    algorithm: SigningAlgorithm.ECDSABased,
    jwk: Jwk.Ec,
    keyId: String? = jwk.kid,
    cryptoProvider: CryptographyProvider = CryptographyProvider.Default,
): JwtParserBuilder = verifyWith(algorithm, jwk.toEcdsaPublicKey(cryptoProvider), keyId)

// ---------------------------------------------------------------------------
// decryptWith — RSA-OAEP / RSA-OAEP-256
// ---------------------------------------------------------------------------

/**
 * Configures the parser to decrypt JWE tokens using an RSA OAEP private key derived from the given [Jwk.Rsa] JWK.
 *
 * @param algorithm the OAEP-based key encryption algorithm (RSA-OAEP or RSA-OAEP-256)
 * @param jwk the RSA JWK containing the private key parameters, including `d` and the CRT parameters
 * @param keyId optional key ID override; when set, the parser will only use this key if the token's
 *   `kid` header matches. Defaults to the JWK's own `kid` field.
 * @param cryptoProvider the [CryptographyProvider] used to decode the key; defaults to [CryptographyProvider.Default]
 * @return this builder for chaining
 */
@ExperimentalKJWTApi
public suspend fun JwtParserBuilder.decryptWith(
    algorithm: EncryptionAlgorithm.OAEPBased,
    jwk: Jwk.Rsa,
    keyId: String? = jwk.kid,
    cryptoProvider: CryptographyProvider = CryptographyProvider.Default,
): JwtParserBuilder = decryptWith(
    algorithm,
    jwk.toRsaOaepPrivateKey(algorithm.digest.toCryptographyKotlin(), cryptoProvider),
    keyId
)
