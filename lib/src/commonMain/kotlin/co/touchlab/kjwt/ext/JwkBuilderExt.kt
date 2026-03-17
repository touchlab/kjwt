package co.touchlab.kjwt.ext

import co.touchlab.kjwt.builder.JwtBuilder
import co.touchlab.kjwt.model.JwtInstance
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.EncryptionContentAlgorithm
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import co.touchlab.kjwt.model.jwk.Jwk

// ---------------------------------------------------------------------------
// signWith — HMAC (oct)
// ---------------------------------------------------------------------------

/**
 * Signs the JWT using an HMAC key derived from the given [Jwk.Oct] symmetric JWK.
 *
 * @param algorithm The HMAC-based signing algorithm (HS256, HS384, or HS512).
 * @param jwk The Oct JWK containing the raw symmetric key material.
 * @return The signed [JwtInstance.Jws] token.
 */
public suspend fun JwtBuilder.signWith(algorithm: SigningAlgorithm.HashBased, jwk: Jwk.Oct): JwtInstance.Jws =
    signWith(algorithm, jwk.toHmacKey(algorithm.digest))

// ---------------------------------------------------------------------------
// signWith — RSA PKCS1 (RS*)
// ---------------------------------------------------------------------------

/**
 * Signs the JWT using an RSA PKCS#1 private key derived from the given [Jwk.Rsa] JWK.
 *
 * @param algorithm The RSA PKCS#1-based signing algorithm (RS256, RS384, or RS512).
 * @param jwk The RSA JWK containing the private key parameters.
 * @return The signed [JwtInstance.Jws] token.
 */
public suspend fun JwtBuilder.signWith(algorithm: SigningAlgorithm.PKCS1Based, jwk: Jwk.Rsa): JwtInstance.Jws =
    signWith(algorithm, jwk.toRsaPkcs1PrivateKey(algorithm.digest))

// ---------------------------------------------------------------------------
// signWith — RSA PSS (PS*)
// ---------------------------------------------------------------------------

/**
 * Signs the JWT using an RSA PSS private key derived from the given [Jwk.Rsa] JWK.
 *
 * @param algorithm The RSA PSS-based signing algorithm (PS256, PS384, or PS512).
 * @param jwk The RSA JWK containing the private key parameters.
 * @return The signed [JwtInstance.Jws] token.
 */
public suspend fun JwtBuilder.signWith(algorithm: SigningAlgorithm.PSSBased, jwk: Jwk.Rsa): JwtInstance.Jws =
    signWith(algorithm, jwk.toRsaPssPrivateKey(algorithm.digest))

// ---------------------------------------------------------------------------
// signWith — ECDSA (ES*)
// ---------------------------------------------------------------------------

/**
 * Signs the JWT using an ECDSA private key derived from the given [Jwk.Ec] JWK.
 *
 * @param algorithm The ECDSA-based signing algorithm (ES256, ES384, or ES512).
 * @param jwk The EC JWK containing the private key parameter `d`.
 * @return The signed [JwtInstance.Jws] token.
 */
public suspend fun JwtBuilder.signWith(algorithm: SigningAlgorithm.ECDSABased, jwk: Jwk.Ec): JwtInstance.Jws =
    signWith(algorithm, jwk.toEcdsaPrivateKey())

// ---------------------------------------------------------------------------
// encryptWith — RSA-OAEP / RSA-OAEP-256
// ---------------------------------------------------------------------------

/**
 * Encrypts the JWT using an RSA OAEP public key derived from the given [Jwk.Rsa] JWK.
 *
 * @param jwk The RSA JWK containing the public key parameters `n` and `e`.
 * @param keyAlgorithm The OAEP-based key encryption algorithm (RSA-OAEP or RSA-OAEP-256).
 * @param contentAlgorithm The content encryption algorithm to use for the JWE payload.
 * @return The encrypted [JwtInstance.Jwe] token.
 */
@OptIn(dev.whyoleg.cryptography.DelicateCryptographyApi::class)
public suspend fun JwtBuilder.encryptWith(
    jwk: Jwk.Rsa,
    keyAlgorithm: EncryptionAlgorithm.OAEPBased,
    contentAlgorithm: EncryptionContentAlgorithm,
): JwtInstance.Jwe =
    encryptWith(jwk.toRsaOaepPublicKey(keyAlgorithm.digest), keyAlgorithm, contentAlgorithm)
