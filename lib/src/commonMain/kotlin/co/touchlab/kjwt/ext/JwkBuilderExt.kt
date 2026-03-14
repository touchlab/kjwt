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

suspend fun JwtBuilder.signWith(algorithm: SigningAlgorithm.HashBased, jwk: Jwk.Oct): JwtInstance.Jws =
    signWith(algorithm, jwk.toHmacKey(algorithm.digest))

// ---------------------------------------------------------------------------
// signWith — RSA PKCS1 (RS*)
// ---------------------------------------------------------------------------

suspend fun JwtBuilder.signWith(algorithm: SigningAlgorithm.PKCS1Based, jwk: Jwk.Rsa): JwtInstance.Jws =
    signWith(algorithm, jwk.toRsaPkcs1PrivateKey(algorithm.digest))

// ---------------------------------------------------------------------------
// signWith — RSA PSS (PS*)
// ---------------------------------------------------------------------------

suspend fun JwtBuilder.signWith(algorithm: SigningAlgorithm.PSSBased, jwk: Jwk.Rsa): JwtInstance.Jws =
    signWith(algorithm, jwk.toRsaPssPrivateKey(algorithm.digest))

// ---------------------------------------------------------------------------
// signWith — ECDSA (ES*)
// ---------------------------------------------------------------------------

suspend fun JwtBuilder.signWith(algorithm: SigningAlgorithm.ECDSABased, jwk: Jwk.Ec): JwtInstance.Jws =
    signWith(algorithm, jwk.toEcdsaPrivateKey())

// ---------------------------------------------------------------------------
// encryptWith — RSA-OAEP / RSA-OAEP-256
// ---------------------------------------------------------------------------

@OptIn(dev.whyoleg.cryptography.DelicateCryptographyApi::class)
suspend fun JwtBuilder.encryptWith(
    jwk: Jwk.Rsa,
    keyAlgorithm: EncryptionAlgorithm.OAEPBased,
    contentAlgorithm: EncryptionContentAlgorithm,
): JwtInstance.Jwe =
    encryptWith(jwk.toRsaOaepPublicKey(keyAlgorithm.digest), keyAlgorithm, contentAlgorithm)
