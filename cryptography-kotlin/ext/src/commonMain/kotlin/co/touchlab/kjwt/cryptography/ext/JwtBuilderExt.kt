package co.touchlab.kjwt.cryptography.ext

import co.touchlab.kjwt.annotations.DelicateKJWTApi
import co.touchlab.kjwt.annotations.ExperimentalKJWTApi
import co.touchlab.kjwt.builder.JwtBuilder
import co.touchlab.kjwt.cryptography.EncryptionKey
import co.touchlab.kjwt.cryptography.SigningKey
import co.touchlab.kjwt.cryptography.SigningKey.Identifier
import co.touchlab.kjwt.cryptography.toCryptographyKotlin
import co.touchlab.kjwt.model.JwtInstance
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.EncryptionContentAlgorithm
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import co.touchlab.kjwt.model.jwk.Jwk
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.EC
import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.RSA

/**
 * Signs the JWT using an HMAC (HS256/384/512) symmetric key.
 *
 * @param algorithm the HMAC-based signing algorithm (HS256, HS384, or HS512)
 * @param key the HMAC symmetric key to sign with
 * @param keyId optional key ID to embed in the token header's `kid` field. Defaults to `null`.
 * @return the resulting [JwtInstance.Jws] compact serialization
 */
@OptIn(DelicateKJWTApi::class)
public suspend fun JwtBuilder.signWith(
    algorithm: SigningAlgorithm.MACBased,
    key: HMAC.Key,
    keyId: String? = null,
): JwtInstance.Jws = signWith(SigningKey.SigningOnlyKey(Identifier(algorithm, keyId), key), keyId)

/**
 * Signs the JWT using an RSA PKCS#1 (RS256/384/512) private key.
 *
 * @param algorithm the RSA PKCS#1-based signing algorithm (RS256, RS384, or RS512)
 * @param key the RSA PKCS#1 private key to sign with
 * @param keyId optional key ID to embed in the token header's `kid` field. Defaults to `null`.
 * @return the resulting [JwtInstance.Jws] compact serialization
 */
@OptIn(DelicateKJWTApi::class)
public suspend fun JwtBuilder.signWith(
    algorithm: SigningAlgorithm.PKCS1Based,
    key: RSA.PKCS1.PrivateKey,
    keyId: String? = null,
): JwtInstance.Jws = signWith(SigningKey.SigningOnlyKey(Identifier(algorithm, keyId), key), keyId)

/**
 * Signs the JWT using an RSA PSS (PS256/384/512) private key.
 *
 * @param algorithm the RSA PSS-based signing algorithm (PS256, PS384, or PS512)
 * @param key the RSA PSS private key to sign with
 * @param keyId optional key ID to embed in the token header's `kid` field. Defaults to `null`.
 * @return the resulting [JwtInstance.Jws] compact serialization
 */
@OptIn(DelicateKJWTApi::class)
public suspend fun JwtBuilder.signWith(
    algorithm: SigningAlgorithm.PSSBased,
    key: RSA.PSS.PrivateKey,
    keyId: String? = null,
): JwtInstance.Jws = signWith(SigningKey.SigningOnlyKey(Identifier(algorithm, keyId), key), keyId)

/**
 * Signs the JWT using an ECDSA (ES256/384/512) private key.
 *
 * @param algorithm the ECDSA-based signing algorithm (ES256, ES384, or ES512)
 * @param key the ECDSA private key to sign with
 * @param keyId optional key ID to embed in the token header's `kid` field. Defaults to `null`.
 * @return the resulting [JwtInstance.Jws] compact serialization
 */
@OptIn(DelicateKJWTApi::class)
public suspend fun JwtBuilder.signWith(
    algorithm: SigningAlgorithm.ECDSABased,
    key: ECDSA.PrivateKey,
    keyId: String? = null,
): JwtInstance.Jws = signWith(SigningKey.SigningOnlyKey(Identifier(algorithm, keyId), key), keyId)

/**
 * Builds and returns a JWS compact serialization using a pre-built [SigningKey.SigningOnlyKey].
 *
 * @param key the signing key (or key pair) used to produce the signature
 * @param keyId optional key ID to embed in the JWT header's `kid` field. Defaults to the
 *   key ID stored in [key]'s identifier.
 * @return the resulting [JwtInstance.Jws] compact serialization
 */
public suspend fun JwtBuilder.signWith(
    key: SigningKey.SigningOnlyKey,
    keyId: String? = key.identifier.keyId,
): JwtInstance.Jws = signWith(key, keyId)

/**
 * Builds and returns a JWS compact serialization using a pre-built [SigningKey.SigningKeyPair].
 *
 * @param key the signing key (or key pair) used to produce the signature
 * @param keyId optional key ID to embed in the JWT header's `kid` field. Defaults to the
 *   key ID stored in [key]'s identifier.
 * @return the resulting [JwtInstance.Jws] compact serialization
 */
public suspend fun JwtBuilder.signWith(
    key: SigningKey.SigningKeyPair,
    keyId: String? = key.identifier.keyId,
): JwtInstance.Jws = signWith(key, keyId)

/**
 * Encrypts the JWT using a direct (`dir`) [SimpleKey] symmetric key.
 *
 * @param key the [SimpleKey] wrapping the raw symmetric content encryption key
 * @param keyAlgorithm the direct key encryption algorithm ([EncryptionAlgorithm.Dir])
 * @param contentAlgorithm the content encryption algorithm to apply to the JWT payload
 * @param keyId optional key ID to embed in the token header's `kid` field. Defaults to `null`.
 * @return the resulting [JwtInstance.Jwe] compact serialization
 */
@OptIn(DelicateKJWTApi::class)
public suspend fun JwtBuilder.encryptWith(
    key: ByteArray,
    keyAlgorithm: EncryptionAlgorithm.Dir,
    contentAlgorithm: EncryptionContentAlgorithm,
    keyId: String? = null,
): JwtInstance.Jwe = encryptWithJweProcessor(
    processor = EncryptionKey.EncryptionOnlyKey(EncryptionKey.Identifier(keyAlgorithm, keyId), key),
    contentAlgorithm = contentAlgorithm,
    keyId = keyId,
)

/**
 * Encrypts the JWT using an RSA-OAEP (RSA-OAEP / RSA-OAEP-256) public key.
 *
 * @param key the RSA OAEP public key used to wrap the content encryption key
 * @param keyAlgorithm the OAEP-based key encryption algorithm (RSA-OAEP or RSA-OAEP-256)
 * @param contentAlgorithm the content encryption algorithm to apply to the JWT payload
 * @param keyId optional key ID to embed in the token header's `kid` field. Defaults to `null`.
 * @return the resulting [JwtInstance.Jwe] compact serialization
 */
@OptIn(DelicateKJWTApi::class)
public suspend fun JwtBuilder.encryptWith(
    key: RSA.OAEP.PublicKey,
    keyAlgorithm: EncryptionAlgorithm.OAEPBased,
    contentAlgorithm: EncryptionContentAlgorithm,
    keyId: String? = null,
): JwtInstance.Jwe = encryptWithJweProcessor(
    processor = EncryptionKey.EncryptionOnlyKey(EncryptionKey.Identifier(keyAlgorithm, keyId), key),
    contentAlgorithm = contentAlgorithm,
    keyId = keyId,
)

/**
 * Builds and returns a JWE compact serialization using a pre-built [EncryptionKey.EncryptionOnlyKey].
 *
 * @param key the encryption key used to wrap the content encryption key
 * @param contentAlgorithm the content encryption algorithm used to encrypt the payload
 * @param keyId optional key ID to embed in the JWE header's `kid` field. Defaults to the
 *   key ID stored in [key]'s identifier.
 * @return the resulting [JwtInstance.Jwe] compact serialization
 */
public suspend fun JwtBuilder.encryptWith(
    key: EncryptionKey.EncryptionOnlyKey,
    contentAlgorithm: EncryptionContentAlgorithm,
    keyId: String? = key.identifier.keyId,
): JwtInstance.Jwe = encryptWithJweProcessor(key, contentAlgorithm, keyId)

/**
 * Builds and returns a JWE compact serialization using a pre-built [EncryptionKey.EncryptionKeyPair].
 *
 * @param key the encryption key used to wrap the content encryption key
 * @param contentAlgorithm the content encryption algorithm used to encrypt the payload
 * @param keyId optional key ID to embed in the JWE header's `kid` field. Defaults to the
 *   key ID stored in [key]'s identifier.
 * @return the resulting [JwtInstance.Jwe] compact serialization
 */
public suspend fun JwtBuilder.encryptWith(
    key: EncryptionKey.EncryptionKeyPair,
    contentAlgorithm: EncryptionContentAlgorithm,
    keyId: String? = key.identifier.keyId,
): JwtInstance.Jwe = encryptWithJweProcessor(key, contentAlgorithm, keyId)

// ---------------------------------------------------------------------------
// signWith — HMAC (oct)
// ---------------------------------------------------------------------------

/**
 * Signs the JWT using an HMAC key derived from the given [Jwk.Oct] symmetric JWK.
 *
 * @param algorithm the HMAC-based signing algorithm (HS256, HS384, or HS512)
 * @param jwk the Oct JWK containing the raw symmetric key material
 * @param keyId optional key ID override; when set, it is embedded in the token header's `kid` field.
 *   Defaults to the JWK's own `kid` field.
 * @param cryptoProvider the [CryptographyProvider] used to decode the key; defaults to [CryptographyProvider.Default]
 * @return the signed [JwtInstance.Jws] token
 */
@ExperimentalKJWTApi
public suspend fun JwtBuilder.signWith(
    algorithm: SigningAlgorithm.MACBased,
    jwk: Jwk.Oct,
    keyId: String? = jwk.kid,
    cryptoProvider: CryptographyProvider = CryptographyProvider.Default,
): JwtInstance.Jws = signWith(algorithm, jwk.toHmacKey(algorithm.digest.toCryptographyKotlin(), cryptoProvider), keyId)

// ---------------------------------------------------------------------------
// signWith — RSA PKCS1 (RS*)
// ---------------------------------------------------------------------------

/**
 * Signs the JWT using an RSA PKCS#1 private key derived from the given [Jwk.Rsa] JWK.
 *
 * @param algorithm the RSA PKCS#1-based signing algorithm (RS256, RS384, or RS512)
 * @param jwk the RSA JWK containing the private key parameters
 * @param keyId optional key ID override; when set, it is embedded in the token header's `kid` field.
 *   Defaults to the JWK's own `kid` field.
 * @param cryptoProvider the [CryptographyProvider] used to decode the key; defaults to [CryptographyProvider.Default]
 * @return the signed [JwtInstance.Jws] token
 */
@ExperimentalKJWTApi
public suspend fun JwtBuilder.signWith(
    algorithm: SigningAlgorithm.PKCS1Based,
    jwk: Jwk.Rsa,
    keyId: String? = jwk.kid,
    cryptoProvider: CryptographyProvider = CryptographyProvider.Default,
): JwtInstance.Jws = signWith(
    algorithm,
    jwk.toRsaPkcs1PrivateKey(algorithm.digest.toCryptographyKotlin(), cryptoProvider),
    keyId
)

// ---------------------------------------------------------------------------
// signWith — RSA PSS (PS*)
// ---------------------------------------------------------------------------

/**
 * Signs the JWT using an RSA PSS private key derived from the given [Jwk.Rsa] JWK.
 *
 * @param algorithm the RSA PSS-based signing algorithm (PS256, PS384, or PS512)
 * @param jwk the RSA JWK containing the private key parameters
 * @param keyId optional key ID override; when set, it is embedded in the token header's `kid` field.
 *   Defaults to the JWK's own `kid` field.
 * @param cryptoProvider the [CryptographyProvider] used to decode the key; defaults to [CryptographyProvider.Default]
 * @return the signed [JwtInstance.Jws] token
 */
@ExperimentalKJWTApi
public suspend fun JwtBuilder.signWith(
    algorithm: SigningAlgorithm.PSSBased,
    jwk: Jwk.Rsa,
    keyId: String? = jwk.kid,
    cryptoProvider: CryptographyProvider = CryptographyProvider.Default,
): JwtInstance.Jws = signWith(
    algorithm,
    jwk.toRsaPssPrivateKey(algorithm.digest.toCryptographyKotlin(), cryptoProvider),
    keyId
)

// ---------------------------------------------------------------------------
// signWith — ECDSA (ES*)
// ---------------------------------------------------------------------------

/**
 * Signs the JWT using an ECDSA private key derived from the given [Jwk.Ec] JWK.
 *
 * @param algorithm the ECDSA-based signing algorithm (ES256, ES384, or ES512)
 * @param jwk the EC JWK containing the private key parameter `d`
 * @param keyId optional key ID override; when set, it is embedded in the token header's `kid` field.
 *   Defaults to the JWK's own `kid` field.
 * @param cryptoProvider the [CryptographyProvider] used to decode the key; defaults to [CryptographyProvider.Default]
 * @return the signed [JwtInstance.Jws] token
 */
@ExperimentalKJWTApi
public suspend fun JwtBuilder.signWith(
    algorithm: SigningAlgorithm.ECDSABased,
    jwk: Jwk.Ec,
    keyId: String? = jwk.kid,
    cryptoProvider: CryptographyProvider = CryptographyProvider.Default,
): JwtInstance.Jws = signWith(algorithm, jwk.toEcdsaPrivateKey(cryptoProvider), keyId)

// ---------------------------------------------------------------------------
// encryptWith — RSA-OAEP / RSA-OAEP-256
// ---------------------------------------------------------------------------

/**
 * Encrypts the JWT using an RSA OAEP public key derived from the given [Jwk.Rsa] JWK.
 *
 * @param jwk the RSA JWK containing the public key parameters `n` and `e`
 * @param keyAlgorithm the OAEP-based key encryption algorithm (RSA-OAEP or RSA-OAEP-256)
 * @param contentAlgorithm the content encryption algorithm to use for the JWE payload
 * @param keyId optional key ID override; when set, it is embedded in the token header's `kid` field.
 *   Defaults to the JWK's own `kid` field.
 * @param cryptoProvider the [CryptographyProvider] used to decode the key; defaults to [CryptographyProvider.Default]
 * @return the encrypted [JwtInstance.Jwe] token
 */
@ExperimentalKJWTApi
public suspend fun JwtBuilder.encryptWith(
    jwk: Jwk.Rsa,
    keyAlgorithm: EncryptionAlgorithm.OAEPBased,
    contentAlgorithm: EncryptionContentAlgorithm,
    keyId: String? = jwk.kid,
    cryptoProvider: CryptographyProvider = CryptographyProvider.Default,
): JwtInstance.Jwe =
    encryptWith(
        jwk.toRsaOaepPublicKey(keyAlgorithm.digest.toCryptographyKotlin(), cryptoProvider),
        keyAlgorithm,
        contentAlgorithm,
        keyId
    )

/**
 * Signs the JWT using an HMAC algorithm with a key decoded from a String.
 *
 * @param algorithm the HMAC-based signing algorithm (HS256, HS384, or HS512).
 * @param key the HMAC key material encoded as a String.
 * @param keyFormat the format in which [key] is encoded.
 * @param keyId optional key ID to embed in the token header's `kid` field. Defaults to `null`.
 * @param cryptoProvider the [CryptographyProvider] used to decode the key; defaults to
 *   [CryptographyProvider.Default]
 * @return the signed [JwtInstance.Jws] token.
 */
public suspend fun JwtBuilder.signWith(
    algorithm: SigningAlgorithm.MACBased,
    key: String,
    keyFormat: HMAC.Key.Format,
    keyId: String? = null,
    cryptoProvider: CryptographyProvider = CryptographyProvider.Default,
): JwtInstance.Jws {
    val parsedKey =
        cryptoProvider
            .get(HMAC)
            .keyDecoder(algorithm.digest.toCryptographyKotlin())
            .decodeFromByteArray(keyFormat, key.encodeToByteArray())

    return signWith(algorithm, parsedKey, keyId)
}

/**
 * Signs the JWT using an RSA PKCS#1 algorithm with a private key decoded from a String.
 *
 * @param algorithm the RSA PKCS#1-based signing algorithm (RS256, RS384, or RS512).
 * @param key the RSA private key material encoded as a String.
 * @param keyFormat the format in which [key] is encoded.
 * @param keyId optional key ID to embed in the token header's `kid` field. Defaults to `null`.
 * @param cryptoProvider the [CryptographyProvider] used to decode the key; defaults to
 *   [CryptographyProvider.Default]
 * @return the signed [JwtInstance.Jws] token.
 */
public suspend fun JwtBuilder.signWith(
    algorithm: SigningAlgorithm.PKCS1Based,
    key: String,
    keyFormat: RSA.PrivateKey.Format,
    keyId: String? = null,
    cryptoProvider: CryptographyProvider = CryptographyProvider.Default,
): JwtInstance.Jws {
    val parsedKey =
        cryptoProvider
            .get(RSA.PKCS1)
            .privateKeyDecoder(algorithm.digest.toCryptographyKotlin())
            .decodeFromByteArray(keyFormat, key.encodeToByteArray())

    return signWith(algorithm, parsedKey, keyId)
}

/**
 * Signs the JWT using an RSA PSS algorithm with a private key decoded from a String.
 *
 * @param algorithm the RSA PSS-based signing algorithm (PS256, PS384, or PS512).
 * @param key the RSA private key material encoded as a String.
 * @param keyFormat the format in which [key] is encoded.
 * @param keyId optional key ID to embed in the token header's `kid` field. Defaults to `null`.
 * @param cryptoProvider the [CryptographyProvider] used to decode the key; defaults to
 *   [CryptographyProvider.Default]
 * @return the signed [JwtInstance.Jws] token.
 */
public suspend fun JwtBuilder.signWith(
    algorithm: SigningAlgorithm.PSSBased,
    key: String,
    keyFormat: RSA.PrivateKey.Format,
    keyId: String? = null,
    cryptoProvider: CryptographyProvider = CryptographyProvider.Default,
): JwtInstance.Jws {
    val parsedKey =
        cryptoProvider
            .get(RSA.PSS)
            .privateKeyDecoder(algorithm.digest.toCryptographyKotlin())
            .decodeFromByteArray(keyFormat, key.encodeToByteArray())

    return signWith(algorithm, parsedKey, keyId)
}

/**
 * Signs the JWT using an ECDSA algorithm with a private key decoded from a String.
 *
 * @param algorithm the ECDSA-based signing algorithm (ES256, ES384, or ES512).
 * @param key the EC private key material encoded as a String.
 * @param keyFormat the format in which [key] is encoded.
 * @param keyId optional key ID to embed in the token header's `kid` field. Defaults to `null`.
 * @param cryptoProvider the [CryptographyProvider] used to decode the key; defaults to
 *   [CryptographyProvider.Default]
 * @return the signed [JwtInstance.Jws] token.
 */
public suspend fun JwtBuilder.signWith(
    algorithm: SigningAlgorithm.ECDSABased,
    key: String,
    keyFormat: EC.PrivateKey.Format,
    keyId: String? = null,
    cryptoProvider: CryptographyProvider = CryptographyProvider.Default,
): JwtInstance.Jws {
    val parsedKey =
        cryptoProvider
            .get(ECDSA)
            .privateKeyDecoder(algorithm.curve.toCryptographyKotlin())
            .decodeFromByteArray(keyFormat, key.encodeToByteArray())

    return signWith(algorithm, parsedKey, keyId)
}

/**
 * Encrypts the JWT using the direct key algorithm (`dir`) with a key supplied as a UTF-8 String.
 *
 * The string is converted to bytes using UTF-8 encoding before being used as the symmetric key.
 *
 * @param key the symmetric key as a UTF-8 string.
 * @param keyAlgorithm the direct key encryption algorithm ([EncryptionAlgorithm.Dir]).
 * @param contentAlgorithm the content encryption algorithm to apply to the JWT payload.
 * @param keyId optional key ID to embed in the token header's `kid` field. Defaults to `null`.
 * @return the encrypted [JwtInstance.Jwe] token.
 */
public suspend fun JwtBuilder.encryptWith(
    key: String,
    keyAlgorithm: EncryptionAlgorithm.Dir,
    contentAlgorithm: EncryptionContentAlgorithm,
    keyId: String? = null,
): JwtInstance.Jwe = encryptWith(key.encodeToByteArray(), keyAlgorithm, contentAlgorithm, keyId)
