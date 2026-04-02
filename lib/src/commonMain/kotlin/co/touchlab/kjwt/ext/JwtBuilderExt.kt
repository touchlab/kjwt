package co.touchlab.kjwt.ext

import co.touchlab.kjwt.builder.JwtBuilder
import co.touchlab.kjwt.cryptography.SimpleKey
import co.touchlab.kjwt.cryptography.toCryptographyKotlin
import co.touchlab.kjwt.model.JwtInstance
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.EncryptionContentAlgorithm
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.EC
import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.RSA

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
 * Encrypts the JWT using the direct key algorithm (`dir`) with a raw key supplied as a [ByteArray].
 *
 * @param key the raw symmetric key bytes used for direct encryption.
 * @param keyAlgorithm the direct key encryption algorithm ([EncryptionAlgorithm.Dir]).
 * @param contentAlgorithm the content encryption algorithm to apply to the JWT payload.
 * @param keyId optional key ID to embed in the token header's `kid` field. Defaults to `null`.
 * @return the encrypted [JwtInstance.Jwe] token.
 */
public suspend fun JwtBuilder.encryptWith(
    key: ByteArray,
    keyAlgorithm: EncryptionAlgorithm.Dir,
    contentAlgorithm: EncryptionContentAlgorithm,
    keyId: String? = null,
): JwtInstance.Jwe = encryptWith(SimpleKey(key), keyAlgorithm, contentAlgorithm, keyId)

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
