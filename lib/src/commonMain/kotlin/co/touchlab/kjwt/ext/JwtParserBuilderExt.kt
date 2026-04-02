package co.touchlab.kjwt.ext

import co.touchlab.kjwt.cryptography.SimpleKey
import co.touchlab.kjwt.cryptography.toCryptographyKotlin
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import co.touchlab.kjwt.parser.JwtParserBuilder
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.EC
import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.RSA

/**
 * Registers an HMAC verification key decoded from a String.
 *
 * @param algorithm the HMAC-based signing algorithm (HS256, HS384, or HS512).
 * @param key the HMAC key material encoded as a String.
 * @param keyFormat the format in which [key] is encoded.
 * @param keyId optional key ID to associate with this verifier; when set, only tokens whose `kid`
 *   header matches will use this key. Defaults to `null` (matches any token).
 * @param cryptoProvider the [CryptographyProvider] used to decode the key; defaults to
 *   [CryptographyProvider.Default]
 * @return this builder for chaining.
 */
public suspend fun JwtParserBuilder.verifyWith(
    algorithm: SigningAlgorithm.MACBased,
    key: String,
    keyFormat: HMAC.Key.Format,
    keyId: String? = null,
    cryptoProvider: CryptographyProvider = CryptographyProvider.Default,
): JwtParserBuilder {
    val parsedKey =
        cryptoProvider
            .get(HMAC)
            .keyDecoder(algorithm.digest.toCryptographyKotlin())
            .decodeFromByteArray(keyFormat, key.encodeToByteArray())

    return verifyWith(algorithm, parsedKey, keyId)
}

/**
 * Registers an RSA PKCS#1 public key decoded from a String for JWS signature verification.
 *
 * @param algorithm the RSA PKCS#1-based signing algorithm (RS256, RS384, or RS512).
 * @param key the RSA public key material encoded as a String.
 * @param keyFormat the format in which [key] is encoded.
 * @param keyId optional key ID to associate with this verifier; when set, only tokens whose `kid`
 *   header matches will use this key. Defaults to `null` (matches any token).
 * @param cryptoProvider the [CryptographyProvider] used to decode the key; defaults to
 *   [CryptographyProvider.Default]
 * @return this builder for chaining.
 */
public suspend fun JwtParserBuilder.verifyWith(
    algorithm: SigningAlgorithm.PKCS1Based,
    key: String,
    keyFormat: RSA.PublicKey.Format,
    keyId: String? = null,
    cryptoProvider: CryptographyProvider = CryptographyProvider.Default,
): JwtParserBuilder {
    val parsedKey =
        cryptoProvider
            .get(RSA.PKCS1)
            .publicKeyDecoder(algorithm.digest.toCryptographyKotlin())
            .decodeFromByteArray(keyFormat, key.encodeToByteArray())

    return verifyWith(algorithm, parsedKey, keyId)
}

/**
 * Registers an RSA PSS public key decoded from a String for JWS signature verification.
 *
 * @param algorithm the RSA PSS-based signing algorithm (PS256, PS384, or PS512).
 * @param key the RSA public key material encoded as a String.
 * @param keyFormat the format in which [key] is encoded.
 * @param keyId optional key ID to associate with this verifier; when set, only tokens whose `kid`
 *   header matches will use this key. Defaults to `null` (matches any token).
 * @param cryptoProvider the [CryptographyProvider] used to decode the key; defaults to
 *   [CryptographyProvider.Default]
 * @return this builder for chaining.
 */
public suspend fun JwtParserBuilder.verifyWith(
    algorithm: SigningAlgorithm.PSSBased,
    key: String,
    keyFormat: RSA.PublicKey.Format,
    keyId: String? = null,
    cryptoProvider: CryptographyProvider = CryptographyProvider.Default,
): JwtParserBuilder {
    val parsedKey =
        cryptoProvider
            .get(RSA.PSS)
            .publicKeyDecoder(algorithm.digest.toCryptographyKotlin())
            .decodeFromByteArray(keyFormat, key.encodeToByteArray())

    return verifyWith(algorithm, parsedKey, keyId)
}

/**
 * Registers an ECDSA public key decoded from a String for JWS signature verification.
 *
 * @param algorithm the ECDSA-based signing algorithm (ES256, ES384, or ES512).
 * @param key the EC public key material encoded as a String.
 * @param keyFormat the format in which [key] is encoded.
 * @param keyId optional key ID to associate with this verifier; when set, only tokens whose `kid`
 *   header matches will use this key. Defaults to `null` (matches any token).
 * @param cryptoProvider the [CryptographyProvider] used to decode the key; defaults to
 *   [CryptographyProvider.Default]
 * @return this builder for chaining.
 */
public suspend fun JwtParserBuilder.verifyWith(
    algorithm: SigningAlgorithm.ECDSABased,
    key: String,
    keyFormat: EC.PublicKey.Format,
    keyId: String? = null,
    cryptoProvider: CryptographyProvider = CryptographyProvider.Default,
): JwtParserBuilder {
    val parsedKey =
        cryptoProvider
            .get(ECDSA)
            .publicKeyDecoder(algorithm.curve.toCryptographyKotlin())
            .decodeFromByteArray(keyFormat, key.encodeToByteArray())

    return verifyWith(algorithm, parsedKey, keyId)
}

/**
 * Registers a direct key (`dir`) for JWE decryption from a raw [ByteArray].
 *
 * @param key the raw symmetric key bytes used for direct decryption.
 * @param keyAlgorithm the direct key encryption algorithm ([EncryptionAlgorithm.Dir]).
 * @param keyId optional key ID to associate with this decryptor; when set, only tokens whose `kid`
 *   header matches will use this key. Defaults to `null` (matches any token).
 * @return this builder for chaining.
 */
public fun JwtParserBuilder.decryptWith(
    key: ByteArray,
    keyAlgorithm: EncryptionAlgorithm.Dir,
    keyId: String? = null,
): JwtParserBuilder = decryptWith(keyAlgorithm, SimpleKey(key), keyId)

/**
 * Registers a direct key (`dir`) for JWE decryption from a UTF-8 String.
 *
 * The string is converted to bytes using UTF-8 encoding before being used as the symmetric key.
 *
 * @param key the symmetric key as a UTF-8 string.
 * @param keyAlgorithm the direct key encryption algorithm ([EncryptionAlgorithm.Dir]).
 * @param keyId optional key ID to associate with this decryptor; when set, only tokens whose `kid`
 *   header matches will use this key. Defaults to `null` (matches any token).
 * @return this builder for chaining.
 */
public fun JwtParserBuilder.decryptWith(
    key: String,
    keyAlgorithm: EncryptionAlgorithm.Dir,
    keyId: String? = null,
): JwtParserBuilder = decryptWith(key.encodeToByteArray(), keyAlgorithm, keyId)
