package co.touchlab.kjwt.cryptography.ext

import co.touchlab.kjwt.annotations.DelicateKJWTApi
import co.touchlab.kjwt.cryptography.EncryptionKey
import co.touchlab.kjwt.cryptography.SigningKey
import co.touchlab.kjwt.cryptography.toCryptographyKotlin
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm.ECDSABased
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm.MACBased
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm.PKCS1Based
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm.PSSBased
import co.touchlab.kjwt.parser.JwtParserBuilder
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.EC
import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.RSA

/**
 * Registers an HMAC (HS256/384/512) symmetric key for JWS signature verification.
 *
 * @param algorithm the HMAC-based signing algorithm (HS256, HS384, or HS512)
 * @param key the HMAC symmetric key to verify signatures with
 * @param keyId optional key ID to associate with this verifier; when set, only tokens whose `kid`
 *   header matches will use this key. Defaults to `null` (matches any token).
 * @return this builder for chaining
 */
@OptIn(DelicateKJWTApi::class)
public fun JwtParserBuilder.verifyWith(
    algorithm: MACBased,
    key: HMAC.Key,
    keyId: String? = null,
): JwtParserBuilder = verifyWith(algorithm as SigningAlgorithm, key, keyId)

/**
 * Registers an RSA PKCS#1 (RS256/384/512) public key for JWS signature verification.
 *
 * @param algorithm the RSA PKCS#1-based signing algorithm (RS256, RS384, or RS512)
 * @param key the RSA PKCS#1 public key to verify signatures with
 * @param keyId optional key ID to associate with this verifier; when set, only tokens whose `kid`
 *   header matches will use this key. Defaults to `null` (matches any token).
 * @return this builder for chaining
 */
@OptIn(DelicateKJWTApi::class)
public fun JwtParserBuilder.verifyWith(
    algorithm: PKCS1Based,
    key: RSA.PKCS1.PublicKey,
    keyId: String? = null,
): JwtParserBuilder = verifyWith(algorithm as SigningAlgorithm, key, keyId)

/**
 * Registers an RSA PSS (PS256/384/512) public key for JWS signature verification.
 *
 * @param algorithm the RSA PSS-based signing algorithm (PS256, PS384, or PS512)
 * @param key the RSA PSS public key to verify signatures with
 * @param keyId optional key ID to associate with this verifier; when set, only tokens whose `kid`
 *   header matches will use this key. Defaults to `null` (matches any token).
 * @return this builder for chaining
 */
@OptIn(DelicateKJWTApi::class)
public fun JwtParserBuilder.verifyWith(
    algorithm: PSSBased,
    key: RSA.PSS.PublicKey,
    keyId: String? = null,
): JwtParserBuilder = verifyWith(algorithm as SigningAlgorithm, key, keyId)

/**
 * Registers an ECDSA (ES256/384/512) public key for JWS signature verification.
 *
 * @param algorithm the ECDSA-based signing algorithm (ES256, ES384, or ES512)
 * @param key the ECDSA public key to verify signatures with
 * @param keyId optional key ID to associate with this verifier; when set, only tokens whose `kid`
 *   header matches will use this key. Defaults to `null` (matches any token).
 * @return this builder for chaining
 */
@OptIn(DelicateKJWTApi::class)
public fun JwtParserBuilder.verifyWith(
    algorithm: ECDSABased,
    key: ECDSA.PublicKey,
    keyId: String? = null,
): JwtParserBuilder = verifyWith(algorithm as SigningAlgorithm, key, keyId)

/**
 * Registers a raw [Key] for JWS signature verification using any [SigningAlgorithm].
 *
 * Prefer the strongly typed overloads (e.g. [verifyWith] accepting [HMAC.Key] or
 * [RSA.PKCS1.PublicKey]) when possible, as they enforce the correct key type at compile time.
 *
 * @param algorithm the JWS signing algorithm this key is associated with
 * @param key the raw cryptography-kotlin key to verify signatures with; must be compatible with [algorithm]
 * @param keyId optional key ID to associate with this verifier; when set, only tokens whose `kid`
 *   header matches will use this key. Defaults to `null` (matches any token).
 * @return this builder for chaining
 */
@DelicateKJWTApi
internal fun JwtParserBuilder.verifyWith(
    algorithm: SigningAlgorithm,
    key: Any,
    keyId: String? = null
): JwtParserBuilder =
    verifyWith(
        SigningKey.VerifyOnlyKey(
            identifier = SigningKey.Identifier(algorithm, keyId),
            publicKey = key,
        ),
    )

/**
 * Registers a pre-built [SigningKey.VerifyOnlyKey] for JWS signature verification.
 *
 * The algorithm and `kid` are taken from [key]'s [SigningKey.Identifier].
 *
 * @param key the verify-only signing key to register
 * @return this builder for chaining
 */
@OptIn(DelicateKJWTApi::class)
public fun JwtParserBuilder.verifyWith(
    key: SigningKey.VerifyOnlyKey,
): JwtParserBuilder = registerSigningKey(key)

/**
 * Registers a pre-built [SigningKey.SigningKeyPair] for JWS signature verification.
 *
 * The algorithm and `kid` are taken from [key]'s [SigningKey.Identifier]. Both the public and
 * private key material are stored, but only the public key is used for verification.
 *
 * @param key the signing key pair to register
 * @return this builder for chaining
 */
@OptIn(DelicateKJWTApi::class)
public fun JwtParserBuilder.verifyWith(
    key: SigningKey.SigningKeyPair,
): JwtParserBuilder = registerSigningKey(key)

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
    algorithm: MACBased,
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
    algorithm: PKCS1Based,
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
    algorithm: PSSBased,
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
@OptIn(DelicateKJWTApi::class)
public suspend fun JwtParserBuilder.verifyWith(
    algorithm: ECDSABased,
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
 * Registers any [SigningKey] variant for JWS signature verification, merging it with any
 * previously registered processor for the same algorithm and key ID.
 *
 * @param key the signing key to register
 * @return this builder for chaining
 * @throws IllegalArgumentException if a key of the same type is already registered for the same
 *   algorithm and key ID
 */
@DelicateKJWTApi
public fun JwtParserBuilder.registerSigningKey(key: SigningKey): JwtParserBuilder =
    apply { processorRegistry.registerJwsProcessor(key) }

/**
 * Registers an RSA-OAEP (RSA-OAEP / RSA-OAEP-256) private key for JWE decryption.
 *
 * @param algorithm the OAEP-based key encryption algorithm (RSA-OAEP or RSA-OAEP-256)
 * @param privateKey the RSA OAEP private key used to unwrap the content encryption key
 * @param keyId optional key ID to associate with this decryptor; when set, only tokens whose `kid`
 *   header matches will use this key. Defaults to `null` (matches any token).
 * @return this builder for chaining
 */
@OptIn(DelicateKJWTApi::class)
public fun JwtParserBuilder.decryptWith(
    algorithm: EncryptionAlgorithm.OAEPBased,
    privateKey: RSA.OAEP.PrivateKey,
    keyId: String? = null,
): JwtParserBuilder = decryptWith(algorithm as EncryptionAlgorithm, privateKey, keyId)

/**
 * Registers a raw [Key] for JWE token decryption using any [EncryptionAlgorithm].
 *
 * Prefer the strongly typed overloads (e.g. [decryptWith] accepting [RSA.OAEP.PrivateKey] or
 * [SimpleKey]) when possible, as they enforce the correct key type at compile time.
 *
 * @param algorithm the JWE key-encryption algorithm this key is associated with
 * @param privateKey the raw cryptography-kotlin key to decrypt tokens with; must be compatible with [algorithm]
 * @param keyId optional key ID to associate with this decryptor; when set, only tokens whose `kid`
 *   header matches will use this key. Defaults to `null` (matches any token).
 * @return this builder for chaining
 */
@DelicateKJWTApi
internal fun JwtParserBuilder.decryptWith(
    algorithm: EncryptionAlgorithm,
    privateKey: Any,
    keyId: String? = null,
): JwtParserBuilder =
    decryptWith(
        EncryptionKey.DecryptionOnlyKey(
            identifier = EncryptionKey.Identifier(algorithm, keyId),
            privateKey = privateKey,
        ),
    )

/**
 * Registers a pre-built [EncryptionKey.DecryptionOnlyKey] for JWE token decryption.
 *
 * The algorithm and `kid` are taken from [key]'s [EncryptionKey.Identifier].
 *
 * @param key the decryption-only encryption key to register
 * @return this builder for chaining
 */
@OptIn(DelicateKJWTApi::class)
public fun JwtParserBuilder.decryptWith(
    key: EncryptionKey.DecryptionOnlyKey,
): JwtParserBuilder = registerEncryptionKey(key)

/**
 * Registers a pre-built [EncryptionKey.EncryptionKeyPair] for JWE token decryption.
 *
 * The algorithm and `kid` are taken from [key]'s [EncryptionKey.Identifier]. Both the public
 * and private key material are stored, but only the private key is used for decryption.
 *
 * @param key the encryption key pair to register
 * @return this builder for chaining
 */
@OptIn(DelicateKJWTApi::class)
public fun JwtParserBuilder.decryptWith(
    key: EncryptionKey.EncryptionKeyPair,
): JwtParserBuilder = registerEncryptionKey(key)

/**
 * Registers any [EncryptionKey] variant for JWE token decryption, merging it with any
 * previously registered processor for the same algorithm and key ID.
 *
 * @param key the encryption key to register
 * @return this builder for chaining
 * @throws IllegalArgumentException if a key of the same type is already registered for the same
 *   algorithm and key ID
 */
@DelicateKJWTApi
public fun JwtParserBuilder.registerEncryptionKey(key: EncryptionKey): JwtParserBuilder =
    apply { processorRegistry.registerJweProcessor(key) }

/**
 * Registers a direct key (`dir`) for JWE decryption from a raw [ByteArray].
 *
 * @param key the raw symmetric key bytes used for direct decryption.
 * @param keyAlgorithm the direct key encryption algorithm ([EncryptionAlgorithm.Dir]).
 * @param keyId optional key ID to associate with this decryptor; when set, only tokens whose `kid`
 *   header matches will use this key. Defaults to `null` (matches any token).
 * @return this builder for chaining.
 */
@OptIn(DelicateKJWTApi::class)
public fun JwtParserBuilder.decryptWith(
    key: ByteArray,
    keyAlgorithm: EncryptionAlgorithm.Dir,
    keyId: String? = null,
): JwtParserBuilder = decryptWith(keyAlgorithm, key, keyId)

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
