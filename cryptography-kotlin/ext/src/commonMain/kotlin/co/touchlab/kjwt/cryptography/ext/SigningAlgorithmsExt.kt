package co.touchlab.kjwt.cryptography.ext

import co.touchlab.kjwt.annotations.DelicateKJWTApi
import co.touchlab.kjwt.cryptography.SigningKey
import co.touchlab.kjwt.cryptography.toCryptographyKotlin
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm.ECDSABased
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm.MACBased
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm.PKCS1Based
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm.PSSBased
import dev.whyoleg.cryptography.BinarySize
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.EC
import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.bigint.BigInt
import dev.whyoleg.cryptography.bigint.toBigInt

internal fun SigningAlgorithm.identifier(keyId: String?) =
    SigningKey.Identifier(this, keyId)

/**
 * Generates a new random HMAC key for use with this algorithm.
 *
 * The returned [SigningKey] is a [SigningKey.SigningKeyPair] usable for both signing and
 * verification since HMAC uses a single symmetric key.
 *
 * @param keyId optional key ID to associate with the generated key. Defaults to `null`.
 * @param cryptographyProvider the provider used to perform key generation.
 * @return a [SigningKey] wrapping the generated [HMAC.Key].
 */
@OptIn(DelicateKJWTApi::class)
public suspend fun MACBased.newKey(
    keyId: String? = null,
    cryptographyProvider: CryptographyProvider = CryptographyProvider.Default,
): SigningKey.SigningKeyPair {
    val macKey =
        cryptographyProvider
            .get(HMAC)
            .keyGenerator(digest.toCryptographyKotlin())
            .generateKey()

    return SigningKey.SigningKeyPair(identifier(keyId), macKey, macKey)
}

/**
 * Decodes an existing HMAC key from a [ByteArray] for use with this algorithm.
 *
 * The returned [SigningKey] is a [SigningKey.SigningKeyPair] usable for both signing and
 * verification since HMAC uses a single symmetric key.
 *
 * @param key the raw key material to decode.
 * @param keyId optional key ID to associate with the decoded key. Defaults to `null`.
 * @param format the format in which [key] is encoded. Defaults to [HMAC.Key.Format.RAW].
 * @param cryptographyProvider the provider used to perform key decoding.
 * @return a [SigningKey] wrapping the decoded [HMAC.Key].
 */
@OptIn(DelicateKJWTApi::class)
public suspend fun MACBased.parse(
    key: ByteArray,
    keyId: String? = null,
    format: HMAC.Key.Format = HMAC.Key.Format.RAW,
    cryptographyProvider: CryptographyProvider = CryptographyProvider.Default,
): SigningKey.SigningKeyPair {
    val macKey =
        cryptographyProvider
            .get(HMAC)
            .keyDecoder(digest.toCryptographyKotlin())
            .decodeFromByteArray(format, key)

    return SigningKey.SigningKeyPair(identifier(keyId), macKey, macKey)
}

/**
 * Generates a new RSA PKCS#1 v1.5 key pair for use with this algorithm.
 *
 * The returned [SigningKey] is a [SigningKey.SigningKeyPair] containing both the public and
 * private key, usable for signing and verification.
 *
 * @param keyId optional key ID to associate with the generated key pair. Defaults to `null`.
 * @param keySize the RSA modulus size in bits. Defaults to 4096 bits.
 * @param publicExponent the RSA public exponent. Defaults to 65537.
 * @param cryptographyProvider the provider used to perform key generation.
 * @return a [SigningKey] wrapping the generated [RSA.PKCS1] key pair.
 */
@OptIn(DelicateKJWTApi::class)
public suspend fun PKCS1Based.newKey(
    keyId: String? = null,
    keySize: BinarySize = 4096.bits,
    publicExponent: BigInt = 65537.toBigInt(),
    cryptographyProvider: CryptographyProvider = CryptographyProvider.Default,
): SigningKey.SigningKeyPair {
    val rsaKeyPair =
        cryptographyProvider
            .get(RSA.PKCS1)
            .keyPairGenerator(keySize, digest.toCryptographyKotlin(), publicExponent)
            .generateKey()

    return SigningKey.SigningKeyPair(
        identifier(keyId),
        rsaKeyPair.publicKey,
        rsaKeyPair.privateKey,
    )
}

/**
 * Decodes an RSA PKCS#1 v1.5 public key from a [ByteArray] for use with this algorithm.
 *
 * The returned [SigningKey] is a [SigningKey.VerifyOnlyKey] that can verify signatures but
 * cannot produce them.
 *
 * @param key the public key material to decode.
 * @param keyId optional key ID to associate with the decoded key. Defaults to `null`.
 * @param format the format in which [key] is encoded. Defaults to [RSA.PublicKey.Format.PEM].
 * @param cryptographyProvider the provider used to perform key decoding.
 * @return a [SigningKey] wrapping the decoded [RSA.PKCS1.PublicKey].
 */
@OptIn(DelicateKJWTApi::class)
public suspend fun PKCS1Based.parsePublicKey(
    key: ByteArray,
    keyId: String? = null,
    format: RSA.PublicKey.Format = RSA.PublicKey.Format.PEM,
    cryptographyProvider: CryptographyProvider = CryptographyProvider.Default,
): SigningKey.VerifyOnlyKey {
    val parsedKey =
        cryptographyProvider
            .get(RSA.PKCS1)
            .publicKeyDecoder(digest.toCryptographyKotlin())
            .decodeFromByteArray(format, key)

    return SigningKey.VerifyOnlyKey(
        identifier(keyId),
        parsedKey,
    )
}

/**
 * Decodes an RSA PKCS#1 v1.5 private key from a [ByteArray] for use with this algorithm.
 *
 * The returned [SigningKey] is a [SigningKey.SigningOnlyKey] that can produce signatures but
 * cannot verify them.
 *
 * @param key the private key material to decode.
 * @param keyId optional key ID to associate with the decoded key. Defaults to `null`.
 * @param format the format in which [key] is encoded. Defaults to [RSA.PrivateKey.Format.PEM].
 * @param cryptographyProvider the provider used to perform key decoding.
 * @return a [SigningKey] wrapping the decoded [RSA.PKCS1.PrivateKey].
 */
@OptIn(DelicateKJWTApi::class)
public suspend fun PKCS1Based.parsePrivateKey(
    key: ByteArray,
    keyId: String? = null,
    format: RSA.PrivateKey.Format = RSA.PrivateKey.Format.PEM,
    cryptographyProvider: CryptographyProvider = CryptographyProvider.Default,
): SigningKey.SigningOnlyKey {
    val parsedKey =
        cryptographyProvider
            .get(RSA.PKCS1)
            .privateKeyDecoder(digest.toCryptographyKotlin())
            .decodeFromByteArray(format, key)

    return SigningKey.SigningOnlyKey(
        identifier(keyId),
        parsedKey,
    )
}

/**
 * Decodes an RSA PKCS#1 v1.5 key pair from separate public and private key [ByteArray]s.
 *
 * The returned [SigningKey] is a [SigningKey.SigningKeyPair] containing both keys, usable for
 * signing and verification.
 *
 * @param publicKey the public key material to decode.
 * @param privateKey the private key material to decode.
 * @param keyId optional key ID to associate with the decoded key pair. Defaults to `null`.
 * @param publicKeyFormat the format in which [publicKey] is encoded. Defaults to [RSA.PublicKey.Format.PEM].
 * @param privateKeyFormat the format in which [privateKey] is encoded. Defaults to [RSA.PrivateKey.Format.PEM].
 * @param cryptographyProvider the provider used to perform key decoding.
 * @return a [SigningKey] wrapping the decoded [RSA.PKCS1] key pair.
 */
@OptIn(DelicateKJWTApi::class)
public suspend fun PKCS1Based.parseKeyPair(
    publicKey: ByteArray,
    privateKey: ByteArray,
    keyId: String? = null,
    publicKeyFormat: RSA.PublicKey.Format = RSA.PublicKey.Format.PEM,
    privateKeyFormat: RSA.PrivateKey.Format = RSA.PrivateKey.Format.PEM,
    cryptographyProvider: CryptographyProvider = CryptographyProvider.Default,
): SigningKey.SigningKeyPair {
    val parsedPublicKey =
        cryptographyProvider
            .get(RSA.PKCS1)
            .publicKeyDecoder(digest.toCryptographyKotlin())
            .decodeFromByteArray(publicKeyFormat, publicKey)

    val parsedPrivateKey =
        cryptographyProvider
            .get(RSA.PKCS1)
            .privateKeyDecoder(digest.toCryptographyKotlin())
            .decodeFromByteArray(privateKeyFormat, privateKey)

    return SigningKey.SigningKeyPair(
        identifier(keyId),
        parsedPublicKey,
        parsedPrivateKey,
    )
}

/**
 * Generates a new RSA PSS key pair for use with this algorithm.
 *
 * The returned [SigningKey] is a [SigningKey.SigningKeyPair] containing both the public and
 * private key, usable for signing and verification.
 *
 * @param keyId optional key ID to associate with the generated key pair. Defaults to `null`.
 * @param keySize the RSA modulus size in bits. Defaults to 4096 bits.
 * @param publicExponent the RSA public exponent. Defaults to 65537.
 * @param cryptographyProvider the provider used to perform key generation.
 * @return a [SigningKey] wrapping the generated [RSA.PSS] key pair.
 */
@OptIn(DelicateKJWTApi::class)
public suspend fun PSSBased.newKey(
    keyId: String? = null,
    keySize: BinarySize = 4096.bits,
    publicExponent: BigInt = 65537.toBigInt(),
    cryptographyProvider: CryptographyProvider = CryptographyProvider.Default,
): SigningKey.SigningKeyPair {
    val rsaKeyPair =
        cryptographyProvider
            .get(RSA.PSS)
            .keyPairGenerator(keySize, digest.toCryptographyKotlin(), publicExponent)
            .generateKey()

    return SigningKey.SigningKeyPair(
        identifier(keyId),
        rsaKeyPair.publicKey,
        rsaKeyPair.privateKey,
    )
}

/**
 * Decodes an RSA PSS public key from a [ByteArray] for use with this algorithm.
 *
 * The returned [SigningKey] is a [SigningKey.VerifyOnlyKey] that can verify signatures but
 * cannot produce them.
 *
 * @param key the public key material to decode.
 * @param keyId optional key ID to associate with the decoded key. Defaults to `null`.
 * @param format the format in which [key] is encoded. Defaults to [RSA.PublicKey.Format.PEM].
 * @param cryptographyProvider the provider used to perform key decoding.
 * @return a [SigningKey] wrapping the decoded [RSA.PSS.PublicKey].
 */
@OptIn(DelicateKJWTApi::class)
public suspend fun PSSBased.parsePublicKey(
    key: ByteArray,
    keyId: String? = null,
    format: RSA.PublicKey.Format = RSA.PublicKey.Format.PEM,
    cryptographyProvider: CryptographyProvider = CryptographyProvider.Default,
): SigningKey.VerifyOnlyKey {
    val parsedKey =
        cryptographyProvider
            .get(RSA.PSS)
            .publicKeyDecoder(digest.toCryptographyKotlin())
            .decodeFromByteArray(format, key)

    return SigningKey.VerifyOnlyKey(
        identifier(keyId),
        parsedKey,
    )
}

/**
 * Decodes an RSA PSS private key from a [ByteArray] for use with this algorithm.
 *
 * The returned [SigningKey] is a [SigningKey.SigningOnlyKey] that can produce signatures but
 * cannot verify them.
 *
 * @param key the private key material to decode.
 * @param keyId optional key ID to associate with the decoded key. Defaults to `null`.
 * @param format the format in which [key] is encoded. Defaults to [RSA.PrivateKey.Format.PEM].
 * @param cryptographyProvider the provider used to perform key decoding.
 * @return a [SigningKey] wrapping the decoded [RSA.PSS.PrivateKey].
 */
@OptIn(DelicateKJWTApi::class)
public suspend fun PSSBased.parsePrivateKey(
    key: ByteArray,
    keyId: String? = null,
    format: RSA.PrivateKey.Format = RSA.PrivateKey.Format.PEM,
    cryptographyProvider: CryptographyProvider = CryptographyProvider.Default,
): SigningKey.SigningOnlyKey {
    val parsedKey =
        cryptographyProvider
            .get(RSA.PSS)
            .privateKeyDecoder(digest.toCryptographyKotlin())
            .decodeFromByteArray(format, key)

    return SigningKey.SigningOnlyKey(
        identifier(keyId),
        parsedKey,
    )
}

/**
 * Decodes an RSA PSS key pair from separate public and private key [ByteArray]s.
 *
 * The returned [SigningKey] is a [SigningKey.SigningKeyPair] containing both keys, usable for
 * signing and verification.
 *
 * @param publicKey the public key material to decode.
 * @param privateKey the private key material to decode.
 * @param keyId optional key ID to associate with the decoded key pair. Defaults to `null`.
 * @param publicKeyFormat the format in which [publicKey] is encoded. Defaults to [RSA.PublicKey.Format.PEM].
 * @param privateKeyFormat the format in which [privateKey] is encoded. Defaults to [RSA.PrivateKey.Format.PEM].
 * @param cryptographyProvider the provider used to perform key decoding.
 * @return a [SigningKey] wrapping the decoded [RSA.PSS] key pair.
 */
@OptIn(DelicateKJWTApi::class)
public suspend fun PSSBased.parseKeyPair(
    publicKey: ByteArray,
    privateKey: ByteArray,
    keyId: String? = null,
    publicKeyFormat: RSA.PublicKey.Format = RSA.PublicKey.Format.PEM,
    privateKeyFormat: RSA.PrivateKey.Format = RSA.PrivateKey.Format.PEM,
    cryptographyProvider: CryptographyProvider = CryptographyProvider.Default,
): SigningKey.SigningKeyPair {
    val parsedPublicKey =
        cryptographyProvider
            .get(RSA.PSS)
            .publicKeyDecoder(digest.toCryptographyKotlin())
            .decodeFromByteArray(publicKeyFormat, publicKey)

    val parsedPrivateKey =
        cryptographyProvider
            .get(RSA.PSS)
            .privateKeyDecoder(digest.toCryptographyKotlin())
            .decodeFromByteArray(privateKeyFormat, privateKey)

    return SigningKey.SigningKeyPair(
        identifier(keyId),
        parsedPublicKey,
        parsedPrivateKey,
    )
}

/**
 * Generates a new ECDSA key pair for use with this algorithm.
 *
 * The returned [SigningKey] is a [SigningKey.SigningKeyPair] containing both the public and
 * private key, usable for signing and verification.
 *
 * @param keyId optional key ID to associate with the generated key pair. Defaults to `null`.
 * @param cryptographyProvider the provider used to perform key generation.
 * @return a [SigningKey] wrapping the generated [ECDSA] key pair.
 */
@OptIn(DelicateKJWTApi::class)
public suspend fun ECDSABased.newKey(
    keyId: String? = null,
    cryptographyProvider: CryptographyProvider = CryptographyProvider.Default,
): SigningKey.SigningKeyPair {
    val rsaKeyPair =
        cryptographyProvider
            .get(ECDSA)
            .keyPairGenerator(curve.toCryptographyKotlin())
            .generateKey()

    return SigningKey.SigningKeyPair(
        identifier(keyId),
        rsaKeyPair.publicKey,
        rsaKeyPair.privateKey,
    )
}

/**
 * Decodes an ECDSA public key from a [ByteArray] for use with this algorithm.
 *
 * The returned [SigningKey] is a [SigningKey.VerifyOnlyKey] that can verify signatures but
 * cannot produce them.
 *
 * @param key the public key material to decode.
 * @param keyId optional key ID to associate with the decoded key. Defaults to `null`.
 * @param format the format in which [key] is encoded. Defaults to [EC.PublicKey.Format.RAW].
 * @param cryptographyProvider the provider used to perform key decoding.
 * @return a [SigningKey] wrapping the decoded [ECDSA.PublicKey].
 */
@OptIn(DelicateKJWTApi::class)
public suspend fun ECDSABased.parsePublicKey(
    key: ByteArray,
    keyId: String? = null,
    format: EC.PublicKey.Format = EC.PublicKey.Format.RAW,
    cryptographyProvider: CryptographyProvider = CryptographyProvider.Default,
): SigningKey.VerifyOnlyKey {
    val parsedKey =
        cryptographyProvider
            .get(ECDSA)
            .publicKeyDecoder(curve.toCryptographyKotlin())
            .decodeFromByteArray(format, key)

    return SigningKey.VerifyOnlyKey(
        identifier(keyId),
        parsedKey,
    )
}

/**
 * Decodes an ECDSA private key from a [ByteArray] for use with this algorithm.
 *
 * The returned [SigningKey] is a [SigningKey.SigningOnlyKey] that can produce signatures but
 * cannot verify them.
 *
 * @param key the private key material to decode.
 * @param keyId optional key ID to associate with the decoded key. Defaults to `null`.
 * @param format the format in which [key] is encoded. Defaults to [EC.PrivateKey.Format.RAW].
 * @param cryptographyProvider the provider used to perform key decoding.
 * @return a [SigningKey] wrapping the decoded [ECDSA.PrivateKey].
 */
@OptIn(DelicateKJWTApi::class)
public suspend fun ECDSABased.parsePrivateKey(
    key: ByteArray,
    keyId: String? = null,
    format: EC.PrivateKey.Format = EC.PrivateKey.Format.RAW,
    cryptographyProvider: CryptographyProvider = CryptographyProvider.Default,
): SigningKey.SigningOnlyKey {
    val parsedKey =
        cryptographyProvider
            .get(ECDSA)
            .privateKeyDecoder(curve.toCryptographyKotlin())
            .decodeFromByteArray(format, key)

    return SigningKey.SigningOnlyKey(
        identifier(keyId),
        parsedKey,
    )
}

/**
 * Decodes an ECDSA key pair from separate public and private key [ByteArray]s.
 *
 * The returned [SigningKey] is a [SigningKey.SigningKeyPair] containing both keys, usable for
 * signing and verification.
 *
 * @param publicKey the public key material to decode.
 * @param privateKey the private key material to decode.
 * @param keyId optional key ID to associate with the decoded key pair. Defaults to `null`.
 * @param publicKeyFormat the format in which [publicKey] is encoded. Defaults to [EC.PublicKey.Format.RAW].
 * @param privateKeyFormat the format in which [privateKey] is encoded. Defaults to [EC.PrivateKey.Format.RAW].
 * @param cryptographyProvider the provider used to perform key decoding.
 * @return a [SigningKey] wrapping the decoded [ECDSA] key pair.
 */
@OptIn(DelicateKJWTApi::class)
public suspend fun ECDSABased.parseKeyPair(
    publicKey: ByteArray,
    privateKey: ByteArray,
    keyId: String? = null,
    publicKeyFormat: EC.PublicKey.Format = EC.PublicKey.Format.RAW,
    privateKeyFormat: EC.PrivateKey.Format = EC.PrivateKey.Format.RAW,
    cryptographyProvider: CryptographyProvider = CryptographyProvider.Default,
): SigningKey.SigningKeyPair {
    val parsedPublicKey =
        cryptographyProvider
            .get(ECDSA)
            .publicKeyDecoder(curve.toCryptographyKotlin())
            .decodeFromByteArray(publicKeyFormat, publicKey)

    val parsedPrivateKey =
        cryptographyProvider
            .get(ECDSA)
            .privateKeyDecoder(curve.toCryptographyKotlin())
            .decodeFromByteArray(privateKeyFormat, privateKey)

    return SigningKey.SigningKeyPair(
        identifier(keyId),
        parsedPublicKey,
        parsedPrivateKey,
    )
}
