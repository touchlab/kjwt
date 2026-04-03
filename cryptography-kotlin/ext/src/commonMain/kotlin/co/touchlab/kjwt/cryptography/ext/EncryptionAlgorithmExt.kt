@file:OptIn(DelicateCryptographyApi::class)

package co.touchlab.kjwt.cryptography.ext

import co.touchlab.kjwt.annotations.DelicateKJWTApi
import co.touchlab.kjwt.cryptography.EncryptionKey
import co.touchlab.kjwt.cryptography.SimpleKey
import co.touchlab.kjwt.cryptography.toCryptographyKotlin
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm.Dir
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm.OAEPBased
import dev.whyoleg.cryptography.BinarySize
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.DelicateCryptographyApi
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.bigint.BigInt
import dev.whyoleg.cryptography.bigint.toBigInt
import kotlin.random.Random

internal fun EncryptionAlgorithm.identifier(keyId: String?) =
    EncryptionKey.Identifier(this, keyId)

// ---- Dir ---------------------------------------------------------------

/**
 * Wraps an existing raw key [ByteArray] as a [Dir] encryption key.
 *
 * The byte length must match the Content Encryption Algorithm's required key size
 * (e.g. 16 bytes for A128GCM, 32 bytes for A256GCM). The returned [EncryptionKey] is an
 * [EncryptionKey.EncryptionKeyPair] usable for both encryption and decryption since `dir`
 * uses the same symmetric key for both operations.
 *
 * @param key the raw symmetric key bytes to wrap.
 * @param keyId optional key ID to associate with this key. Defaults to `null`.
 * @return an [EncryptionKey] wrapping the provided key bytes.
 */
@OptIn(DelicateKJWTApi::class)
public fun Dir.key(
    key: ByteArray,
    keyId: String? = null,
): EncryptionKey.EncryptionKeyPair {
    val simpleKey = SimpleKey(key)
    return EncryptionKey.EncryptionKeyPair(identifier(keyId), simpleKey, simpleKey)
}

/**
 * Generates a new random symmetric key for use with the `dir` algorithm.
 *
 * The returned [EncryptionKey] is an [EncryptionKey.EncryptionKeyPair] usable for both
 * encryption and decryption since `dir` uses the same key for both operations.
 *
 * @param keySize the size of the key to generate in bits. Must match the Content Encryption
 *   Algorithm's required key size (e.g. 128, 192, or 256 bits). Defaults to 256 bits.
 * @param keyId optional key ID to associate with the generated key. Defaults to `null`.
 * @return an [EncryptionKey] wrapping the generated key bytes.
 */
public fun Dir.newKey(
    keySize: BinarySize = 256.bits,
    keyId: String? = null,
): EncryptionKey.EncryptionKeyPair = key(Random.nextBytes(keySize.inBytes), keyId)

// ---- OAEPBased ---------------------------------------------------------

/**
 * Generates a new RSA-OAEP key pair for use with this algorithm.
 *
 * The returned [EncryptionKey] is an [EncryptionKey.EncryptionKeyPair] containing both the
 * public and private key, usable for encryption and decryption.
 *
 * @param keyId optional key ID to associate with the generated key pair. Defaults to `null`.
 * @param keySize the RSA modulus size in bits. Defaults to 2048 bits.
 * @param publicExponent the RSA public exponent. Defaults to 65537.
 * @param cryptographyProvider the provider used to perform key generation.
 * @return an [EncryptionKey] wrapping the generated [RSA.OAEP] key pair.
 */
@OptIn(DelicateKJWTApi::class)
public suspend fun OAEPBased.newKey(
    keyId: String? = null,
    keySize: BinarySize = 2048.bits,
    publicExponent: BigInt = 65537.toBigInt(),
    cryptographyProvider: CryptographyProvider = CryptographyProvider.Default,
): EncryptionKey.EncryptionKeyPair {
    val rsaKeyPair =
        cryptographyProvider
            .get(RSA.OAEP)
            .keyPairGenerator(keySize, digest.toCryptographyKotlin(), publicExponent)
            .generateKey()

    return EncryptionKey.EncryptionKeyPair(
        identifier(keyId),
        rsaKeyPair.publicKey,
        rsaKeyPair.privateKey,
    )
}

/**
 * Decodes an RSA-OAEP public key from a [ByteArray] for use with this algorithm.
 *
 * The returned [EncryptionKey] is an [EncryptionKey.EncryptionOnlyKey] that can encrypt tokens
 * but cannot decrypt them.
 *
 * @param key the public key material to decode.
 * @param keyId optional key ID to associate with the decoded key. Defaults to `null`.
 * @param format the format in which [key] is encoded. Defaults to [RSA.PublicKey.Format.PEM].
 * @param cryptographyProvider the provider used to perform key decoding.
 * @return an [EncryptionKey] wrapping the decoded [RSA.OAEP.PublicKey].
 */
@OptIn(DelicateKJWTApi::class)
public suspend fun OAEPBased.parsePublicKey(
    key: ByteArray,
    keyId: String? = null,
    format: RSA.PublicKey.Format = RSA.PublicKey.Format.PEM,
    cryptographyProvider: CryptographyProvider = CryptographyProvider.Default,
): EncryptionKey.EncryptionOnlyKey {
    val parsedKey =
        cryptographyProvider
            .get(RSA.OAEP)
            .publicKeyDecoder(digest.toCryptographyKotlin())
            .decodeFromByteArray(format, key)

    return EncryptionKey.EncryptionOnlyKey(
        identifier(keyId),
        parsedKey,
    )
}

/**
 * Decodes an RSA-OAEP private key from a [ByteArray] for use with this algorithm.
 *
 * The returned [EncryptionKey] is an [EncryptionKey.DecryptionOnlyKey] that can decrypt tokens
 * but cannot encrypt them.
 *
 * @param key the private key material to decode.
 * @param keyId optional key ID to associate with the decoded key. Defaults to `null`.
 * @param format the format in which [key] is encoded. Defaults to [RSA.PrivateKey.Format.PEM].
 * @param cryptographyProvider the provider used to perform key decoding.
 * @return an [EncryptionKey] wrapping the decoded [RSA.OAEP.PrivateKey].
 */
@OptIn(DelicateKJWTApi::class)
public suspend fun OAEPBased.parsePrivateKey(
    key: ByteArray,
    keyId: String? = null,
    format: RSA.PrivateKey.Format = RSA.PrivateKey.Format.PEM,
    cryptographyProvider: CryptographyProvider = CryptographyProvider.Default,
): EncryptionKey.DecryptionOnlyKey {
    val parsedKey =
        cryptographyProvider
            .get(RSA.OAEP)
            .privateKeyDecoder(digest.toCryptographyKotlin())
            .decodeFromByteArray(format, key)

    return EncryptionKey.DecryptionOnlyKey(
        identifier(keyId),
        parsedKey,
    )
}

/**
 * Decodes an RSA-OAEP key pair from separate public and private key [ByteArray]s.
 *
 * The returned [EncryptionKey] is an [EncryptionKey.EncryptionKeyPair] containing both keys,
 * usable for encryption and decryption.
 *
 * @param publicKey the public key material to decode.
 * @param privateKey the private key material to decode.
 * @param keyId optional key ID to associate with the decoded key pair. Defaults to `null`.
 * @param publicKeyFormat the format in which [publicKey] is encoded. Defaults to [RSA.PublicKey.Format.PEM].
 * @param privateKeyFormat the format in which [privateKey] is encoded. Defaults to [RSA.PrivateKey.Format.PEM].
 * @param cryptographyProvider the provider used to perform key decoding.
 * @return an [EncryptionKey] wrapping the decoded [RSA.OAEP] key pair.
 */
@OptIn(DelicateKJWTApi::class)
public suspend fun OAEPBased.parseKeyPair(
    publicKey: ByteArray,
    privateKey: ByteArray,
    keyId: String? = null,
    publicKeyFormat: RSA.PublicKey.Format = RSA.PublicKey.Format.PEM,
    privateKeyFormat: RSA.PrivateKey.Format = RSA.PrivateKey.Format.PEM,
    cryptographyProvider: CryptographyProvider = CryptographyProvider.Default,
): EncryptionKey.EncryptionKeyPair {
    val parsedPublicKey =
        cryptographyProvider
            .get(RSA.OAEP)
            .publicKeyDecoder(digest.toCryptographyKotlin())
            .decodeFromByteArray(publicKeyFormat, publicKey)

    val parsedPrivateKey =
        cryptographyProvider
            .get(RSA.OAEP)
            .privateKeyDecoder(digest.toCryptographyKotlin())
            .decodeFromByteArray(privateKeyFormat, privateKey)

    return EncryptionKey.EncryptionKeyPair(
        identifier(keyId),
        parsedPublicKey,
        parsedPrivateKey,
    )
}
