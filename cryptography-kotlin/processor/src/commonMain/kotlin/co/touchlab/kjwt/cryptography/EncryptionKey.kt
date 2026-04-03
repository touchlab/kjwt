@file:OptIn(DelicateCryptographyApi::class)

package co.touchlab.kjwt.cryptography

import co.touchlab.kjwt.annotations.DelicateKJWTApi
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.EncryptionContentAlgorithm
import co.touchlab.kjwt.model.algorithm.JweEncryptResult
import co.touchlab.kjwt.processor.BaseJweProcessor
import co.touchlab.kjwt.processor.JweDecryptor
import co.touchlab.kjwt.processor.JweEncryptor
import co.touchlab.kjwt.processor.JweProcessor
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.DelicateCryptographyApi
import dev.whyoleg.cryptography.algorithms.AES
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.algorithms.SHA384
import dev.whyoleg.cryptography.algorithms.SHA512
import dev.whyoleg.cryptography.materials.key.Key
import kotlin.random.Random

/**
 * Represents a cryptographic key (or key pair) used for JWE encryption and/or decryption.
 *
 * Instances are identified by a ([EncryptionAlgorithm], optional key ID) pair captured in
 * [identifier]. Depending on which key material is available, an [EncryptionKey] may be:
 * - [EncryptionOnlyKey] — holds only the public key; used by [co.touchlab.kjwt.builder.JwtBuilder]
 *   to encrypt tokens.
 * - [DecryptionOnlyKey] — holds only the private key; used by [co.touchlab.kjwt.parser.JwtParser]
 *   to decrypt tokens.
 * - [EncryptionKeyPair] — holds both keys; supports both encryption and decryption.
 *
 * Complementary keys that share the same [Identifier] can be merged into an [EncryptionKeyPair]
 * via [mergeWith]. This happens automatically when both are registered with the same
 * [co.touchlab.kjwt.model.registry.DefaultJwtProcessorRegistry].
 *
 * Each subtype directly implements the appropriate processor interface ([JweEncryptor],
 * [JweDecryptor], or [JweProcessor]) and carries the cryptographic logic for its role.
 *
 * @see co.touchlab.kjwt.model.registry.DefaultJwtProcessorRegistry
 * @see co.touchlab.kjwt.parser.JwtParserBuilder.decryptWith
 */
public sealed class EncryptionKey : BaseJweProcessor {
    /** The algorithm and key ID that identify this key within a registry. */
    public abstract val identifier: Identifier

    /** The public key material used for encryption; throws on subtypes that do not hold a public key. */
    public abstract val publicKey: Key

    /** The private key material used for decryption; throws on subtypes that do not hold a private key. */
    public abstract val privateKey: Key

    override val algorithm: EncryptionAlgorithm get() = identifier.algorithm
    override val keyId: String? get() = identifier.keyId

    /**
     * Identifies an [EncryptionKey] within a [co.touchlab.kjwt.model.registry.DefaultJwtProcessorRegistry]
     * by algorithm and optional key ID.
     *
     * The combination of [algorithm] and [keyId] must be unique within a registry. When [keyId]
     * is `null` the key acts as a catch-all for its algorithm (matched after any exact-`kid` key
     * during look-up).
     *
     * @property algorithm the JWE key-encryption algorithm this key is associated with
     * @property keyId the optional `kid` header value used to select this key; `null` matches any
     *   token for the given algorithm that has no more specific key registered
     */
    public data class Identifier(
        val algorithm: EncryptionAlgorithm,
        val keyId: String?,
    ) {
        public companion object;
    }

    /**
     * An encryption-only key that holds only the public key material, implementing [JweEncryptor].
     *
     * Used when a token must be encrypted but decryption is not performed by the same key holder
     * (e.g. asymmetric algorithms where only the public key is available). Accessing [privateKey]
     * on this type throws.
     */
    public class EncryptionOnlyKey @DelicateKJWTApi constructor(
        override val identifier: Identifier,
        override val publicKey: Key,
    ) : EncryptionKey(), JweEncryptor {
        @Deprecated("EncryptionOnlyKey does not have a private key", level = DeprecationLevel.ERROR)
        override val privateKey: Key
            get() = error("EncryptionOnlyKey does not have a private key")

        override suspend fun encrypt(
            data: ByteArray,
            aad: ByteArray,
            contentAlgorithm: EncryptionContentAlgorithm,
        ): JweEncryptResult = publicKey.encryptWith(identifier.algorithm, data, aad, contentAlgorithm)

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as EncryptionOnlyKey

            if (identifier != other.identifier) return false
            if (publicKey != other.publicKey) return false

            return true
        }

        override fun hashCode(): Int {
            var result = identifier.hashCode()
            result = 31 * result + publicKey.hashCode()
            return result
        }

        override fun toString(): String = "EncryptionOnlyKey(identifier=$identifier, publicKey=$publicKey)"
    }

    /**
     * A decryption-only key that holds only the private key material, implementing [JweDecryptor].
     *
     * Used when tokens must be decrypted but encryption is not required (e.g. a service that only
     * consumes encrypted tokens). Accessing [publicKey] on this type throws.
     */
    public class DecryptionOnlyKey @DelicateKJWTApi constructor(
        override val identifier: Identifier,
        override val privateKey: Key,
    ) : EncryptionKey(), JweDecryptor {
        @Deprecated("DecryptionOnlyKey does not have a public key", level = DeprecationLevel.ERROR)
        override val publicKey: Key
            get() = error("DecryptionOnlyKey does not have a public key")

        override suspend fun decrypt(
            aad: ByteArray,
            encryptedKey: ByteArray,
            iv: ByteArray,
            data: ByteArray,
            tag: ByteArray,
            contentAlgorithm: EncryptionContentAlgorithm,
        ): ByteArray = privateKey.decryptWith(identifier.algorithm, aad, encryptedKey, iv, data, tag, contentAlgorithm)

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as DecryptionOnlyKey

            if (identifier != other.identifier) return false
            if (privateKey != other.privateKey) return false

            return true
        }

        override fun hashCode(): Int {
            var result = identifier.hashCode()
            result = 31 * result + privateKey.hashCode()
            return result
        }

        override fun toString(): String = "DecryptionOnlyKey(identifier=$identifier, privateKey=$privateKey)"
    }

    /**
     * A complete key pair that holds both public and private key material, implementing [JweProcessor].
     *
     * Produced automatically by [mergeWith] when an [EncryptionOnlyKey] and a [DecryptionOnlyKey]
     * with the same [Identifier] are both registered in a
     * [co.touchlab.kjwt.model.registry.DefaultJwtProcessorRegistry]. Supports both encryption and
     * decryption.
     */
    public class EncryptionKeyPair @DelicateKJWTApi constructor(
        override val identifier: Identifier,
        override val publicKey: Key,
        override val privateKey: Key,
    ) : EncryptionKey(), JweProcessor {
        override suspend fun encrypt(
            data: ByteArray,
            aad: ByteArray,
            contentAlgorithm: EncryptionContentAlgorithm,
        ): JweEncryptResult = publicKey.encryptWith(identifier.algorithm, data, aad, contentAlgorithm)

        override suspend fun decrypt(
            aad: ByteArray,
            encryptedKey: ByteArray,
            iv: ByteArray,
            data: ByteArray,
            tag: ByteArray,
            contentAlgorithm: EncryptionContentAlgorithm,
        ): ByteArray = privateKey.decryptWith(identifier.algorithm, aad, encryptedKey, iv, data, tag, contentAlgorithm)

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as EncryptionKeyPair

            if (identifier != other.identifier) return false
            if (publicKey != other.publicKey) return false
            if (privateKey != other.privateKey) return false

            return true
        }

        override fun hashCode(): Int {
            var result = identifier.hashCode()
            result = 31 * result + publicKey.hashCode()
            result = 31 * result + privateKey.hashCode()
            return result
        }

        override fun toString(): String =
            "EncryptionKeyPair(identifier=$identifier, publicKey=$publicKey, privateKey=$privateKey)"
    }

    @OptIn(DelicateKJWTApi::class)
    public fun mergeWith(other: EncryptionKey?): EncryptionKey {
        if (other == null) return this

        require(identifier == other.identifier) { "Cannot merge keys with different identifiers" }
        require(this::class != other::class) { "Cannot merge keys of the same type" }
        require(this !is EncryptionKeyPair || other !is EncryptionKeyPair) { "Cannot merge when one key is complete" }

        return when (this) {
            is EncryptionOnlyKey if other is DecryptionOnlyKey -> {
                EncryptionKeyPair(identifier, publicKey, other.privateKey)
            }

            is DecryptionOnlyKey if other is EncryptionKeyPair -> {
                EncryptionKeyPair(identifier, other.publicKey, privateKey)
            }

            else -> {
                error("Cannot merge given keys")
            }
        }
    }
}

private suspend fun Key.encryptWith(
    algorithm: EncryptionAlgorithm,
    data: ByteArray,
    aad: ByteArray,
    contentAlgorithm: EncryptionContentAlgorithm,
): JweEncryptResult =
    when (this) {
        is RSA.OAEP.PublicKey if (algorithm is EncryptionAlgorithm.OAEPBased) -> {
            val cek = generateCek(contentAlgorithm)
            val encryptedKey = encryptor().encrypt(cek)
            encryptContent(contentAlgorithm, cek, data, aad, encryptedKey)
        }

        is SimpleKey if (algorithm is EncryptionAlgorithm.Dir) -> {
            val cek = value
            encryptContent(contentAlgorithm, cek, data, aad, ByteArray(0))
        }

        else -> {
            error("The keys provided for encryption are not valid for the ${algorithm.id}.")
        }
    }

private suspend fun Key.decryptWith(
    algorithm: EncryptionAlgorithm,
    aad: ByteArray,
    encryptedKey: ByteArray,
    iv: ByteArray,
    data: ByteArray,
    tag: ByteArray,
    contentAlgorithm: EncryptionContentAlgorithm,
): ByteArray =
    when (this) {
        is RSA.OAEP.PrivateKey if (algorithm is EncryptionAlgorithm.OAEPBased) -> {
            val cek = decryptor().decrypt(encryptedKey)
            decryptContent(contentAlgorithm, cek, iv, data, tag, aad)
        }

        is SimpleKey if (algorithm is EncryptionAlgorithm.Dir) -> {
            val cek = value
            decryptContent(contentAlgorithm, cek, iv, data, tag, aad)
        }

        else -> {
            error("The keys provided for decryption are not valid for the ${algorithm.id}.")
        }
    }

private fun generateCek(contentAlgorithm: EncryptionContentAlgorithm): ByteArray =
    Random.nextBytes(
        when (contentAlgorithm) {
            EncryptionContentAlgorithm.A128GCM -> 16

            EncryptionContentAlgorithm.A192GCM -> 24

            EncryptionContentAlgorithm.A256GCM -> 32

            EncryptionContentAlgorithm.A128CbcHs256 -> 32

            // 16 mac + 16 enc
            EncryptionContentAlgorithm.A192CbcHs384 -> 48

            // 24 mac + 24 enc
            EncryptionContentAlgorithm.A256CbcHs512 -> 64 // 32 mac + 32 enc
        },
    )

private suspend fun encryptContent(
    contentAlgorithm: EncryptionContentAlgorithm,
    cek: ByteArray,
    plaintext: ByteArray,
    aad: ByteArray,
    encryptedKey: ByteArray,
): JweEncryptResult =
    when (contentAlgorithm) {
        is EncryptionContentAlgorithm.AesGCMBased -> {
            val aesKey =
                CryptographyProvider.Default
                    .get(AES.GCM)
                    .keyDecoder()
                    .decodeFromByteArray(AES.Key.Format.RAW, cek)

            val cipher = aesKey.cipher()
            val iv = Random.nextBytes(GCM_IV_SIZE)

            // encryptWithIv returns ciphertext || auth_tag
            val combined = cipher.encryptWithIv(iv, plaintext, aad)
            val ctLen = combined.size - GCM_TAG_SIZE
            val ciphertext = combined.copyOfRange(0, ctLen)
            val tag = combined.copyOfRange(ctLen, combined.size)

            JweEncryptResult(encryptedKey, iv, ciphertext, tag)
        }

        is EncryptionContentAlgorithm.AesCBCBased -> {
            val half = cek.size / 2
            val macKey = cek.copyOfRange(0, half)
            val encKey = cek.copyOfRange(half, cek.size)

            val iv = Random.nextBytes(CBC_IV_SIZE)

            val aesKey =
                CryptographyProvider.Default
                    .get(AES.CBC)
                    .keyDecoder()
                    .decodeFromByteArray(AES.Key.Format.RAW, encKey)
            val ciphertext = aesKey.cipher().encryptWithIv(iv, plaintext)

            val tag = computeCbcHmacTag(contentAlgorithm, macKey, aad, iv, ciphertext)

            JweEncryptResult(encryptedKey, iv, ciphertext, tag)
        }
    }

private suspend fun decryptContent(
    contentAlgorithm: EncryptionContentAlgorithm,
    cek: ByteArray,
    iv: ByteArray,
    ciphertext: ByteArray,
    tag: ByteArray,
    aad: ByteArray,
): ByteArray =
    when (contentAlgorithm) {
        is EncryptionContentAlgorithm.AesGCMBased -> {
            val aesKey =
                CryptographyProvider.Default
                    .get(AES.GCM)
                    .keyDecoder()
                    .decodeFromByteArray(AES.Key.Format.RAW, cek)
            // Recombine ciphertext || tag before passing to the cipher
            aesKey.cipher().decryptWithIv(iv, ciphertext + tag, aad)
        }

        is EncryptionContentAlgorithm.AesCBCBased -> {
            val half = cek.size / 2
            val macKey = cek.copyOfRange(0, half)
            val encKey = cek.copyOfRange(half, cek.size)

            val expectedTag = computeCbcHmacTag(contentAlgorithm, macKey, aad, iv, ciphertext)
            require(expectedTag.contentEquals(tag)) {
                "JWE authentication tag verification failed"
            }

            val aesKey =
                CryptographyProvider.Default
                    .get(AES.CBC)
                    .keyDecoder()
                    .decodeFromByteArray(AES.Key.Format.RAW, encKey)
            aesKey.cipher().decryptWithIv(iv, ciphertext)
        }
    }

private suspend fun computeCbcHmacTag(
    contentAlgorithm: EncryptionContentAlgorithm.AesCBCBased,
    macKey: ByteArray,
    aad: ByteArray,
    iv: ByteArray,
    ciphertext: ByteArray,
): ByteArray {
    // MAC input: AAD || IV || Ciphertext || AL (RFC 7516 §5.2.2.1)
    val al = aad.size.toLong() * 8
    val alBytes = ByteArray(8) { i -> ((al shr (56 - i * 8)) and 0xFF).toByte() }
    val macInput = aad + iv + ciphertext + alBytes

    val (hmacDigest, tagLen) =
        when (contentAlgorithm) {
            EncryptionContentAlgorithm.A128CbcHs256 -> Pair(SHA256, 16)
            EncryptionContentAlgorithm.A192CbcHs384 -> Pair(SHA384, 24)
            EncryptionContentAlgorithm.A256CbcHs512 -> Pair(SHA512, 32)
        }

    val hmacKey =
        CryptographyProvider.Default
            .get(HMAC)
            .keyDecoder(hmacDigest)
            .decodeFromByteArray(HMAC.Key.Format.RAW, macKey)
    val fullMac = hmacKey.signatureGenerator().generateSignature(macInput)

    // Per RFC 7516: truncate to the first T_LEN bytes
    return fullMac.copyOfRange(0, tagLen)
}

private const val GCM_IV_SIZE = 12
private const val GCM_TAG_SIZE = 16
private const val CBC_IV_SIZE = 16
