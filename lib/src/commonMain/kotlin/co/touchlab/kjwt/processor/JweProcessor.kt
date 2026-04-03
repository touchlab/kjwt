package co.touchlab.kjwt.processor

import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.EncryptionContentAlgorithm
import co.touchlab.kjwt.model.algorithm.JweEncryptResult

/**
 * Common base for all JWE processor types, carrying the [algorithm] and optional [keyId] that
 * identify the key material used for encryption or decryption.
 *
 * Subtypes specialise into [JweEncryptor] (encryption only), [JweDecryptor] (decryption only), or
 * the combined [JweProcessor].
 *
 * @see JweEncryptor
 * @see JweDecryptor
 * @see JweProcessor
 */
public interface BaseJweProcessor {
    /** The JWE key-encryption algorithm this processor implements. */
    public val algorithm: EncryptionAlgorithm

    /** The optional key ID (`kid`) associated with the key material used by this processor. */
    public val keyId: String?

    public companion object;
}

/**
 * Core abstraction for JWE (encrypted JWT) key encryption and decryption.
 *
 * Combines the [JweEncryptor] and [JweDecryptor] functional interfaces and associates them with an
 * [EncryptionAlgorithm] and an optional key ID. Implementations are supplied to
 * [co.touchlab.kjwt.builder.JwtBuilder] for token encryption and to
 * [co.touchlab.kjwt.parser.JwtParserBuilder] for token decryption.
 *
 * @see BaseJweProcessor
 * @see JweEncryptor
 * @see JweDecryptor
 */
public interface JweProcessor : BaseJweProcessor, JweEncryptor, JweDecryptor {
    public companion object {
        /**
         * Creates a [JweProcessor] that delegates encryption to [encryptor] and decryption to [decryptor].
         *
         * Both must share the same algorithm; [encryptor]'s algorithm and key ID are used for the
         * combined processor.
         *
         * @param encryptor the [JweEncryptor] that performs key wrapping and content encryption
         * @param decryptor the [JweDecryptor] that performs key unwrapping and content decryption
         * @return a [JweProcessor] combining both operations
         */
        public fun combining(
            encryptor: JweEncryptor,
            decryptor: JweDecryptor,
        ): JweProcessor = object : JweProcessor, JweEncryptor by encryptor, JweDecryptor by decryptor {
            override val algorithm: EncryptionAlgorithm = encryptor.algorithm
            override val keyId: String? = encryptor.keyId
        }
    }
}

/**
 * Functional interface for encrypting a content encryption key (CEK) and the token payload.
 *
 * @see JweProcessor
 */
public interface JweEncryptor : BaseJweProcessor {
    /**
     * Encrypts [data] using the given [contentAlgorithm] and returns the full JWE encryption result.
     *
     * @param data the plaintext payload bytes to encrypt
     * @param aad the additional authenticated data (the ASCII encoding of the JWE Protected Header)
     * @param contentAlgorithm the content encryption algorithm to use for encrypting [data]
     * @return the [JweEncryptResult] containing the encrypted key, IV, ciphertext, and authentication tag
     */
    public suspend fun encrypt(
        data: ByteArray,
        aad: ByteArray,
        contentAlgorithm: EncryptionContentAlgorithm,
    ): JweEncryptResult

    public companion object;
}

/**
 * Functional interface for decrypting a JWE token payload.
 *
 * @see JweProcessor
 */
public interface JweDecryptor : BaseJweProcessor {
    /**
     * Decrypts and authenticates the JWE token components, returning the plaintext payload bytes.
     *
     * @param aad the additional authenticated data (the ASCII encoding of the JWE Protected Header)
     * @param encryptedKey the encrypted content encryption key bytes
     * @param iv the initialization vector bytes
     * @param data the ciphertext bytes to decrypt
     * @param tag the authentication tag bytes
     * @param contentAlgorithm the content encryption algorithm used to encrypt the payload
     * @return the decrypted plaintext payload bytes
     * @throws co.touchlab.kjwt.exception.SignatureException if authentication tag verification fails
     */
    public suspend fun decrypt(
        aad: ByteArray,
        encryptedKey: ByteArray,
        iv: ByteArray,
        data: ByteArray,
        tag: ByteArray,
        contentAlgorithm: EncryptionContentAlgorithm,
    ): ByteArray

    public companion object;
}
