package co.touchlab.kjwt.hardware

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import co.touchlab.kjwt.hardware.AndroidKeyStoreEncryptionKey.Companion.getInstance
import co.touchlab.kjwt.hardware.AndroidKeyStoreEncryptionKey.Companion.getOrCreateInstance
import co.touchlab.kjwt.hardware.ext.generateCek
import co.touchlab.kjwt.hardware.ext.toOaepCipherName
import co.touchlab.kjwt.hardware.ext.toOaepParameterSpec
import co.touchlab.kjwt.hardware.helpers.AndroidKeyStoreManager
import co.touchlab.kjwt.hardware.model.SecureHardwarePreference
import co.touchlab.kjwt.hardware.model.runWithFlag
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.EncryptionContentAlgorithm
import co.touchlab.kjwt.model.algorithm.Jwa
import co.touchlab.kjwt.model.algorithm.JweEncryptResult
import co.touchlab.kjwt.model.algorithm.JwtDigest
import co.touchlab.kjwt.processor.JweProcessor
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * A hardware-backed [JweProcessor] that wraps and unwraps content-encryption keys (CEKs) using
 * RSA keys stored in the Android Keystore. The RSA private key never leaves the secure element
 * (TEE or StrongBox); only the CEK — generated per-encrypt call — leaves the hardware boundary.
 *
 * Use [getInstance] to look up an existing key, or [getOrCreateInstance] to obtain one and
 * generate it on first use.
 */
public class AndroidKeyStoreEncryptionKey internal constructor(
    override val algorithm: EncryptionAlgorithm,
    override val keyId: String,
) : JweProcessor {
    public companion object {
        @Deprecated(
            "AndroidKeyStoreEncryptionKey does not support the Dir algorithm. Use a symmetric key provider instead.",
            level = DeprecationLevel.ERROR
        )
        public fun getInstance(
            algorithm: EncryptionAlgorithm.Dir,
            keyId: String?,
        ): AndroidKeyStoreEncryptionKey? {
            error(
                "AndroidKeyStoreEncryptionKey does not support the Dir algorithm. Use a symmetric key provider instead."
            )
        }

        /**
         * Returns an [AndroidKeyStoreEncryptionKey] for the given [algorithm] and [keyId] if a
         * matching key already exists in the Android Keystore, or `null` if no such key is found.
         *
         * This function never generates a new key. Use [getOrCreateInstance] to auto-create one.
         *
         * @param keyId The Android Keystore alias to look up. When `null`, a library-managed
         *   default alias derived from [algorithm] is used.
         */
        public fun getInstance(
            algorithm: EncryptionAlgorithm,
            keyId: String?,
        ): AndroidKeyStoreEncryptionKey? {
            require(algorithm != EncryptionAlgorithm.Dir) {
                "AndroidKeyStoreEncryptionKey does not support the Dir algorithm. Use a symmetric key provider instead."
            }
            val finalKeyId = AndroidKeyStoreManager.getDefaultKey(keyId, algorithm)

            return if (AndroidKeyStoreManager.containsKey(finalKeyId)) {
                AndroidKeyStoreEncryptionKey(
                    algorithm = algorithm,
                    keyId = finalKeyId
                )
            } else {
                null
            }
        }

        @Deprecated(
            "AndroidKeyStoreEncryptionKey does not support the Dir algorithm. Use a symmetric key provider instead.",
            level = DeprecationLevel.ERROR
        )
        public fun getOrCreateInstance(
            algorithm: EncryptionAlgorithm.Dir,
            keyId: String?,
            keySizeInBits: Int = 2048,
            strongBoxPreference: SecureHardwarePreference = SecureHardwarePreference.None,
        ): AndroidKeyStoreEncryptionKey {
            error(
                "AndroidKeyStoreEncryptionKey does not support the Dir algorithm. Use a symmetric key provider instead."
            )
        }

        /**
         * Returns an [AndroidKeyStoreEncryptionKey] for the given [algorithm] and [keyId],
         * generating a new RSA key pair in the Android Keystore if one does not already exist.
         *
         * @param keyId The Android Keystore alias to use. When `null`, a library-managed default
         *   alias derived from [algorithm] is used.
         * @param keySizeInBits RSA key size in bits. Defaults to 2048.
         * @param strongBoxPreference Controls whether the key is generated inside StrongBox.
         *   Defaults to [SecureHardwarePreference.None].
         */
        public fun getOrCreateInstance(
            algorithm: EncryptionAlgorithm,
            keyId: String?,
            keySizeInBits: Int = 2048,
            strongBoxPreference: SecureHardwarePreference = SecureHardwarePreference.Preferred,
        ): AndroidKeyStoreEncryptionKey {
            require(algorithm != EncryptionAlgorithm.Dir) {
                "AndroidKeyStoreEncryptionKey does not support the Dir algorithm. Use a symmetric key provider instead."
            }
            val finalKeyId = AndroidKeyStoreManager.getDefaultKey(keyId, algorithm)

            if (!AndroidKeyStoreManager.containsKey(finalKeyId)) {
                AndroidKeystoreEncryptionKeyFactory.create(algorithm, finalKeyId, keySizeInBits, strongBoxPreference)
            }

            return AndroidKeyStoreEncryptionKey(
                algorithm = algorithm,
                keyId = finalKeyId
            )
        }
    }

    private val secureRandom = SecureRandom()

    /**
     * Generates a random CEK for [contentAlgorithm], encrypts it with the hardware-backed RSA
     * public key using OAEP padding, then encrypts [data] with the CEK using [contentAlgorithm].
     *
     * Returns a [JweEncryptResult] containing the wrapped key, IV, ciphertext, and authentication
     * tag ready for use as JWE token parts.
     */
    override suspend fun encrypt(
        data: ByteArray,
        aad: ByteArray,
        contentAlgorithm: EncryptionContentAlgorithm,
    ): JweEncryptResult {
        val key = AndroidKeyStoreManager.getKey(keyId)

        return when (algorithm) {
            EncryptionAlgorithm.Dir -> {
                error("DIR algorithm is not supported by AndroidKeyStoreEncryptionKey.")
            }

            is EncryptionAlgorithm.OAEPBased if (key is KeyStore.PrivateKeyEntry) -> {
                val cipherName = algorithm.toOaepCipherName()
                val oaepSpec = algorithm.toOaepParameterSpec()
                val cek = contentAlgorithm.generateCek {
                    ByteArray(it).apply(secureRandom::nextBytes)
                }
                val encryptedKey = Cipher.getInstance(cipherName)
                    .run {
                        init(
                            Cipher.ENCRYPT_MODE,
                            key.certificate.publicKey,
                            oaepSpec
                        )
                        doFinal(cek)
                    }
                val (iv, ciphertext, tag) = contentAlgorithm.encryptContentJca(cek, data, aad)
                JweEncryptResult(encryptedKey, iv, ciphertext, tag)
            }

            else -> {
                error("No key available for encrypting $algorithm with id $keyId.")
            }
        }
    }

    /**
     * Unwraps [encryptedKey] using the hardware-backed RSA private key, then decrypts [data]
     * with the recovered CEK using [contentAlgorithm].
     *
     * Throws if authentication tag verification fails (AES-CBC-HMAC modes) or if the
     * OAEP unwrapping fails.
     */
    override suspend fun decrypt(
        aad: ByteArray,
        encryptedKey: ByteArray,
        iv: ByteArray,
        data: ByteArray,
        tag: ByteArray,
        contentAlgorithm: EncryptionContentAlgorithm,
    ): ByteArray {
        val key = AndroidKeyStoreManager.getKey(keyId)

        return when (algorithm) {
            EncryptionAlgorithm.Dir -> {
                error("DIR algorithm is not supported by AndroidKeyStoreEncryptionKey.")
            }

            is EncryptionAlgorithm.OAEPBased if (key is KeyStore.PrivateKeyEntry) -> {
                val cipherName = algorithm.toOaepCipherName()
                val oaepSpec = algorithm.toOaepParameterSpec()

                val cek = Cipher.getInstance(cipherName)
                    .run {
                        init(Cipher.DECRYPT_MODE, key.privateKey, oaepSpec)
                        doFinal(encryptedKey)
                    }

                contentAlgorithm.decryptContentJca(cek, iv, data, tag, aad)
            }

            else -> {
                error("No key available for encrypting $algorithm with id $keyId.")
            }
        }
    }

    /** Returns (iv, ciphertext, tag). */
    private fun EncryptionContentAlgorithm.encryptContentJca(
        cek: ByteArray,
        plaintext: ByteArray,
        aad: ByteArray,
    ): Triple<ByteArray, ByteArray, ByteArray> =
        when (this) {
            is EncryptionContentAlgorithm.AesGCMBased -> {
                val iv = ByteArray(12).also { secureRandom.nextBytes(it) }
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(cek, "AES"), GCMParameterSpec(128, iv))
                cipher.updateAAD(aad)
                val combined = cipher.doFinal(plaintext)
                val ctLen = combined.size - 16
                Triple(iv, combined.copyOf(ctLen), combined.copyOfRange(ctLen, combined.size))
            }

            is EncryptionContentAlgorithm.AesCBCBased -> {
                val half = cek.size / 2
                val macKey = cek.copyOf(half)
                val encKey = cek.copyOfRange(half, cek.size)
                val iv = ByteArray(16).also { secureRandom.nextBytes(it) }
                val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
                cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(encKey, "AES"), IvParameterSpec(iv))
                val ciphertext = cipher.doFinal(plaintext)
                val tag = computeCbcHmacTagJca(macKey, aad, iv, ciphertext)
                Triple(iv, ciphertext, tag)
            }
        }

    private fun EncryptionContentAlgorithm.decryptContentJca(
        cek: ByteArray,
        iv: ByteArray,
        ciphertext: ByteArray,
        tag: ByteArray,
        aad: ByteArray,
    ): ByteArray =
        when (this) {
            is EncryptionContentAlgorithm.AesGCMBased -> {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(cek, "AES"), GCMParameterSpec(128, iv))
                cipher.updateAAD(aad)
                cipher.doFinal(ciphertext + tag)
            }

            is EncryptionContentAlgorithm.AesCBCBased -> {
                val half = cek.size / 2
                val macKey = cek.copyOf(half)
                val encKey = cek.copyOfRange(half, cek.size)
                val expectedTag = computeCbcHmacTagJca(macKey, aad, iv, ciphertext)
                require(MessageDigest.isEqual(expectedTag, tag)) { "JWE authentication tag verification failed" }
                val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(encKey, "AES"), IvParameterSpec(iv))
                cipher.doFinal(ciphertext)
            }
        }

    private fun EncryptionContentAlgorithm.AesCBCBased.computeCbcHmacTagJca(
        macKey: ByteArray,
        aad: ByteArray,
        iv: ByteArray,
        ciphertext: ByteArray,
    ): ByteArray {
        val al = aad.size.toLong() * 8
        val alBytes = ByteArray(8) { i -> ((al shr (56 - i * 8)) and 0xFF).toByte() }
        val macInput = aad + iv + ciphertext + alBytes

        val (jcaMacAlg, tagLen) = when (this) {
            EncryptionContentAlgorithm.A128CbcHs256 -> "HmacSHA256" to 16
            EncryptionContentAlgorithm.A192CbcHs384 -> "HmacSHA384" to 24
            EncryptionContentAlgorithm.A256CbcHs512 -> "HmacSHA512" to 32
        }

        val mac = Mac.getInstance(jcaMacAlg)
        mac.init(SecretKeySpec(macKey, jcaMacAlg))
        return mac.doFinal(macInput).copyOf(tagLen)
    }
}

/**
 * Low-level factory that generates and registers RSA encryption key pairs in the Android Keystore.
 *
 * Most callers should use [AndroidKeyStoreEncryptionKey.getOrCreateInstance] instead, which wraps
 * this factory and handles existence checks automatically.
 */
public object AndroidKeystoreEncryptionKeyFactory {
    /**
     * Generates a new RSA key pair for [algorithm] and stores it in the Android Keystore under
     * the alias [keyId].
     *
     * @param keySizeInBits RSA key size in bits. Defaults to 2048.
     * @param strongBoxPreference Controls whether the key is generated inside StrongBox.
     *   Defaults to [SecureHardwarePreference.None].
     */
    public fun create(
        algorithm: EncryptionAlgorithm,
        keyId: String,
        keySizeInBits: Int = 2048,
        strongBoxPreference: SecureHardwarePreference = SecureHardwarePreference.None,
    ) {
        strongBoxPreference.runWithFlag { useStrongBox ->
            val spec =
                KeyGenParameterSpec.Builder(keyId, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .configureFor(algorithm, keySizeInBits, useStrongBox)
                    .build()

            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
                .apply { initialize(spec) }
                .generateKeyPair()
        }
    }

    private fun KeyGenParameterSpec.Builder.configureFor(
        algorithm: EncryptionAlgorithm,
        keySize: Int,
        useStrongBox: Boolean,
    ) = apply {
        if (algorithm is Jwa.UsesHashingAlgorithm) {
            setDigests(
                when (algorithm.digest) {
                    JwtDigest.SHA1 -> KeyProperties.DIGEST_SHA1
                    JwtDigest.SHA256 -> KeyProperties.DIGEST_SHA256
                    JwtDigest.SHA384 -> KeyProperties.DIGEST_SHA384
                    JwtDigest.SHA512 -> KeyProperties.DIGEST_SHA512
                }
            )
        }

        if (algorithm is EncryptionAlgorithm.OAEPBased) {
            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            setKeySize(keySize)
            // setMgf1Digests was added in API 35; on older APIs SHA-1 is the only allowed MGF1 digest
            if (algorithm == EncryptionAlgorithm.RsaOaep256 && Build.VERSION.SDK_INT >= 35) {
                setMgf1Digests(KeyProperties.DIGEST_SHA256)
            }
        }

        if (useStrongBox && Build.VERSION.SDK_INT >= 28) {
            setIsStrongBoxBacked(true)
        }
    }
}
