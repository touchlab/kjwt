package co.touchlab.kjwt.hardware

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import co.touchlab.kjwt.hardware.ext.algorithmParameterSpec
import co.touchlab.kjwt.hardware.ext.asKeyPropertiesDigest
import co.touchlab.kjwt.hardware.ext.coordLen
import co.touchlab.kjwt.hardware.ext.toJcaSignatureName
import co.touchlab.kjwt.hardware.ext.toPSSParameterSpec
import co.touchlab.kjwt.hardware.internal.ecdsaDerToP1363
import co.touchlab.kjwt.hardware.internal.ecdsaP1363ToDer
import co.touchlab.kjwt.hardware.helpers.AndroidKeyStoreManager
import co.touchlab.kjwt.hardware.model.SecureHardwarePreference
import co.touchlab.kjwt.hardware.model.runWithFlag
import co.touchlab.kjwt.model.algorithm.Jwa
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import co.touchlab.kjwt.processor.JwsProcessor
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import javax.crypto.KeyGenerator
import javax.crypto.Mac

/**
 * A hardware-backed [JwsProcessor] that signs and verifies data using keys stored in the Android
 * Keystore. Key material never leaves the secure element (TEE or StrongBox) — private and secret
 * keys are generated and used entirely within the secure hardware.
 *
 * Use [getInstance] to look up an existing key, or [getOrCreateInstance] to obtain one and
 * generate it on first use.
 */
public class AndroidKeyStoreSigningKey internal constructor(
    override val algorithm: SigningAlgorithm,
    override val keyId: String,
) : JwsProcessor {
    public companion object {
        /**
         * Returns an [AndroidKeyStoreSigningKey] for the given [algorithm] and [keyId] if a
         * matching key already exists in the Android Keystore, or `null` if no such key is found.
         *
         * This function never generates a new key. Use [getOrCreateInstance] to auto-create one.
         *
         * @param keyId The Android Keystore alias to look up. When `null`, a library-managed
         *   default alias derived from [algorithm] is used.
         */
        public fun getInstance(
            algorithm: SigningAlgorithm,
            keyId: String?,
        ): AndroidKeyStoreSigningKey? {
            val finalKeyId = AndroidKeyStoreManager.getDefaultKey(keyId, algorithm)

            return if (AndroidKeyStoreManager.containsKey(finalKeyId)) {
                AndroidKeyStoreSigningKey(algorithm, finalKeyId)
            } else {
                null
            }
        }

        /**
         * Returns an [AndroidKeyStoreSigningKey] for the given [algorithm] and [keyId], generating
         * a new key in the Android Keystore if one does not already exist.
         *
         * @param keyId The Android Keystore alias to use. When `null`, a library-managed default
         *   alias derived from [algorithm] is used.
         * @param keySizeInBits RSA key size in bits, used when [algorithm] is RSA-based.
         *   Ignored for ECDSA and HMAC keys. Defaults to 2048.
         * @param strongBoxPreference Controls whether the key is generated inside StrongBox.
         *   Defaults to [SecureHardwarePreference.None].
         */
        public fun getOrCreateInstance(
            algorithm: SigningAlgorithm,
            keyId: String?,
            keySizeInBits: Int = 2048,
            strongBoxPreference: SecureHardwarePreference = SecureHardwarePreference.None,
        ): AndroidKeyStoreSigningKey {
            val finalKeyId = AndroidKeyStoreManager.getDefaultKey(keyId, algorithm)

            if (!AndroidKeyStoreManager.containsKey(finalKeyId)) {
                AndroidKeystoreSigningKeyFactory.create(algorithm, finalKeyId, keySizeInBits, strongBoxPreference)
            }

            return AndroidKeyStoreSigningKey(algorithm, finalKeyId)
        }
    }

    /**
     * Signs [data] using the hardware-backed key identified by [keyId].
     *
     * ECDSA signatures are converted from the DER encoding produced by Android Keystore to the
     * P1363 (raw `r || s`) format required by JWT before being returned.
     */
    override suspend fun sign(data: ByteArray): ByteArray {
        if (algorithm is SigningAlgorithm.None) {
            return SigningAlgorithm.None.SimpleProcessor.sign(data)
        }

        val key = AndroidKeyStoreManager.getKey(keyId)
        val jcaAlgorithm = algorithm.toJcaSignatureName()

        return when (algorithm) {
            is SigningAlgorithm.MACBased if (key is KeyStore.SecretKeyEntry) -> {
                Mac.getInstance(jcaAlgorithm)
                    .also { it.init(key.secretKey) }
                    .doFinal(data)
            }

            is SigningAlgorithm.PKCS1Based if (key is KeyStore.PrivateKeyEntry) -> {
                Signature.getInstance(jcaAlgorithm).run {
                    initSign(key.privateKey)
                    update(data)
                    sign()
                }
            }

            is SigningAlgorithm.PSSBased if (key is KeyStore.PrivateKeyEntry) -> {
                val pssParameter = algorithm.toPSSParameterSpec()
                Signature.getInstance(jcaAlgorithm)
                    .run {
                        setParameter(pssParameter)
                        initSign(key.privateKey)
                        update(data)
                        sign()
                    }
            }

            is SigningAlgorithm.ECDSABased if (key is KeyStore.PrivateKeyEntry) -> {
                val derSignature = Signature.getInstance(jcaAlgorithm)
                    .run {
                        initSign(key.privateKey)
                        update(data)
                        sign()
                    }

                derSignature.ecdsaDerToP1363(algorithm.coordLen)
            }

            else -> {
                error("No key available for signing content using $algorithm with id $keyId.")
            }
        }
    }

    /**
     * Verifies that [signature] is a valid signature over [data] produced by the key identified
     * by [keyId].
     *
     * P1363-encoded ECDSA signatures are converted back to DER before being passed to the
     * Android Keystore `Signature` API.
     */
    override suspend fun verify(data: ByteArray, signature: ByteArray): Boolean {
        if (algorithm is SigningAlgorithm.None) {
            return SigningAlgorithm.None.SimpleProcessor.verify(data, signature)
        }

        val key = AndroidKeyStoreManager.getKey(keyId)
        val jcaAlgorithm = algorithm.toJcaSignatureName()

        return when (algorithm) {
            is SigningAlgorithm.MACBased if (key is KeyStore.SecretKeyEntry) -> {
                val computed = sign(data)
                MessageDigest.isEqual(computed, signature)
            }

            is SigningAlgorithm.PKCS1Based if (key is KeyStore.PrivateKeyEntry) -> {
                Signature.getInstance(jcaAlgorithm).run {
                    initVerify(key.certificate.publicKey)
                    update(data)
                    verify(signature)
                }
            }

            is SigningAlgorithm.PSSBased if (key is KeyStore.PrivateKeyEntry) -> {
                val pssParameter = algorithm.toPSSParameterSpec()
                Signature.getInstance(jcaAlgorithm)
                    .run {
                        setParameter(pssParameter)
                        initVerify(key.certificate.publicKey)
                        update(data)
                        verify(signature)
                    }
            }

            is SigningAlgorithm.ECDSABased if (key is KeyStore.PrivateKeyEntry) -> {
                val derSignature = signature.ecdsaP1363ToDer(algorithm.coordLen)

                Signature.getInstance(jcaAlgorithm)
                    .run {
                        initVerify(key.certificate.publicKey)
                        update(data)
                        verify(derSignature)
                    }
            }

            else -> {
                error("No key available for verifying $algorithm with id $keyId.")
            }
        }
    }

}

/**
 * Low-level factory that generates and registers signing keys in the Android Keystore.
 *
 * Most callers should use [AndroidKeyStoreSigningKey.getOrCreateInstance] instead, which wraps
 * this factory and handles existence checks automatically.
 */
public object AndroidKeystoreSigningKeyFactory {
    /**
     * Generates a new signing key for [algorithm] and stores it in the Android Keystore under
     * the alias [keyId].
     *
     * @param keySizeInBits RSA key size in bits (ignored for ECDSA and HMAC keys). Defaults to 2048.
     * @param strongBoxPreference Controls whether the key is generated inside StrongBox.
     *   Defaults to [SecureHardwarePreference.None].
     */
    public fun create(
        algorithm: SigningAlgorithm,
        keyId: String,
        keySizeInBits: Int = 2048,
        strongBoxPreference: SecureHardwarePreference = SecureHardwarePreference.None,
    ) {
        strongBoxPreference.runWithFlag { useStrongBox ->
            val spec = KeyGenParameterSpec.Builder(keyId, algorithm.purpose())
                .configureFor(algorithm, keySizeInBits, useStrongBox)
                .build()

            when (algorithm) {
                is SigningAlgorithm.MACBased -> {
                    KeyGenerator.getInstance(algorithm.toKeyPropertiesAlgorithm(), "AndroidKeyStore")
                        .apply { init(spec) }
                        .generateKey()
                }

                else -> {
                    KeyPairGenerator.getInstance(algorithm.toKeyPropertiesAlgorithm(), "AndroidKeyStore")
                        .apply { initialize(spec) }
                        .generateKeyPair()
                }
            }
        }
    }

    private fun SigningAlgorithm.purpose(): Int = when (this) {
        is SigningAlgorithm.MACBased -> KeyProperties.PURPOSE_SIGN
        else -> KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
    }

    private fun KeyGenParameterSpec.Builder.configureFor(
        algorithm: SigningAlgorithm,
        keySize: Int,
        useStrongBox: Boolean,
    ) = apply {
        if (algorithm is Jwa.UsesHashingAlgorithm) {
            setDigests(algorithm.digest.asKeyPropertiesDigest)
        }

        if (algorithm is SigningAlgorithm.PKCS1Based) {
            setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            setKeySize(keySize)
        }

        if (algorithm is SigningAlgorithm.PSSBased) {
            setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
            setKeySize(keySize)
        }

        if (algorithm is SigningAlgorithm.ECDSABased) {
            setAlgorithmParameterSpec(algorithm.algorithmParameterSpec)
        }

        if (useStrongBox && Build.VERSION.SDK_INT >= 28) {
            setIsStrongBoxBacked(true)
        }
    }

    private fun SigningAlgorithm.toKeyPropertiesAlgorithm(): String = when (this) {
        SigningAlgorithm.HS256 -> KeyProperties.KEY_ALGORITHM_HMAC_SHA256
        SigningAlgorithm.HS384 -> KeyProperties.KEY_ALGORITHM_HMAC_SHA384
        SigningAlgorithm.HS512 -> KeyProperties.KEY_ALGORITHM_HMAC_SHA512
        is SigningAlgorithm.PKCS1Based -> KeyProperties.KEY_ALGORITHM_RSA
        is SigningAlgorithm.PSSBased -> KeyProperties.KEY_ALGORITHM_RSA
        is SigningAlgorithm.ECDSABased -> KeyProperties.KEY_ALGORITHM_EC
        SigningAlgorithm.None -> error("None algorithm should be handled outside")
    }
}
