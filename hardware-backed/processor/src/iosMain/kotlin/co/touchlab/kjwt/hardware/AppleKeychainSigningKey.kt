package co.touchlab.kjwt.hardware

import co.touchlab.kjwt.hardware.ext.constantTimeEquals
import co.touchlab.kjwt.hardware.ext.coordLen
import co.touchlab.kjwt.hardware.ext.ecKeySizeInBits
import co.touchlab.kjwt.hardware.ext.generateSecureRandomBytes
import co.touchlab.kjwt.hardware.ext.secKeyAlgorithm
import co.touchlab.kjwt.hardware.ext.secKeyType
import co.touchlab.kjwt.hardware.helpers.AppleKeychainManager
import co.touchlab.kjwt.hardware.helpers.cfDictAdd
import co.touchlab.kjwt.hardware.helpers.cfMutableDict
import co.touchlab.kjwt.hardware.helpers.toByteArray
import co.touchlab.kjwt.hardware.helpers.toCFData
import co.touchlab.kjwt.hardware.internal.ecdsaDerToP1363
import co.touchlab.kjwt.hardware.internal.ecdsaP1363ToDer
import co.touchlab.kjwt.hardware.model.SecureEnclaveUnavailableException
import co.touchlab.kjwt.hardware.model.SecureHardwarePreference
import co.touchlab.kjwt.hardware.model.runWithFlag
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import co.touchlab.kjwt.processor.JwsProcessor
import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.refTo
import kotlinx.cinterop.value
import platform.CoreCrypto.CCHmac
import platform.CoreCrypto.CCHmacAlgorithm
import platform.CoreCrypto.kCCHmacAlgSHA256
import platform.CoreCrypto.kCCHmacAlgSHA384
import platform.CoreCrypto.kCCHmacAlgSHA512
import platform.CoreFoundation.CFErrorGetCode
import platform.CoreFoundation.CFErrorRefVar
import platform.CoreFoundation.CFStringRef
import platform.CoreFoundation.kCFBooleanTrue
import platform.Security.SecKeyCreateRandomKey
import platform.Security.SecKeyCreateSignature
import platform.Security.SecKeyRef
import platform.Security.SecKeyVerifySignature
import platform.Security.kSecAttrAccessible
import platform.Security.kSecAttrAccessibleAfterFirstUnlock
import platform.Security.kSecAttrApplicationTag
import platform.Security.kSecAttrIsPermanent
import platform.Security.kSecAttrKeySizeInBits
import platform.Security.kSecAttrKeyType
import platform.Security.kSecAttrTokenID
import platform.Security.kSecAttrTokenIDSecureEnclave
import platform.Security.kSecPrivateKeyAttrs

/**
 * A hardware-backed [JwsProcessor] that signs and verifies JWT payloads using keys stored in the
 * iOS/macOS Keychain.
 *
 * Keys are stored in the Keychain with `kSecAttrAccessibleAfterFirstUnlock`,
 * making them hardware-bound to this device (they cannot be migrated via iCloud/backups).
 *
 * Use [getInstance] to look up an existing key, or [getOrCreateInstance] to obtain one and
 * generate it on first use.
 */
@OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
public class AppleKeychainSigningKey internal constructor(
    override val algorithm: SigningAlgorithm,
    override val keyId: String,
) : JwsProcessor {
    public companion object {
        /**
         * Returns an [AppleKeychainSigningKey] for the given [algorithm] and [keyId] if a matching
         * key already exists in the Keychain, or `null` if no such key is found.
         *
         * @param keyId The Keychain key alias to look up. When `null`, a library-managed default
         *   alias derived from [algorithm] is used.
         */
        public fun getInstance(
            algorithm: SigningAlgorithm,
            keyId: String?,
        ): AppleKeychainSigningKey? {
            val finalKeyId = AppleKeychainManager.getDefaultKey(keyId, algorithm)
            return if (AppleKeychainManager.containsKey(finalKeyId)) {
                AppleKeychainSigningKey(algorithm, finalKeyId)
            } else {
                null
            }
        }

        /**
         * Returns an [AppleKeychainSigningKey] for the given [algorithm] and [keyId], generating a
         * new key if one does not already exist.
         *
         * @param keyId The Keychain key alias to use. When `null`, a library-managed default alias
         *   derived from [algorithm] is used.
         * @param keySizeInBits RSA key size in bits. Ignored for ECDSA and HMAC keys. Defaults to 2048.
         * @param secureHardwarePreference Controls whether the Secure Enclave is used for key storage.
         *   Only ES256 keys can be stored in the Secure Enclave; other algorithms always use the
         *   standard hardware-bound Keychain regardless of this setting.
         */
        public fun getOrCreateInstance(
            algorithm: SigningAlgorithm,
            keyId: String?,
            keySizeInBits: Int = 2048,
            secureHardwarePreference: SecureHardwarePreference = SecureHardwarePreference.None,
        ): AppleKeychainSigningKey {
            val finalKeyId = AppleKeychainManager.getDefaultKey(keyId, algorithm)
            if (!AppleKeychainManager.containsKey(finalKeyId)) {
                secureHardwarePreference.runWithFlag(algorithm) { useSecureEnclave ->
                    AppleKeychainSigningKeyFactory.create(algorithm, finalKeyId, keySizeInBits, useSecureEnclave)
                }
            }
            return AppleKeychainSigningKey(algorithm, finalKeyId)
        }
    }

    override suspend fun sign(data: ByteArray): ByteArray {
        if (algorithm is SigningAlgorithm.None) {
            return SigningAlgorithm.None.SimpleProcessor.sign(data)
        }

        return when (algorithm) {
            is SigningAlgorithm.MACBased -> {
                val keyBytes = AppleKeychainManager.findSymmetricKeyBytes(keyId)
                    ?: error("No HMAC key found for alias '$keyId'. Did you call getOrCreateInstance?")
                computeHmac(algorithm, keyBytes, data)
            }

            is SigningAlgorithm.ECDSABased -> {
                val privateKey = AppleKeychainManager.findPrivateKey(keyId)
                    ?: error("No EC private key found for alias '$keyId'. Did you call getOrCreateInstance?")
                val derSignature = signWithSecKey(privateKey, algorithm.secKeyAlgorithm!!, data)
                derSignature.ecdsaDerToP1363(algorithm.coordLen)
            }

            is SigningAlgorithm.PKCS1Based, is SigningAlgorithm.PSSBased -> {
                val privateKey = AppleKeychainManager.findPrivateKey(keyId)
                    ?: error("No RSA private key found for alias '$keyId'. Did you call getOrCreateInstance?")
                signWithSecKey(privateKey, algorithm.secKeyAlgorithm!!, data)
            }
        }
    }

    override suspend fun verify(data: ByteArray, signature: ByteArray): Boolean {
        if (algorithm is SigningAlgorithm.None) {
            return SigningAlgorithm.None.SimpleProcessor.verify(data, signature)
        }

        return when (algorithm) {
            is SigningAlgorithm.MACBased -> {
                val computed = sign(data)
                computed.constantTimeEquals(signature)
            }

            is SigningAlgorithm.ECDSABased -> {
                val publicKey = AppleKeychainManager.findPublicKey(keyId)
                    ?: error("No EC public key found for alias '$keyId'.")
                val derSignature = signature.ecdsaP1363ToDer(algorithm.coordLen)
                verifyWithSecKey(publicKey, algorithm.secKeyAlgorithm!!, data, derSignature)
            }

            is SigningAlgorithm.PKCS1Based, is SigningAlgorithm.PSSBased -> {
                val publicKey = AppleKeychainManager.findPublicKey(keyId)
                    ?: error("No RSA public key found for alias '$keyId'.")
                verifyWithSecKey(publicKey, algorithm.secKeyAlgorithm!!, data, signature)
            }
        }
    }

    private fun signWithSecKey(
        privateKey: SecKeyRef,
        secAlgorithm: CFStringRef,
        data: ByteArray,
    ): ByteArray = memScoped {
        val errorVar = alloc<CFErrorRefVar>()
        val result = SecKeyCreateSignature(privateKey, secAlgorithm, data.toCFData(), errorVar.ptr)
            ?: run {
                val code = errorVar.value?.let { CFErrorGetCode(it) } ?: -1L
                error("SecKeyCreateSignature failed (code $code)")
            }
        result.toByteArray()
    }

    private fun verifyWithSecKey(
        publicKey: SecKeyRef,
        secAlgorithm: CFStringRef,
        data: ByteArray,
        signature: ByteArray,
    ): Boolean = memScoped {
        val errorVar = alloc<CFErrorRefVar>()
        SecKeyVerifySignature(publicKey, secAlgorithm, data.toCFData(), signature.toCFData(), errorVar.ptr)
    }

    private fun computeHmac(
        algorithm: SigningAlgorithm.MACBased,
        key: ByteArray,
        data: ByteArray,
    ): ByteArray = memScoped {
        val (hmacAlg, outputLen) = when (algorithm) {
            SigningAlgorithm.HS256 -> kCCHmacAlgSHA256 to 32
            SigningAlgorithm.HS384 -> kCCHmacAlgSHA384 to 48
            SigningAlgorithm.HS512 -> kCCHmacAlgSHA512 to 64
        }
        val output = ByteArray(outputLen)
        CCHmac(
            hmacAlg.convert<CCHmacAlgorithm>(),
            key.refTo(0),
            key.size.convert(),
            if (data.isNotEmpty()) data.refTo(0) else null,
            data.size.convert(),
            output.refTo(0),
        )
        output
    }
}

/**
 * Low-level factory that generates and stores signing keys in the Keychain.
 *
 * Most callers should use [AppleKeychainSigningKey.getOrCreateInstance] instead.
 */
@OptIn(ExperimentalForeignApi::class)
public object AppleKeychainSigningKeyFactory {
    /**
     * Generates a new signing key for [algorithm] and stores it under [keyId].
     *
     * @param keySizeInBits RSA key size in bits. Ignored for ECDSA and HMAC keys. Defaults to 2048.
     * @param useSecureEnclave When `true`, generates the key inside the Secure Enclave. Only valid
     *   for ES256; ignored for all other algorithms (they always use the standard Keychain).
     */
    public fun create(
        algorithm: SigningAlgorithm,
        keyId: String,
        keySizeInBits: Int = 2048,
        useSecureEnclave: Boolean = false,
    ) {
        when (algorithm) {
            is SigningAlgorithm.MACBased -> {
                val keySize = when (algorithm) {
                    SigningAlgorithm.HS256 -> 32
                    SigningAlgorithm.HS384 -> 48
                    SigningAlgorithm.HS512 -> 64
                }
                AppleKeychainManager.storeSymmetricKeyBytes(keyId, generateSecureRandomBytes(keySize))
            }

            is SigningAlgorithm.ECDSABased -> {
                generateAsymmetricKey(algorithm.secKeyType!!, algorithm.ecKeySizeInBits, keyId, useSecureEnclave)
            }

            is SigningAlgorithm.PKCS1Based, is SigningAlgorithm.PSSBased -> {
                // Secure Enclave does not support RSA — always use standard Keychain.
                generateAsymmetricKey(algorithm.secKeyType!!, keySizeInBits, keyId, useSecureEnclave = false)
            }

            SigningAlgorithm.None -> error("None algorithm should not be stored in hardware.")
        }
    }

    private fun generateAsymmetricKey(
        keyType: CFStringRef,
        keySize: Int,
        keyId: String,
        useSecureEnclave: Boolean,
    ) {
        memScoped {
            val privateKeyAttrs = cfMutableDict(if (useSecureEnclave) 2 else 3)

            cfDictAdd(privateKeyAttrs, kSecAttrIsPermanent, kCFBooleanTrue)
            cfDictAdd(privateKeyAttrs, kSecAttrApplicationTag, keyId.toCFData())

            if (!useSecureEnclave) {
                cfDictAdd(privateKeyAttrs, kSecAttrAccessible, kSecAttrAccessibleAfterFirstUnlock)
            }

            val keySizeRef = platform.CoreFoundation.CFNumberCreate(
                null, platform.CoreFoundation.kCFNumberSInt32Type, intArrayOf(keySize).refTo(0)
            )

            val attrs = cfMutableDict(if (useSecureEnclave) 4 else 3)
            cfDictAdd(attrs, kSecAttrKeyType, keyType)
            cfDictAdd(attrs, kSecAttrKeySizeInBits, keySizeRef)
            cfDictAdd(attrs, kSecPrivateKeyAttrs, privateKeyAttrs)

            if (useSecureEnclave) {
                cfDictAdd(attrs, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave)
            }

            val errorVar = alloc<CFErrorRefVar>()
            val result = SecKeyCreateRandomKey(attrs, errorVar.ptr)
            if (result == null) {
                val code = errorVar.value?.let { CFErrorGetCode(it) } ?: -1L
                error("Key generation failed (code $code) for alias '$keyId'")
            }
        }
    }
}
