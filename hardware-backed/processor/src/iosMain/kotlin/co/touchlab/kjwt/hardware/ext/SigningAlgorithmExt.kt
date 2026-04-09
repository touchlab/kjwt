package co.touchlab.kjwt.hardware.ext

import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import kotlinx.cinterop.ExperimentalForeignApi
import platform.CoreFoundation.CFStringRef
import platform.Security.kSecAttrKeyTypeECSECPrimeRandom
import platform.Security.kSecAttrKeyTypeRSA
import platform.Security.kSecKeyAlgorithmECDSASignatureMessageX962SHA256
import platform.Security.kSecKeyAlgorithmECDSASignatureMessageX962SHA384
import platform.Security.kSecKeyAlgorithmECDSASignatureMessageX962SHA512
import platform.Security.kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256
import platform.Security.kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384
import platform.Security.kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512
import platform.Security.kSecKeyAlgorithmRSASignatureMessagePSSSHA256
import platform.Security.kSecKeyAlgorithmRSASignatureMessagePSSSHA384
import platform.Security.kSecKeyAlgorithmRSASignatureMessagePSSSHA512

/**
 * Maps a [SigningAlgorithm] to the corresponding Apple Security framework `SecKeyAlgorithm`.
 *
 * Returns null for HMAC algorithms (which use raw `CCHmac` instead) and for [SigningAlgorithm.None].
 *
 * The `*Message*` variants are used so the full message is passed and the framework handles
 * hashing internally, matching the contract of [co.touchlab.kjwt.processor.JwsSigner].
 */
@OptIn(ExperimentalForeignApi::class)
public val SigningAlgorithm.secKeyAlgorithm: CFStringRef?
    get() = when (this) {
        is SigningAlgorithm.MACBased -> null // HMAC handled via CCHmac directly
        SigningAlgorithm.RS256 -> kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256
        SigningAlgorithm.RS384 -> kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384
        SigningAlgorithm.RS512 -> kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512
        SigningAlgorithm.PS256 -> kSecKeyAlgorithmRSASignatureMessagePSSSHA256
        SigningAlgorithm.PS384 -> kSecKeyAlgorithmRSASignatureMessagePSSSHA384
        SigningAlgorithm.PS512 -> kSecKeyAlgorithmRSASignatureMessagePSSSHA512
        SigningAlgorithm.ES256 -> kSecKeyAlgorithmECDSASignatureMessageX962SHA256
        SigningAlgorithm.ES384 -> kSecKeyAlgorithmECDSASignatureMessageX962SHA384
        SigningAlgorithm.ES512 -> kSecKeyAlgorithmECDSASignatureMessageX962SHA512
        SigningAlgorithm.None -> null
    }

/** The Keychain key type attribute for this algorithm. */
@OptIn(ExperimentalForeignApi::class)
internal val SigningAlgorithm.secKeyType: CFStringRef?
    get() = when (this) {
        is SigningAlgorithm.MACBased -> null // HMAC stored as generic password, not as SecKey
        is SigningAlgorithm.PKCS1Based, is SigningAlgorithm.PSSBased -> kSecAttrKeyTypeRSA
        is SigningAlgorithm.ECDSABased -> kSecAttrKeyTypeECSECPrimeRandom
        SigningAlgorithm.None -> null
    }

/** The key size in bits for EC keys based on the curve. */
internal val SigningAlgorithm.ECDSABased.ecKeySizeInBits: Int
    get() = when (this) {
        SigningAlgorithm.ES256 -> 256
        SigningAlgorithm.ES384 -> 384
        SigningAlgorithm.ES512 -> 521
    }
