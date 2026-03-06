package co.touchlab.kjwt.internal

import co.touchlab.kjwt.algorithm.JwsAlgorithm
import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.algorithms.SHA384
import dev.whyoleg.cryptography.algorithms.SHA512
import dev.whyoleg.cryptography.materials.key.Key

/**
 * Signs [signingInput] using [algorithm] and the given [key].
 *
 * Expected key types by algorithm family:
 * - HS256/384/512 → [HMAC.Key] (created with the matching SHA digest)
 * - RS256/384/512 → [RSA.PKCS1.PrivateKey]
 * - PS256/384/512 → [RSA.PSS.PrivateKey]
 * - ES256         → [ECDSA.PrivateKey] (created with P-256 curve)
 * - ES384         → [ECDSA.PrivateKey] (created with P-384 curve)
 * - ES512         → [ECDSA.PrivateKey] (created with P-521 curve)
 * - None          → any key (ignored); returns empty ByteArray
 */
internal suspend fun <T : Key> jwsSign(
    algorithm: JwsAlgorithm<T>,
    key: Key,
    signingInput: ByteArray
): ByteArray =
    when (algorithm) {
        JwsAlgorithm.HS256,
        JwsAlgorithm.HS384,
        JwsAlgorithm.HS512,
            -> (key as HMAC.Key).signatureGenerator().generateSignature(signingInput)

        JwsAlgorithm.RS256,
        JwsAlgorithm.RS384,
        JwsAlgorithm.RS512,
            -> (key as RSA.PKCS1.PrivateKey).signatureGenerator().generateSignature(signingInput)

        JwsAlgorithm.PS256,
        JwsAlgorithm.PS384,
        JwsAlgorithm.PS512,
            -> (key as RSA.PSS.PrivateKey).signatureGenerator().generateSignature(signingInput)

        // RFC 7518 §3.4: ECDSA signature MUST use RAW (R‖S) format, not DER.
        // The digest is determined by the algorithm; the key must match the curve.
        JwsAlgorithm.ES256 ->
            (key as ECDSA.PrivateKey).signatureGenerator(SHA256, ECDSA.SignatureFormat.RAW)
                .generateSignature(signingInput)

        JwsAlgorithm.ES384 ->
            (key as ECDSA.PrivateKey).signatureGenerator(SHA384, ECDSA.SignatureFormat.RAW)
                .generateSignature(signingInput)

        JwsAlgorithm.ES512 ->
            (key as ECDSA.PrivateKey).signatureGenerator(SHA512, ECDSA.SignatureFormat.RAW)
                .generateSignature(signingInput)

        JwsAlgorithm.None -> ByteArray(0)
    }

/**
 * Verifies [signature] over [signingInput] using [algorithm] and the given [key].
 *
 * Expected key types by algorithm family:
 * - HS256/384/512 → [HMAC.Key] (same key used for signing)
 * - RS256/384/512 → [RSA.PKCS1.PublicKey]
 * - PS256/384/512 → [RSA.PSS.PublicKey]
 * - ES256/384/512 → [ECDSA.PublicKey]
 * - None          → returns `true` only if [signature] is empty
 */
internal suspend fun <T : Key> jwsVerify(
    algorithm: JwsAlgorithm<T>,
    key: T,
    signingInput: ByteArray,
    signature: ByteArray,
): Boolean = try {
    when (algorithm) {
        JwsAlgorithm.HS256,
        JwsAlgorithm.HS384,
        JwsAlgorithm.HS512,
            -> {
            (key as HMAC.Key).signatureVerifier().verifySignature(signingInput, signature)
            true
        }

        JwsAlgorithm.RS256,
        JwsAlgorithm.RS384,
        JwsAlgorithm.RS512,
            -> {
            (key as RSA.PKCS1.PublicKey).signatureVerifier().verifySignature(signingInput, signature)
            true
        }

        JwsAlgorithm.PS256,
        JwsAlgorithm.PS384,
        JwsAlgorithm.PS512,
            -> {
            (key as RSA.PSS.PublicKey).signatureVerifier().verifySignature(signingInput, signature)
            true
        }

        JwsAlgorithm.ES256 -> {
            (key as ECDSA.PublicKey).signatureVerifier(SHA256, ECDSA.SignatureFormat.RAW)
                .verifySignature(signingInput, signature)
            true
        }

        JwsAlgorithm.ES384 -> {
            (key as ECDSA.PublicKey).signatureVerifier(SHA384, ECDSA.SignatureFormat.RAW)
                .verifySignature(signingInput, signature)
            true
        }

        JwsAlgorithm.ES512 -> {
            (key as ECDSA.PublicKey).signatureVerifier(SHA512, ECDSA.SignatureFormat.RAW)
                .verifySignature(signingInput, signature)
            true
        }

        JwsAlgorithm.None -> signature.isEmpty()
    }
} catch (_: Exception) {
    false
}
