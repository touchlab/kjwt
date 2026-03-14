package co.touchlab.kjwt.ext

import co.touchlab.kjwt.internal.JwtJson
import co.touchlab.kjwt.internal.decodeBase64Url
import co.touchlab.kjwt.internal.encodeBase64Url
import co.touchlab.kjwt.model.jwk.Jwk
import dev.whyoleg.cryptography.CryptographyAlgorithmId
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.Digest
import dev.whyoleg.cryptography.algorithms.EC
import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.algorithms.SHA384
import dev.whyoleg.cryptography.algorithms.SHA512
import dev.whyoleg.cryptography.bigint.decodeToBigInt
import dev.whyoleg.cryptography.serialization.asn1.BitArray
import dev.whyoleg.cryptography.serialization.asn1.Der
import dev.whyoleg.cryptography.serialization.asn1.ObjectIdentifier
import dev.whyoleg.cryptography.serialization.asn1.modules.EcKeyAlgorithmIdentifier
import dev.whyoleg.cryptography.serialization.asn1.modules.EcParameters
import dev.whyoleg.cryptography.serialization.asn1.modules.EcPrivateKey
import dev.whyoleg.cryptography.serialization.asn1.modules.PrivateKeyInfo
import dev.whyoleg.cryptography.serialization.asn1.modules.RsaKeyAlgorithmIdentifier
import dev.whyoleg.cryptography.serialization.asn1.modules.RsaPrivateKey
import dev.whyoleg.cryptography.serialization.asn1.modules.RsaPublicKey
import dev.whyoleg.cryptography.serialization.asn1.modules.SubjectPublicKeyInfo

suspend fun Jwk.Thumbprint.hashed(): String {
    val bytes = JwtJson.encodeToString(this).encodeToByteArray()
    val hash = CryptographyProvider.Default.get(SHA256).hasher().hash(bytes)
    return hash.encodeBase64Url()
}

// ---------------------------------------------------------------------------
// oct → HMAC
// ---------------------------------------------------------------------------

/**
 * Converts this [Jwk.Oct] to an [HMAC.Key] for the given [digest].
 */
suspend fun Jwk.Oct.toHmacKey(digest: CryptographyAlgorithmId<Digest>): HMAC.Key =
    CryptographyProvider.Default
        .get(HMAC)
        .keyDecoder(digest)
        .decodeFromByteArray(HMAC.Key.Format.RAW, k.decodeBase64Url())

// ---------------------------------------------------------------------------
// RSA → various RSA key types
// ---------------------------------------------------------------------------

/**
 * Converts a base64url-encoded unsigned big-endian integer (JWK "Base64urlUInt")
 * to a [dev.whyoleg.cryptography.bigint.BigInt] by treating it as a positive two's-complement value.
 */
private fun String.decodeJwkBigInt() =
    decodeBase64Url().let { bytes ->
        // DER INTEGER uses two's complement; prepend 0x00 to ensure positive if MSB is set
        if (bytes.isNotEmpty() && bytes[0].toInt() and 0x80 != 0) {
            (byteArrayOf(0x00) + bytes).decodeToBigInt()
        } else {
            bytes.decodeToBigInt()
        }
    }

private fun Jwk.Rsa.toSpkiDer(): ByteArray {
    val rsaPubKey = RsaPublicKey(
        modulus = n.decodeJwkBigInt(),
        publicExponent = e.decodeJwkBigInt(),
    )
    val spki = SubjectPublicKeyInfo(
        algorithm = RsaKeyAlgorithmIdentifier,
        subjectPublicKey = BitArray(0, Der.encodeToByteArray(RsaPublicKey.serializer(), rsaPubKey)),
    )
    return Der.encodeToByteArray(SubjectPublicKeyInfo.serializer(), spki)
}

private fun Jwk.Rsa.toPkcs8Der(): ByteArray {
    val d = requireNotNull(d) { "RSA private key requires 'd' parameter" }
    val p = requireNotNull(p) { "RSA private key requires 'p' parameter (CRT)" }
    val q = requireNotNull(q) { "RSA private key requires 'q' parameter (CRT)" }
    val dp = requireNotNull(dp) { "RSA private key requires 'dp' parameter (CRT)" }
    val dq = requireNotNull(dq) { "RSA private key requires 'dq' parameter (CRT)" }
    val qi = requireNotNull(qi) { "RSA private key requires 'qi' parameter (CRT)" }
    val rsaPrivKey = RsaPrivateKey(
        version = 0,
        modulus = n.decodeJwkBigInt(),
        publicExponent = e.decodeJwkBigInt(),
        privateExponent = d.decodeJwkBigInt(),
        prime1 = p.decodeJwkBigInt(),
        prime2 = q.decodeJwkBigInt(),
        exponent1 = dp.decodeJwkBigInt(),
        exponent2 = dq.decodeJwkBigInt(),
        coefficient = qi.decodeJwkBigInt(),
    )
    val pkcs8 = PrivateKeyInfo(
        version = 0,
        privateKeyAlgorithm = RsaKeyAlgorithmIdentifier,
        privateKey = Der.encodeToByteArray(RsaPrivateKey.serializer(), rsaPrivKey),
    )
    return Der.encodeToByteArray(PrivateKeyInfo.serializer(), pkcs8)
}

/** Converts to [RSA.PKCS1.PublicKey] for RS256/RS384/RS512 verification. */
suspend fun Jwk.Rsa.toRsaPkcs1PublicKey(digest: CryptographyAlgorithmId<Digest>): RSA.PKCS1.PublicKey =
    CryptographyProvider.Default
        .get(RSA.PKCS1)
        .publicKeyDecoder(digest)
        .decodeFromByteArray(RSA.PublicKey.Format.DER, toSpkiDer())

/** Converts to [RSA.PKCS1.PrivateKey] for RS256/RS384/RS512 signing. */
suspend fun Jwk.Rsa.toRsaPkcs1PrivateKey(digest: CryptographyAlgorithmId<Digest>): RSA.PKCS1.PrivateKey =
    CryptographyProvider.Default
        .get(RSA.PKCS1)
        .privateKeyDecoder(digest)
        .decodeFromByteArray(RSA.PrivateKey.Format.DER, toPkcs8Der())

/** Converts to [RSA.PSS.PublicKey] for PS256/PS384/PS512 verification. */
suspend fun Jwk.Rsa.toRsaPssPublicKey(digest: CryptographyAlgorithmId<Digest>): RSA.PSS.PublicKey =
    CryptographyProvider.Default
        .get(RSA.PSS)
        .publicKeyDecoder(digest)
        .decodeFromByteArray(RSA.PublicKey.Format.DER, toSpkiDer())

/** Converts to [RSA.PSS.PrivateKey] for PS256/PS384/PS512 signing. */
suspend fun Jwk.Rsa.toRsaPssPrivateKey(digest: CryptographyAlgorithmId<Digest>): RSA.PSS.PrivateKey =
    CryptographyProvider.Default
        .get(RSA.PSS)
        .privateKeyDecoder(digest)
        .decodeFromByteArray(RSA.PrivateKey.Format.DER, toPkcs8Der())

/** Converts to [RSA.OAEP.PublicKey] for RSA-OAEP / RSA-OAEP-256 key encryption. */
@OptIn(dev.whyoleg.cryptography.DelicateCryptographyApi::class)
suspend fun Jwk.Rsa.toRsaOaepPublicKey(digest: CryptographyAlgorithmId<Digest>): RSA.OAEP.PublicKey =
    CryptographyProvider.Default
        .get(RSA.OAEP)
        .publicKeyDecoder(digest)
        .decodeFromByteArray(RSA.PublicKey.Format.DER, toSpkiDer())

/** Converts to [RSA.OAEP.PrivateKey] for RSA-OAEP / RSA-OAEP-256 key decryption. */
@OptIn(dev.whyoleg.cryptography.DelicateCryptographyApi::class)
suspend fun Jwk.Rsa.toRsaOaepPrivateKey(digest: CryptographyAlgorithmId<Digest>): RSA.OAEP.PrivateKey =
    CryptographyProvider.Default
        .get(RSA.OAEP)
        .privateKeyDecoder(digest)
        .decodeFromByteArray(RSA.PrivateKey.Format.DER, toPkcs8Der())

// ---------------------------------------------------------------------------
// EC → ECDSA
// ---------------------------------------------------------------------------

private fun ecCurveOid(crv: String): ObjectIdentifier = when (crv) {
    "P-256" -> ObjectIdentifier("1.2.840.10045.3.1.7")
    "P-384" -> ObjectIdentifier("1.3.132.0.34")
    "P-521" -> ObjectIdentifier("1.3.132.0.35")
    else -> error("Unsupported EC curve: '$crv'")
}

private fun ecCurve(crv: String): EC.Curve = when (crv) {
    "P-256" -> EC.Curve.P256
    "P-384" -> EC.Curve.P384
    "P-521" -> EC.Curve.P521
    else -> error("Unsupported EC curve: '$crv'")
}

private fun ecCoordSize(crv: String): Int = when (crv) {
    "P-256" -> 32
    "P-384" -> 48
    "P-521" -> 66
    else -> error("Unsupported EC curve: '$crv'")
}

private fun ByteArray.padToLength(length: Int): ByteArray = when {
    size == length -> this
    size < length -> ByteArray(length - size) + this
    else -> copyOfRange(size - length, size)
}

private fun Jwk.Ec.toSpkiDer(): ByteArray {
    val coordSize = ecCoordSize(crv)
    val point = byteArrayOf(0x04) +
        x.decodeBase64Url().padToLength(coordSize) +
        y.decodeBase64Url().padToLength(coordSize)
    val spki = SubjectPublicKeyInfo(
        algorithm = EcKeyAlgorithmIdentifier(EcParameters(ecCurveOid(crv))),
        subjectPublicKey = BitArray(0, point),
    )
    return Der.encodeToByteArray(SubjectPublicKeyInfo.serializer(), spki)
}

private fun Jwk.Ec.toPkcs8Der(): ByteArray {
    val d = requireNotNull(d) { "EC private key requires 'd' parameter" }
    val coordSize = ecCoordSize(crv)
    val point = byteArrayOf(0x04) +
        x.decodeBase64Url().padToLength(coordSize) +
        y.decodeBase64Url().padToLength(coordSize)
    val ecPrivKey = EcPrivateKey(
        version = 1,
        privateKey = d.decodeBase64Url().padToLength(coordSize),
        publicKey = BitArray(0, point),
    )
    val pkcs8 = PrivateKeyInfo(
        version = 0,
        privateKeyAlgorithm = EcKeyAlgorithmIdentifier(EcParameters(ecCurveOid(crv))),
        privateKey = Der.encodeToByteArray(EcPrivateKey.serializer(), ecPrivKey),
    )
    return Der.encodeToByteArray(PrivateKeyInfo.serializer(), pkcs8)
}

/** Converts to [ECDSA.PublicKey] for ES256/ES384/ES512 verification. */
suspend fun Jwk.Ec.toEcdsaPublicKey(): ECDSA.PublicKey =
    CryptographyProvider.Default
        .get(ECDSA)
        .publicKeyDecoder(ecCurve(crv))
        .decodeFromByteArray(EC.PublicKey.Format.DER, toSpkiDer())

/** Converts to [ECDSA.PrivateKey] for ES256/ES384/ES512 signing. */
suspend fun Jwk.Ec.toEcdsaPrivateKey(): ECDSA.PrivateKey =
    CryptographyProvider.Default
        .get(ECDSA)
        .privateKeyDecoder(ecCurve(crv))
        .decodeFromByteArray(EC.PrivateKey.Format.DER, toPkcs8Der())

// ---------------------------------------------------------------------------
// Digest helpers
// ---------------------------------------------------------------------------

/**
 * Returns the SHA digest implied by the JWK's [Jwk.alg] field, or null if absent/unrecognised.
 */
fun Jwk.impliedDigest(): CryptographyAlgorithmId<Digest>? = when (alg) {
    "HS256", "RS256", "PS256", "ES256", "RSA-OAEP-256" -> SHA256
    "HS384", "RS384", "PS384", "ES384" -> SHA384
    "HS512", "RS512", "PS512", "ES512" -> SHA512
    else -> null
}
