package co.touchlab.kjwt

import co.touchlab.kjwt.cryptography.SimpleKey
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.algorithms.EC
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.algorithms.SHA1
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.algorithms.SHA384
import dev.whyoleg.cryptography.algorithms.SHA512
import dev.whyoleg.cryptography.algorithms.Digest
import dev.whyoleg.cryptography.CryptographyAlgorithmId
import co.touchlab.kjwt.exception.JwtException
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.random.Random
import kotlin.test.assertFailsWith

val provider: CryptographyProvider get() = CryptographyProvider.Default

// ---- HMAC keys ----

val hs256Secret = "a-string-secret-at-least-256-bits-long".encodeToByteArray()
val hs384Secret = "a-string-secret-at-least-384-bits-long-padding-extra".encodeToByteArray()
val hs512Secret = "a-string-secret-at-least-512-bits-long-padding-extra-bytes-here-ok".encodeToByteArray()

suspend fun hmacKey(digest: CryptographyAlgorithmId<Digest>, secret: ByteArray): HMAC.Key =
    provider.get(HMAC).keyDecoder(digest).decodeFromByteArray(HMAC.Key.Format.RAW, secret)

suspend fun hs256Key(): HMAC.Key = hmacKey(SHA256, hs256Secret)
suspend fun hs384Key(): HMAC.Key = hmacKey(SHA384, hs384Secret)
suspend fun hs512Key(): HMAC.Key = hmacKey(SHA512, hs512Secret)

// ---- RSA PKCS1 ----

suspend fun rsaPkcs1KeyPair(digest: CryptographyAlgorithmId<Digest> = SHA256): RSA.PKCS1.KeyPair =
    provider.get(RSA.PKCS1).keyPairGenerator(digest = digest).generateKey()

// ---- RSA PSS ----

suspend fun rsaPssKeyPair(digest: CryptographyAlgorithmId<Digest> = SHA256): RSA.PSS.KeyPair =
    provider.get(RSA.PSS).keyPairGenerator(digest = digest).generateKey()

// ---- ECDSA ----

suspend fun ecKeyPair(curve: EC.Curve = EC.Curve.P256): ECDSA.KeyPair =
    provider.get(ECDSA).keyPairGenerator(curve).generateKey()

// ---- RSA OAEP (for JWE) ----

@OptIn(dev.whyoleg.cryptography.DelicateCryptographyApi::class)
suspend fun rsaOaepKeyPair(digest: CryptographyAlgorithmId<Digest> = SHA1): RSA.OAEP.KeyPair =
    provider.get(RSA.OAEP).keyPairGenerator(digest = digest).generateKey()

@OptIn(dev.whyoleg.cryptography.DelicateCryptographyApi::class)
suspend fun rsaOaep256KeyPair(): RSA.OAEP.KeyPair =
    provider.get(RSA.OAEP).keyPairGenerator(digest = SHA256).generateKey()

// ---- AES key bytes for JWE Dir ----

fun aesSimpleKey(bits: Int): SimpleKey =
    SimpleKey(Random.Default.nextBytes(bits / 8))

// ---- Token helpers ----

/** Decodes the payload (middle) part of a compact JWT and returns it as a JSON string. */
@OptIn(ExperimentalEncodingApi::class)
fun decodeTokenPayload(token: String): String {
    val part = token.split('.')[1]
    val padded = when (val rem = part.length % 4) {
        0 -> part
        else -> part + "=".repeat(4 - rem)
    }
    return Base64.UrlSafe.decode(padded).decodeToString()
}

/** Decodes the header (first) part of a compact JWT and returns it as a JSON string. */
@OptIn(ExperimentalEncodingApi::class)
fun decodeTokenHeader(token: String): String {
    val part = token.split('.')[0]
    val padded = when (val rem = part.length % 4) {
        0 -> part
        else -> part + "=".repeat(4 - rem)
    }
    return Base64.UrlSafe.decode(padded).decodeToString()
}

/** Decodes a raw base64url segment to bytes (used for IV/tag length checks). */
@OptIn(ExperimentalEncodingApi::class)
fun decodeBase64Url(segment: String): ByteArray {
    val padded = when (val rem = segment.length % 4) {
        0 -> segment
        else -> segment + "=".repeat(4 - rem)
    }
    return Base64.UrlSafe.decode(padded)
}

// ---- Assertion helpers ----

inline fun <reified T : JwtException> assertThrowsJwt(block: () -> Unit): T =
    assertFailsWith<T>(block = block)
