package co.touchlab.kjwt.ext

import co.touchlab.kjwt.algorithm.JweContentAlgorithm
import co.touchlab.kjwt.algorithm.JweKeyAlgorithm
import co.touchlab.kjwt.algorithm.JwsAlgorithm
import co.touchlab.kjwt.builder.JwtBuilder
import co.touchlab.kjwt.cryptography.SimpleKey
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.EC
import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.algorithms.SHA384
import dev.whyoleg.cryptography.algorithms.SHA512

suspend fun JwtBuilder.signWith(
    algorithm: JwsAlgorithm.HashBased,
    key: String,
    keyFormat: HMAC.Key.Format,
): String {
    val parsedKey = CryptographyProvider.Default.get(HMAC)
        .keyDecoder(
            when (algorithm) {
                JwsAlgorithm.HS256 -> SHA256
                JwsAlgorithm.HS384 -> SHA384
                JwsAlgorithm.HS512 -> SHA512
            }
        )
        .decodeFromByteArray(keyFormat, key.encodeToByteArray())

    return signWith(algorithm, parsedKey)
}

suspend fun JwtBuilder.signWith(
    algorithm: JwsAlgorithm.PKCS1Based,
    key: String,
    keyFormat: RSA.PrivateKey.Format,
): String {
    val parsedKey = CryptographyProvider.Default.get(RSA.PKCS1)
        .privateKeyDecoder(
            when (algorithm) {
                JwsAlgorithm.RS256 -> SHA256
                JwsAlgorithm.RS384 -> SHA384
                JwsAlgorithm.RS512 -> SHA512
            }
        )
        .decodeFromByteArray(keyFormat, key.encodeToByteArray())

    return signWith(algorithm, parsedKey)
}

suspend fun JwtBuilder.signWith(
    algorithm: JwsAlgorithm.PSSBased,
    key: String,
    keyFormat: RSA.PrivateKey.Format,
): String {
    val parsedKey = CryptographyProvider.Default.get(RSA.PSS)
        .privateKeyDecoder(
            when (algorithm) {
                JwsAlgorithm.PS256 -> SHA256
                JwsAlgorithm.PS384 -> SHA384
                JwsAlgorithm.PS512 -> SHA512
            }
        )
        .decodeFromByteArray(keyFormat, key.encodeToByteArray())

    return signWith(algorithm, parsedKey)
}

suspend fun JwtBuilder.signWith(
    algorithm: JwsAlgorithm.ECDSABased,
    key: String,
    keyFormat: EC.PrivateKey.Format,
): String {
    val parsedKey = CryptographyProvider.Default.get(ECDSA)
        .privateKeyDecoder(
            when (algorithm) {
                JwsAlgorithm.ES256 -> EC.Curve.P256
                JwsAlgorithm.ES384 -> EC.Curve.P384
                JwsAlgorithm.ES512 -> EC.Curve.P521
            }
        )
        .decodeFromByteArray(keyFormat, key.encodeToByteArray())

    return signWith(algorithm, parsedKey)
}

suspend fun JwtBuilder.encryptWith(
    key: ByteArray,
    keyAlgorithm: JweKeyAlgorithm.Dir,
    contentAlgorithm: JweContentAlgorithm,
): String = encryptWith(SimpleKey(key), keyAlgorithm, contentAlgorithm)

suspend fun JwtBuilder.encryptWith(
    key: String,
    keyAlgorithm: JweKeyAlgorithm.Dir,
    contentAlgorithm: JweContentAlgorithm,
): String = encryptWith(key.encodeToByteArray(), keyAlgorithm, contentAlgorithm)