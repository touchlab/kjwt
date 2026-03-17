package co.touchlab.kjwt.ext

import co.touchlab.kjwt.builder.JwtBuilder
import co.touchlab.kjwt.cryptography.SimpleKey
import co.touchlab.kjwt.model.JwtInstance
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.EncryptionContentAlgorithm
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.EC
import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.algorithms.SHA384
import dev.whyoleg.cryptography.algorithms.SHA512

public suspend fun JwtBuilder.signWith(
    algorithm: SigningAlgorithm.HashBased,
    key: String,
    keyFormat: HMAC.Key.Format,
): JwtInstance.Jws {
    val parsedKey = CryptographyProvider.Default.get(HMAC)
        .keyDecoder(
            when (algorithm) {
                SigningAlgorithm.HS256 -> SHA256
                SigningAlgorithm.HS384 -> SHA384
                SigningAlgorithm.HS512 -> SHA512
            }
        )
        .decodeFromByteArray(keyFormat, key.encodeToByteArray())

    return signWith(algorithm, parsedKey)
}

public suspend fun JwtBuilder.signWith(
    algorithm: SigningAlgorithm.PKCS1Based,
    key: String,
    keyFormat: RSA.PrivateKey.Format,
): JwtInstance.Jws {
    val parsedKey = CryptographyProvider.Default.get(RSA.PKCS1)
        .privateKeyDecoder(
            when (algorithm) {
                SigningAlgorithm.RS256 -> SHA256
                SigningAlgorithm.RS384 -> SHA384
                SigningAlgorithm.RS512 -> SHA512
            }
        )
        .decodeFromByteArray(keyFormat, key.encodeToByteArray())

    return signWith(algorithm, parsedKey)
}

public suspend fun JwtBuilder.signWith(
    algorithm: SigningAlgorithm.PSSBased,
    key: String,
    keyFormat: RSA.PrivateKey.Format,
): JwtInstance.Jws {
    val parsedKey = CryptographyProvider.Default.get(RSA.PSS)
        .privateKeyDecoder(
            when (algorithm) {
                SigningAlgorithm.PS256 -> SHA256
                SigningAlgorithm.PS384 -> SHA384
                SigningAlgorithm.PS512 -> SHA512
            }
        )
        .decodeFromByteArray(keyFormat, key.encodeToByteArray())

    return signWith(algorithm, parsedKey)
}

public suspend fun JwtBuilder.signWith(
    algorithm: SigningAlgorithm.ECDSABased,
    key: String,
    keyFormat: EC.PrivateKey.Format,
): JwtInstance.Jws {
    val parsedKey = CryptographyProvider.Default.get(ECDSA)
        .privateKeyDecoder(
            when (algorithm) {
                SigningAlgorithm.ES256 -> EC.Curve.P256
                SigningAlgorithm.ES384 -> EC.Curve.P384
                SigningAlgorithm.ES512 -> EC.Curve.P521
            }
        )
        .decodeFromByteArray(keyFormat, key.encodeToByteArray())

    return signWith(algorithm, parsedKey)
}

public suspend fun JwtBuilder.encryptWith(
    key: ByteArray,
    keyAlgorithm: EncryptionAlgorithm.Dir,
    contentAlgorithm: EncryptionContentAlgorithm,
): JwtInstance.Jwe = encryptWith(SimpleKey(key), keyAlgorithm, contentAlgorithm)

public suspend fun JwtBuilder.encryptWith(
    key: String,
    keyAlgorithm: EncryptionAlgorithm.Dir,
    contentAlgorithm: EncryptionContentAlgorithm,
): JwtInstance.Jwe = encryptWith(key.encodeToByteArray(), keyAlgorithm, contentAlgorithm)
