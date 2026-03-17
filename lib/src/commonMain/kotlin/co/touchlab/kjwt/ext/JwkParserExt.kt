package co.touchlab.kjwt.ext

import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import co.touchlab.kjwt.model.jwk.Jwk
import co.touchlab.kjwt.parser.JwtParserBuilder
import dev.whyoleg.cryptography.algorithms.SHA1
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.algorithms.SHA384
import dev.whyoleg.cryptography.algorithms.SHA512

// ---------------------------------------------------------------------------
// verifyWith — HMAC (oct)
// ---------------------------------------------------------------------------

public suspend fun JwtParserBuilder.verifyWith(algorithm: SigningAlgorithm.HashBased, jwk: Jwk.Oct): JwtParserBuilder {
    val digest = when (algorithm) {
        SigningAlgorithm.HS256 -> SHA256
        SigningAlgorithm.HS384 -> SHA384
        SigningAlgorithm.HS512 -> SHA512
    }
    return verifyWith(algorithm, jwk.toHmacKey(digest))
}

// ---------------------------------------------------------------------------
// verifyWith — RSA PKCS1 (RS*)
// ---------------------------------------------------------------------------

public suspend fun JwtParserBuilder.verifyWith(algorithm: SigningAlgorithm.PKCS1Based, jwk: Jwk.Rsa): JwtParserBuilder {
    val digest = when (algorithm) {
        SigningAlgorithm.RS256 -> SHA256
        SigningAlgorithm.RS384 -> SHA384
        SigningAlgorithm.RS512 -> SHA512
    }
    return verifyWith(algorithm, jwk.toRsaPkcs1PublicKey(digest))
}

// ---------------------------------------------------------------------------
// verifyWith — RSA PSS (PS*)
// ---------------------------------------------------------------------------

public suspend fun JwtParserBuilder.verifyWith(algorithm: SigningAlgorithm.PSSBased, jwk: Jwk.Rsa): JwtParserBuilder {
    val digest = when (algorithm) {
        SigningAlgorithm.PS256 -> SHA256
        SigningAlgorithm.PS384 -> SHA384
        SigningAlgorithm.PS512 -> SHA512
    }
    return verifyWith(algorithm, jwk.toRsaPssPublicKey(digest))
}

// ---------------------------------------------------------------------------
// verifyWith — ECDSA (ES*)
// ---------------------------------------------------------------------------

public suspend fun JwtParserBuilder.verifyWith(algorithm: SigningAlgorithm.ECDSABased, jwk: Jwk.Ec): JwtParserBuilder =
    verifyWith(algorithm, jwk.toEcdsaPublicKey())

// ---------------------------------------------------------------------------
// decryptWith — RSA-OAEP / RSA-OAEP-256
// ---------------------------------------------------------------------------

@OptIn(dev.whyoleg.cryptography.DelicateCryptographyApi::class)
public suspend fun JwtParserBuilder.decryptWith(
    algorithm: EncryptionAlgorithm.OAEPBased,
    jwk: Jwk.Rsa,
): JwtParserBuilder {
    val digest = when (algorithm) {
        EncryptionAlgorithm.RsaOaep -> SHA1
        EncryptionAlgorithm.RsaOaep256 -> SHA256
    }
    return decryptWith(algorithm, jwk.toRsaOaepPrivateKey(digest))
}
