package co.touchlab.kjwt.cryptography

import co.touchlab.kjwt.annotations.InternalKJWTApi
import co.touchlab.kjwt.model.algorithm.JwtCurve
import co.touchlab.kjwt.model.algorithm.JwtDigest
import dev.whyoleg.cryptography.CryptographyAlgorithmId
import dev.whyoleg.cryptography.DelicateCryptographyApi
import dev.whyoleg.cryptography.algorithms.Digest
import dev.whyoleg.cryptography.algorithms.EC
import dev.whyoleg.cryptography.algorithms.SHA1
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.algorithms.SHA384
import dev.whyoleg.cryptography.algorithms.SHA512

@OptIn(DelicateCryptographyApi::class)
@InternalKJWTApi
public fun JwtDigest.toCryptographyKotlin(): CryptographyAlgorithmId<Digest> =
    when (this) {
        JwtDigest.SHA1 -> SHA1
        JwtDigest.SHA256 -> SHA256
        JwtDigest.SHA384 -> SHA384
        JwtDigest.SHA512 -> SHA512
    }

public fun JwtCurve.toCryptographyKotlin(): EC.Curve =
    when (this) {
        JwtCurve.P256 -> EC.Curve.P256
        JwtCurve.P384 -> EC.Curve.P384
        JwtCurve.P521 -> EC.Curve.P521
    }
