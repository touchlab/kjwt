package co.touchlab.kjwt.hardware.ext

import android.security.keystore.KeyProperties
import co.touchlab.kjwt.model.algorithm.JwtDigest

public val JwtDigest.asKeyPropertiesDigest: String
    get() = when (this) {
        JwtDigest.SHA1 -> KeyProperties.DIGEST_SHA1
        JwtDigest.SHA256 -> KeyProperties.DIGEST_SHA256
        JwtDigest.SHA384 -> KeyProperties.DIGEST_SHA384
        JwtDigest.SHA512 -> KeyProperties.DIGEST_SHA512
    }
