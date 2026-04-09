package co.touchlab.kjwt.hardware.ext

import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import java.security.spec.ECGenParameterSpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec

public fun SigningAlgorithm.toJcaSignatureName(): String = when (this) {
    SigningAlgorithm.HS256 -> "HmacSHA256"
    SigningAlgorithm.HS384 -> "HmacSHA384"
    SigningAlgorithm.HS512 -> "HmacSHA512"
    SigningAlgorithm.RS256 -> "SHA256withRSA"
    SigningAlgorithm.RS384 -> "SHA384withRSA"
    SigningAlgorithm.RS512 -> "SHA512withRSA"
    SigningAlgorithm.PS256 -> "SHA256withRSA/PSS"
    SigningAlgorithm.PS384 -> "SHA384withRSA/PSS"
    SigningAlgorithm.PS512 -> "SHA512withRSA/PSS"
    SigningAlgorithm.ES256 -> "SHA256withECDSA"
    SigningAlgorithm.ES384 -> "SHA384withECDSA"
    SigningAlgorithm.ES512 -> "SHA512withECDSA"
    SigningAlgorithm.Ed25519 -> "Ed25519"
    SigningAlgorithm.Ed448 -> "Ed448"
    SigningAlgorithm.None -> error("Unsupported algorithm")
}

public fun SigningAlgorithm.PSSBased.toPSSParameterSpec(): PSSParameterSpec {
    val (digestName, saltLen) = when (this) {
        SigningAlgorithm.PS256 -> "SHA-256" to 32
        SigningAlgorithm.PS384 -> "SHA-384" to 48
        SigningAlgorithm.PS512 -> "SHA-512" to 64
    }
    return PSSParameterSpec(
        digestName,
        "MGF1",
        MGF1ParameterSpec(digestName),
        saltLen,
        1
    )
}

public val SigningAlgorithm.ECDSABased.algorithmParameterSpec: ECGenParameterSpec
    get() = ECGenParameterSpec(
        when (this) {
            SigningAlgorithm.ES256 -> "secp256r1"
            SigningAlgorithm.ES384 -> "secp384r1"
            SigningAlgorithm.ES512 -> "secp521r1"
        }
    )
