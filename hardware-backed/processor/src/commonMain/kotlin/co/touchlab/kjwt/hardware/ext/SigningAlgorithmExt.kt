package co.touchlab.kjwt.hardware.ext

import co.touchlab.kjwt.model.algorithm.SigningAlgorithm

public val SigningAlgorithm.ECDSABased.coordLen: Int
    get() = when (this) {
        SigningAlgorithm.ES256 -> 32
        SigningAlgorithm.ES384 -> 48
        SigningAlgorithm.ES512 -> 66 // P-521 is 521 bits = 66 bytes
    }
