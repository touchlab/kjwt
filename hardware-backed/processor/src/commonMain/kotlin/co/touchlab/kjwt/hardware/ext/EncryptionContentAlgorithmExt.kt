package co.touchlab.kjwt.hardware.ext

import co.touchlab.kjwt.model.algorithm.EncryptionContentAlgorithm

public fun EncryptionContentAlgorithm.generateCek(
    generateRandomBytes: (Int) -> ByteArray,
): ByteArray = generateRandomBytes(
    when (this) {
        EncryptionContentAlgorithm.A128GCM -> 16
        EncryptionContentAlgorithm.A192GCM -> 24
        EncryptionContentAlgorithm.A256GCM -> 32
        EncryptionContentAlgorithm.A128CbcHs256 -> 32
        EncryptionContentAlgorithm.A192CbcHs384 -> 48
        EncryptionContentAlgorithm.A256CbcHs512 -> 64
    }
)
