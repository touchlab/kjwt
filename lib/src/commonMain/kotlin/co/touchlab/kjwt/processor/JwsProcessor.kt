package co.touchlab.kjwt.processor

import co.touchlab.kjwt.model.algorithm.SigningAlgorithm

public interface JwsProcessor : Signer, Verifier {
    public val algorithm: SigningAlgorithm
}

public fun interface Signer {
    public suspend fun sign(data: ByteArray): ByteArray
}

public fun interface Verifier {
    public suspend fun verify(data: ByteArray, signature: ByteArray): Boolean
}
