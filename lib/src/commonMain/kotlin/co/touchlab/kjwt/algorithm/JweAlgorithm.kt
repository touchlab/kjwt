package co.touchlab.kjwt.algorithm

import kotlin.jvm.JvmStatic

sealed class JweKeyAlgorithm(val id: String) {
    /** Direct use of a shared symmetric CEK — no key wrapping. */
    data object Dir : JweKeyAlgorithm("dir")

    /**
     * RSA-OAEP with SHA-1.
     * Key must be created with `RSA.OAEP.keyPairGenerator(SHA1)` or equivalent.
     */
    data object RsaOaep : JweKeyAlgorithm("RSA-OAEP")

    /**
     * RSA-OAEP with SHA-256.
     * Key must be created with `RSA.OAEP.keyPairGenerator(SHA256)` or equivalent.
     */
    data object RsaOaep256 : JweKeyAlgorithm("RSA-OAEP-256")

    override fun toString(): String = id

    companion object {
        private val all = listOf(Dir, RsaOaep, RsaOaep256)

        fun fromId(id: String): JweKeyAlgorithm =
            all.firstOrNull { it.id == id }
                ?: throw IllegalArgumentException("Unknown JWE key algorithm: '$id'")
    }
}

sealed class JweContentAlgorithm(val id: String) {
    data object A128GCM : JweContentAlgorithm("A128GCM")
    data object A192GCM : JweContentAlgorithm("A192GCM")
    data object A256GCM : JweContentAlgorithm("A256GCM")

    data object A128CbcHs256 : JweContentAlgorithm("A128CBC-HS256")
    data object A192CbcHs384 : JweContentAlgorithm("A192CBC-HS384")
    data object A256CbcHs512 : JweContentAlgorithm("A256CBC-HS512")

    override fun toString(): String = id

    companion object {
        @JvmStatic
        private val entries: List<JweContentAlgorithm> by lazy {
            listOf(
                A128GCM, A192GCM, A256GCM,
                A128CbcHs256, A192CbcHs384, A256CbcHs512,
            )
        }

        @JvmStatic
        fun fromId(id: String): JweContentAlgorithm =
            entries.firstOrNull { it.id == id }
                ?: throw IllegalArgumentException("Unknown JWE content algorithm: '$id'")
    }
}
