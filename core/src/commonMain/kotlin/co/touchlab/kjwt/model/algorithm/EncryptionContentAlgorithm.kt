package co.touchlab.kjwt.model.algorithm

/**
 * Sealed class representing the JWE content encryption algorithms defined in RFC 7518 §5.
 *
 * The content encryption algorithm determines how the plaintext payload is encrypted and
 * integrity-protected inside the JWE compact serialization. The supported algorithms are:
 * - [AesGCMBased] — AES in GCM mode ([A128GCM], [A192GCM], [A256GCM]).
 * - [AesCBCBased] — AES in CBC mode combined with HMAC ([A128CbcHs256], [A192CbcHs384], [A256CbcHs512]).
 *
 * Use [fromId] to look up an instance by its JWA identifier string.
 *
 * @see EncryptionAlgorithm
 */
public sealed class EncryptionContentAlgorithm(
    /** The JWA content encryption algorithm identifier string (e.g. `"A256GCM"`). */
    public val id: String,
) {
    /** AES-128 in GCM mode (`A128GCM`) content encryption algorithm. */
    public data object A128GCM : AesGCMBased("A128GCM")

    /** AES-192 in GCM mode (`A192GCM`) content encryption algorithm. */
    public data object A192GCM : AesGCMBased("A192GCM")

    /** AES-256 in GCM mode (`A256GCM`) content encryption algorithm. */
    public data object A256GCM : AesGCMBased("A256GCM")

    /** AES-128 CBC with HMAC-SHA-256 (`A128CBC-HS256`) content encryption algorithm. */
    public data object A128CbcHs256 : AesCBCBased("A128CBC-HS256")

    /** AES-192 CBC with HMAC-SHA-384 (`A192CBC-HS384`) content encryption algorithm. */
    public data object A192CbcHs384 : AesCBCBased("A192CBC-HS384")

    /** AES-256 CBC with HMAC-SHA-512 (`A256CBC-HS512`) content encryption algorithm. */
    public data object A256CbcHs512 : AesCBCBased("A256CBC-HS512")

    /**
     * Base class for AES GCM content encryption algorithms (A128GCM, A192GCM, A256GCM).
     *
     * Uses AES in Galois/Counter Mode, which provides both confidentiality and integrity.
     */
    public sealed class AesGCMBased(id: String) : EncryptionContentAlgorithm(id)

    /**
     * Base class for AES CBC + HMAC content encryption algorithms (A128CBC-HS256, A192CBC-HS384, A256CBC-HS512).
     *
     * Uses AES in CBC mode combined with an HMAC tag for authenticated encryption per RFC 7516.
     */
    public sealed class AesCBCBased(id: String) : EncryptionContentAlgorithm(id)

    override fun toString(): String = id

    public companion object {
        /**
         * List of all supported [EncryptionContentAlgorithm] instances.
         */
        internal val entries: List<EncryptionContentAlgorithm> by lazy {
            listOf(
                A128GCM,
                A192GCM,
                A256GCM,
                A128CbcHs256,
                A192CbcHs384,
                A256CbcHs512,
            )
        }

        /**
         * Returns the [EncryptionContentAlgorithm] whose [id] matches the given string.
         *
         * @param id the JWE content algorithm identifier to look up (e.g. `"A256GCM"`)
         * @return the matching [EncryptionContentAlgorithm] instance
         * @throws IllegalArgumentException if no algorithm with the given [id] is registered
         */
        public fun fromId(id: String): EncryptionContentAlgorithm =
            requireNotNull(entries.firstOrNull { it.id == id }) {
                "Unknown JWE content algorithm: '$id'"
            }
    }
}
