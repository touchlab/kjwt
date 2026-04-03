package co.touchlab.kjwt.model.algorithm

/**
 * Holds the raw byte outputs produced by a JWE content encryption operation.
 *
 * Instances are created by [co.touchlab.kjwt.processor.JweProcessor] implementations and
 * consumed by [co.touchlab.kjwt.builder.JwtBuilder] to assemble the five-part JWE compact
 * serialization per RFC 7516.
 */
public class JweEncryptResult(
    /** The encrypted Content Encryption Key (CEK) bytes; may be empty for `dir` key management. */
    public val encryptedKey: ByteArray,
    /** The initialization vector bytes used during content encryption. */
    public val iv: ByteArray,
    /** The ciphertext bytes produced by content encryption. */
    public val ciphertext: ByteArray,
    /** The authentication tag bytes produced by content encryption. */
    public val tag: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JweEncryptResult

        if (!encryptedKey.contentEquals(other.encryptedKey)) return false
        if (!iv.contentEquals(other.iv)) return false
        if (!ciphertext.contentEquals(other.ciphertext)) return false
        if (!tag.contentEquals(other.tag)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = encryptedKey.contentHashCode()
        result = 31 * result + iv.contentHashCode()
        result = 31 * result + ciphertext.contentHashCode()
        result = 31 * result + tag.contentHashCode()
        return result
    }

    override fun toString(): String =
        "JweEncryptResult(" +
            "encryptedKey=${encryptedKey.contentToString()}, " +
            "iv=${iv.contentToString()}, " +
            "ciphertext=${ciphertext.contentToString()}, " +
            "tag=${tag.contentToString()}" +
            ")"
}
