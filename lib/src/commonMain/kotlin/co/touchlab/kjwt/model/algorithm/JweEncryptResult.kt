package co.touchlab.kjwt.model.algorithm

public class JweEncryptResult(
    public val encryptedKey: ByteArray,
    public val iv: ByteArray,
    public val ciphertext: ByteArray,
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
