package co.touchlab.kjwt.model

data class Jws<P>(
    val header: JwsHeader,
    val payload: P,
    val signature: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Jws<*>) return false
        return header == other.header && payload == other.payload && signature.contentEquals(other.signature)
    }

    override fun hashCode(): Int {
        var result = header.hashCode()
        result = 31 * result + (payload?.hashCode() ?: 0)
        result = 31 * result + signature.contentHashCode()
        return result
    }
}