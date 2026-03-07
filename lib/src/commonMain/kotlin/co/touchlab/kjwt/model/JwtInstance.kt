package co.touchlab.kjwt.model

sealed class JwtInstance<P : JwtPayload> {
    abstract val header: JwtHeader
    abstract val payload: P

    data class Jwe<P : JwtPayload>(
        override val header: JwtHeader.Jwe,
        override val payload: P,
    ) : JwtInstance<P>()

    data class Jws<P : JwtPayload>(
        override val header: JwtHeader.Jws,
        override val payload: P,
        val signature: ByteArray,
    ) : JwtInstance<P>() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Jws<*>) return false
            return header == other.header && payload == other.payload && signature.contentEquals(other.signature)
        }

        override fun hashCode(): Int {
            var result = header.hashCode()
            result = 31 * result + payload.hashCode()
            result = 31 * result + signature.contentHashCode()
            return result
        }
    }
}