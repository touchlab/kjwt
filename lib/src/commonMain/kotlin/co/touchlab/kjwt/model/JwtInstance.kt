package co.touchlab.kjwt.model

import co.touchlab.kjwt.internal.JwtJson

sealed class JwtInstance {
    abstract val header: JwtHeader
    abstract val payload: JwtPayload

    abstract fun compact(): String

    override fun toString(): String = compact()

    inline fun <reified T> getPayload(): T =
        JwtJson.decodeFromJsonElement(kotlinx.serialization.serializer<T>(), payload.jsonData)

    class Jwe internal constructor(
        override val header: JwtHeader,
        override val payload: JwtPayload,
        val encryptedKey: String,
        val iv: String,
        val cipherText: String,
        val tag: String,
    ) : JwtInstance() {
        // All strings are Base64 URLEncoded
        internal constructor(
            headerB64: String,
            payloadB64: String,
            encryptedKey: String,
            iv: String,
            cipherText: String,
            tag: String,
        ) : this(
            header = JwtHeader(headerB64),
            payload = JwtPayload(payloadB64),
            encryptedKey = encryptedKey,
            iv = iv,
            cipherText = cipherText,
            tag = tag,
        )

        val aad: String
            get() = header.base64Encoded

        override fun compact(): String = buildString {
            append(aad)
            append('.')
            append(encryptedKey)
            append('.')
            append(iv)
            append('.')
            append(cipherText)
            append('.')
            append(tag)
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as Jwe

            if (header != other.header) return false
            if (payload != other.payload) return false
            if (encryptedKey != other.encryptedKey) return false
            if (iv != other.iv) return false
            if (cipherText != other.cipherText) return false
            if (tag != other.tag) return false

            return true
        }

        override fun hashCode(): Int {
            var result = header.hashCode()
            result = 31 * result + payload.hashCode()
            result = 31 * result + encryptedKey.hashCode()
            result = 31 * result + iv.hashCode()
            result = 31 * result + cipherText.hashCode()
            result = 31 * result + tag.hashCode()
            return result
        }
    }

    class Jws internal constructor(
        override val payload: JwtPayload,
        val signatures: List<Signature>,
    ) : JwtInstance() {
        internal constructor(
            header: JwtHeader,
            payload: JwtPayload,
            signature: String
        ) : this(
            payload = payload,
            signatures = listOf(Signature(header, signature)),
        )

        internal constructor(
            headerB64: String, // Base64 URLEncoded
            payloadB64: String, // Base64 URLEncoded
            signature: String,
        ) : this(
            header = JwtHeader(headerB64),
            payload = JwtPayload(payloadB64),
            signature = signature,
        )

        override val header: JwtHeader
            get() = signatures.first().header

        val signature: String
            get() = signatures.first().signature

        override fun compact(): String =
            "$header.$payload.$signature"

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as Jws

            if (payload != other.payload) return false
            if (!signatures.containsAll(other.signatures)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = header.hashCode()
            result = 31 * result + payload.hashCode()
            result = 31 * result + signature.hashCode()
            return result
        }

        class Signature(
            val header: JwtHeader,
            val signature: String,
        )
    }
}
