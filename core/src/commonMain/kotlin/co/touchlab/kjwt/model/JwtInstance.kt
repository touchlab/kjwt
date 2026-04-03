package co.touchlab.kjwt.model

import co.touchlab.kjwt.Jwt
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json

/**
 * Sealed base class for a parsed or constructed JWT token instance.
 *
 * The two concrete variants correspond to the two main JWT token types defined in the JOSE
 * specifications:
 * - [Jws] — a signed token (JWS, RFC 7515) with three compact-serialization parts:
 *   `header.payload.signature`.
 * - [Jwe] — an encrypted token (JWE, RFC 7516) with five compact-serialization parts:
 *   `header.encryptedKey.iv.ciphertext.tag`.
 *
 * Use [compact] to obtain the compact-serialized string, or [getPayload] / [getHeader] to
 * deserialize the payload or header into a typed object.
 *
 * @see co.touchlab.kjwt.builder.JwtBuilder
 * @see co.touchlab.kjwt.parser.JwtParser
 */
public sealed class JwtInstance {
    /** The JOSE header of the token. */
    public abstract val header: JwtHeader

    /** The payload (claims set) of the token. */
    public abstract val payload: JwtPayload

    /**
     * Returns the compact serialization of this token.
     *
     * @return the compact token string
     */
    public abstract fun compact(): String

    override fun toString(): String = compact()

    /**
     * Deserializes the token payload as type [T].
     *
     * @param T the target type to deserialize the payload into
     * @param jsonInstance the [Json] instance to use for deserialization; defaults to the library's
     *   [Jwt.defaultJsonParser] configuration (`ignoreUnknownKeys = true`, `explicitNulls = false`)
     * @return the payload deserialized into an instance of [T]
     */
    public inline fun <reified T> getPayload(jsonInstance: Json = Jwt.defaultJsonParser): T =
        getPayload(kotlinx.serialization.serializer<T>(), jsonInstance)

    /**
     * Deserializes the token payload using the given [serializer].
     *
     * @param T the target type to deserialize the payload into
     * @param serializer the [KSerializer] used to deserialize the payload
     * @param jsonInstance the [Json] instance to use for deserialization; defaults to the library's
     *   [Jwt.defaultJsonParser] configuration (`ignoreUnknownKeys = true`, `explicitNulls = false`)
     * @return the payload deserialized into an instance of [T]
     */
    public fun <T> getPayload(serializer: KSerializer<T>, jsonInstance: Json = Jwt.defaultJsonParser): T =
        jsonInstance.decodeFromJsonElement(serializer, payload.jsonData)

    /**
     * Deserializes the token header as type [T].
     *
     * @param T the target type to deserialize the header into
     * @param jsonInstance the [Json] instance to use for deserialization; defaults to the library's
     *   [Jwt.defaultJsonParser] configuration (`ignoreUnknownKeys = true`, `explicitNulls = false`)
     * @return the header deserialized into an instance of [T]
     */
    public inline fun <reified T> getHeader(jsonInstance: Json = Jwt.defaultJsonParser): T =
        getHeader(kotlinx.serialization.serializer<T>(), jsonInstance)

    /**
     * Deserializes the token header using the given [serializer].
     *
     * @param T the target type to deserialize the header into
     * @param serializer the [KSerializer] used to deserialize the header
     * @param jsonInstance the [Json] instance to use for deserialization; defaults to the library's
     *   [Jwt.defaultJsonParser] configuration (`ignoreUnknownKeys = true`, `explicitNulls = false`)
     * @return the header deserialized into an instance of [T]
     */
    public fun <T> getHeader(serializer: KSerializer<T>, jsonInstance: Json = Jwt.defaultJsonParser): T =
        jsonInstance.decodeFromJsonElement(serializer, header.jsonData)

    /** Represents a JWE (encrypted) token with five compact-serialization parts. */
    public class Jwe internal constructor(
        override val header: JwtHeader,
        override val payload: JwtPayload,
        /** The base64url-encoded encrypted Content Encryption Key (CEK). */
        public val encryptedKey: String,
        /** The base64url-encoded initialization vector used during content encryption. */
        public val iv: String,
        /** The base64url-encoded ciphertext produced by content encryption. */
        public val cipherText: String,
        /** The base64url-encoded authentication tag produced by content encryption. */
        public val tag: String,
    ) : JwtInstance() {
        /**
         * The Additional Authenticated Data (AAD) for this JWE token, which is the
         * base64url-encoded header string used during encryption and decryption.
         */
        public val aad: String
            get() = header.base64Encoded

        /**
         * Returns the compact five-part JWE serialization:
         * `header.encryptedKey.iv.ciphertext.tag`.
         *
         * @return the compact JWE token string
         */
        override fun compact(): String =
            buildString {
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

    /** Represents a JWS (signed) token with one or more signatures. */
    public class Jws internal constructor(
        override val payload: JwtPayload,
        /** The list of [Signature] entries; each holds a header and its corresponding base64url-encoded signature. */
        public val signatures: List<Signature>,
    ) : JwtInstance() {
        internal constructor(
            header: JwtHeader,
            payload: JwtPayload,
            signature: String,
        ) : this(
            payload = payload,
            signatures = listOf(Signature(header, signature)),
        )

        override val header: JwtHeader
            get() = signatures.first().header

        /**
         * The signature string for this token, taken from the first entry in [signatures].
         */
        public val signature: String
            get() = signatures.first().signature

        /**
         * Returns the compact three-part JWS serialization: `header.payload.signature`.
         *
         * @return the compact JWS token string
         */
        override fun compact(): String = "$header.$payload.$signature"

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

        /** Represents a single signature entry within a JWS token. */
        public class Signature(
            /** The JOSE header associated with this signature. */
            public val header: JwtHeader,
            /** The base64url-encoded signature value. */
            public val signature: String,
        )
    }
}
