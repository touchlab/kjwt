package co.touchlab.kjwt.model.jwk

import co.touchlab.kjwt.serializers.JwkEcSerializer
import co.touchlab.kjwt.serializers.JwkEcThumbprintSerializer
import co.touchlab.kjwt.serializers.JwkOctSerializer
import co.touchlab.kjwt.serializers.JwkOctThumbprintSerializer
import co.touchlab.kjwt.serializers.JwkRsaSerializer
import co.touchlab.kjwt.serializers.JwkRsaThumbprintSerializer
import co.touchlab.kjwt.serializers.JwkSerializer
import co.touchlab.kjwt.serializers.JwkThumbprintSerializer
import kotlinx.serialization.Serializable

@Serializable(with = JwkSerializer::class)
public sealed class Jwk {
    /**
     * The `use` parameter (RFC 7517 §4.2); indicates the intended use of the public key ("sig" for signature or "enc"
     * for encryption).
     */
    public abstract val use: String?

    /**
     * The `key_ops` parameter (RFC 7517 §4.3); lists the operations for which this key is intended to be used.
     */
    public abstract val keyOps: List<String>?

    /**
     * The `alg` parameter (RFC 7517 §4.4); identifies the algorithm intended for use with this key.
     */
    public abstract val alg: String?

    /**
     * The `kid` parameter (RFC 7517 §4.5); a hint used to identify a specific key within a key set.
     */
    public abstract val kid: String?

    /**
     * Whether this JWK contains private key material.
     */
    public abstract val isPrivate: Boolean

    /**
     * The JWK Thumbprint for this key as defined by RFC 7638.
     */
    public abstract val thumbprint: Thumbprint

    /**
     * Base class for typed JWK Thumbprints as defined by RFC 7638.
     *
     * Each subclass holds the required members for a specific key type in lexicographic order,
     * ready to be serialized and hashed to produce the thumbprint value.
     */
    @Serializable(with = JwkThumbprintSerializer::class)
    public sealed class Thumbprint

    /**
     * RSA key (kty = "RSA"). Public key requires [n] and [e].
     * Private key additionally requires [d]; CRT parameters [p], [q], [dp], [dq], [qi]
     * are optional but required for key conversion to cryptography-kotlin types.
     */
    @Serializable(with = JwkRsaSerializer::class)
    public data class Rsa(
        public val n: String,
        public val e: String,
        public val d: String? = null,
        public val p: String? = null,
        public val q: String? = null,
        public val dp: String? = null,
        public val dq: String? = null,
        public val qi: String? = null,
        override val use: String? = null,
        override val keyOps: List<String>? = null,
        override val alg: String? = null,
        override val kid: String? = null,
    ) : Jwk() {
        override val isPrivate: Boolean get() = d != null

        override val thumbprint: Thumbprint by lazy {
            RSAThumbprint(e, n)
        }

        /**
         * Thumbprint computed from the RSA key parameters `e` (public exponent) and `n` (modulus).
         */
        @Serializable(with = JwkRsaThumbprintSerializer::class)
        public data class RSAThumbprint(
            public val e: String,
            public val n: String,
        ) : Thumbprint()

        public companion object {
            public const val KTY: String = "RSA"
        }
    }

    /**
     * Elliptic Curve key (kty = "EC"). Public key requires [crv], [x], and [y].
     * Private key additionally requires [d]. Supported curves: "P-256", "P-384", "P-521".
     */
    @Serializable(with = JwkEcSerializer::class)
    public data class Ec(
        public val crv: String,
        public val x: String,
        public val y: String,
        public val d: String? = null,
        override val use: String? = null,
        override val keyOps: List<String>? = null,
        override val alg: String? = null,
        override val kid: String? = null,
    ) : Jwk() {
        override val isPrivate: Boolean get() = d != null

        override val thumbprint: Thumbprint by lazy {
            ECThumbprint(crv, x, y)
        }

        /**
         * Thumbprint computed from the EC key parameters `crv` (curve), `x`, and `y` (public key coordinates).
         */
        @Serializable(with = JwkEcThumbprintSerializer::class)
        public data class ECThumbprint(
            public val crv: String,
            public val x: String,
            public val y: String,
        ) : Thumbprint()

        public companion object {
            public const val KTY: String = "EC"
        }
    }

    /**
     * Symmetric (octet sequence) key (kty = "oct"). The [k] parameter holds the raw key bytes
     * encoded as base64url. Always considered private key material.
     */
    @Serializable(with = JwkOctSerializer::class)
    public data class Oct(
        public val k: String,
        override val use: String? = null,
        override val keyOps: List<String>? = null,
        override val alg: String? = null,
        override val kid: String? = null,
    ) : Jwk() {
        override val isPrivate: Boolean get() = true

        override val thumbprint: Thumbprint by lazy {
            OctThumbprint(k)
        }

        /**
         * Thumbprint computed from the symmetric key material `k` (the raw key bytes encoded as base64url).
         */
        @Serializable(with = JwkOctThumbprintSerializer::class)
        public data class OctThumbprint(val k: String) : Thumbprint()

        public companion object {
            public const val KTY: String = "oct"
        }
    }
}
