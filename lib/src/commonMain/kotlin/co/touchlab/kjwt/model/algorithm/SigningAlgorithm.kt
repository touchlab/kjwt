package co.touchlab.kjwt.model.algorithm

import co.touchlab.kjwt.model.registry.SigningKey
import co.touchlab.kjwt.serializers.SigningAlgorithmSerializer
import kotlinx.serialization.Serializable

@Serializable(SigningAlgorithmSerializer::class)
public sealed class SigningAlgorithm(
    override val id: String,
) : Jwa {
    internal fun identifier(keyId: String?) = SigningKey.Identifier(this, keyId)

    /** HMAC with SHA-256 (`HS256`) signing algorithm using a symmetric [HMAC.Key]. */
    public data object HS256 : MACBased("HS256")

    /** HMAC with SHA-384 (`HS384`) signing algorithm using a symmetric [HMAC.Key]. */
    public data object HS384 : MACBased("HS384")

    /** HMAC with SHA-512 (`HS512`) signing algorithm using a symmetric [HMAC.Key]. */
    public data object HS512 : MACBased("HS512")

    /** RSA PKCS#1 v1.5 with SHA-256 (`RS256`) signing algorithm using RSA key pairs. */
    public data object RS256 : PKCS1Based("RS256")

    /** RSA PKCS#1 v1.5 with SHA-384 (`RS384`) signing algorithm using RSA key pairs. */
    public data object RS384 : PKCS1Based("RS384")

    /** RSA PKCS#1 v1.5 with SHA-512 (`RS512`) signing algorithm using RSA key pairs. */
    public data object RS512 : PKCS1Based("RS512")

    /** RSA PSS with SHA-256 (`PS256`) signing algorithm using RSA key pairs. */
    public data object PS256 : PSSBased("PS256")

    /** RSA PSS with SHA-384 (`PS384`) signing algorithm using RSA key pairs. */
    public data object PS384 : PSSBased("PS384")

    /** RSA PSS with SHA-512 (`PS512`) signing algorithm using RSA key pairs. */
    public data object PS512 : PSSBased("PS512")

    /** ECDSA with SHA-256 (`ES256`) signing algorithm using elliptic-curve key pairs. */
    public data object ES256 : ECDSABased("ES256")

    /** ECDSA with SHA-384 (`ES384`) signing algorithm using elliptic-curve key pairs. */
    public data object ES384 : ECDSABased("ES384")

    /** ECDSA with SHA-512 (`ES512`) signing algorithm using elliptic-curve key pairs. */
    public data object ES512 : ECDSABased("ES512")

    /**
     * Groups the HMAC-based signing algorithms (HS256, HS384, HS512).
     *
     * All members use a symmetric [HMAC.Key] for signing and verification.
     */
    public sealed class MACBased(
        id: String,
    ) : SigningAlgorithm(id),
        Jwa.UsesHashingAlgorithm {
        override val digest: JwtDigest
            get() =
                when (this) {
                    HS256 -> JwtDigest.SHA256
                    HS384 -> JwtDigest.SHA384
                    HS512 -> JwtDigest.SHA512
                }
    }

    /**
     * Groups the RSA PKCS#1 v1.5 signing algorithms (RS256, RS384, RS512).
     *
     * All members use [RSA.PKCS1] key pairs for signing and verification.
     */
    public sealed class PKCS1Based(
        id: String,
    ) : SigningAlgorithm(id),
        Jwa.UsesHashingAlgorithm {
        override val digest: JwtDigest
            get() =
                when (this) {
                    RS256 -> JwtDigest.SHA256
                    RS384 -> JwtDigest.SHA384
                    RS512 -> JwtDigest.SHA512
                }
    }

    /**
     * Groups the RSA PSS signing algorithms (PS256, PS384, PS512).
     *
     * All members use [RSA.PSS] key pairs for signing and verification.
     */
    public sealed class PSSBased(
        id: String,
    ) : SigningAlgorithm(id),
        Jwa.UsesHashingAlgorithm {
        override val digest: JwtDigest
            get() =
                when (this) {
                    PS256 -> JwtDigest.SHA256
                    PS384 -> JwtDigest.SHA384
                    PS512 -> JwtDigest.SHA512
                }
    }

    /**
     * Groups the ECDSA signing algorithms (ES256, ES384, ES512).
     *
     * All members use [ECDSA] key pairs and produce raw-format signatures.
     */
    public sealed class ECDSABased(
        id: String,
    ) : SigningAlgorithm(id),
        Jwa.UsesHashingAlgorithm {
        override val digest: JwtDigest
            get() =
                when (this) {
                    ES256 -> JwtDigest.SHA256
                    ES384 -> JwtDigest.SHA384
                    ES512 -> JwtDigest.SHA512
                }

        public val curve: JwtCurve
            get() =
                when (this) {
                    ES256 -> JwtCurve.P256
                    ES384 -> JwtCurve.P384
                    ES512 -> JwtCurve.P521
                }
    }

    /** Unsecured JWT — opt-in only. Rejected by parser unless `allowUnsecured(true)`. */
    public data object None : SigningAlgorithm("none")

    override fun toString(): String = id

    public companion object {
        /**
         * List of all supported [SigningAlgorithm] instances, including [None].
         */
        internal val entries: List<SigningAlgorithm> by lazy {
            listOf(
                HS256,
                HS384,
                HS512,
                RS256,
                RS384,
                RS512,
                PS256,
                PS384,
                PS512,
                ES256,
                ES384,
                ES512,
                None,
            )
        }

        /**
         * Returns the [SigningAlgorithm] whose [id] matches the given string.
         *
         * @param id the JWS algorithm identifier to look up (e.g. `"RS256"`)
         * @return the matching [SigningAlgorithm] instance
         * @throws IllegalArgumentException if no algorithm with the given [id] is registered
         */
        public fun fromId(id: String): SigningAlgorithm =
            requireNotNull(entries.firstOrNull { it.id == id }) {
                "Unknown JWS algorithm: '$id'"
            }
    }
}
