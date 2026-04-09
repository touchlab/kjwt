package co.touchlab.kjwt.model.algorithm

import co.touchlab.kjwt.model.algorithm.SigningAlgorithm.Companion.fromId
import co.touchlab.kjwt.processor.JwsProcessor
import co.touchlab.kjwt.serializers.SigningAlgorithmSerializer
import kotlinx.serialization.Serializable

/**
 * Sealed class representing the JWS signing algorithms defined in RFC 7518.
 *
 * The supported algorithms are grouped by their cryptographic family:
 * - [MACBased] — HMAC-based algorithms ([HS256], [HS384], [HS512]).
 * - [PKCS1Based] — RSA PKCS#1 v1.5 algorithms ([RS256], [RS384], [RS512]).
 * - [PSSBased] — RSA PSS algorithms ([PS256], [PS384], [PS512]).
 * - [ECDSABased] — Elliptic Curve DSA algorithms ([ES256], [ES384], [ES512]).
 * - [None] — the unsecured algorithm (`alg=none`); rejected by the parser unless
 *   `allowUnsecured(true)` is set.
 *
 * Use [fromId] to look up an instance by its JWA identifier string.
 *
 * @see co.touchlab.kjwt.builder.JwtBuilder.signWith
 * @see co.touchlab.kjwt.parser.JwtParserBuilder.verifyWith
 */
@Serializable(SigningAlgorithmSerializer::class)
public sealed class SigningAlgorithm(
    override val id: String,
) : Jwa {
    /** HMAC with SHA-256 (`HS256`) signing algorithm using a symmetric HMAC Key. */
    public data object HS256 : MACBased("HS256")

    /** HMAC with SHA-384 (`HS384`) signing algorithm using a symmetric HMAC Key. */
    public data object HS384 : MACBased("HS384")

    /** HMAC with SHA-512 (`HS512`) signing algorithm using a symmetric HMAC Key. */
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

    /** EdDSA with Ed25519 curve (`Ed25519`) signing algorithm using Edwards-curve key pairs (RFC 8037). */
    public data object Ed25519 : EdDSABased("Ed25519", JwtEdCurve.Ed25519)

    /** EdDSA with Ed448 curve (`Ed448`) signing algorithm using Edwards-curve key pairs (RFC 8037). */
    public data object Ed448 : EdDSABased("Ed448", JwtEdCurve.Ed448)

    /**
     * Groups the HMAC-based signing algorithms (HS256, HS384, HS512).
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

        /** The [JwtCurve] (P-256, P-384, or P-521) required by this ECDSA algorithm. */
        public val curve: JwtCurve
            get() =
                when (this) {
                    ES256 -> JwtCurve.P256
                    ES384 -> JwtCurve.P384
                    ES512 -> JwtCurve.P521
                }
    }

    /**
     * Groups the EdDSA signing algorithms (Ed25519, Ed448) as defined in RFC 8037.
     *
     * Each uses a fully-specified algorithm identifier in the JWT header (`"Ed25519"` or `"Ed448"`)
     * to prevent algorithm-confusion attacks. This follows the industry direction away from the
     * ambiguous `"EdDSA"` umbrella identifier.
     */
    public sealed class EdDSABased(
        id: String,
        /** The Edwards curve (Ed25519 or Ed448) used by this algorithm. */
        public val curve: JwtEdCurve,
    ) : SigningAlgorithm(id)

    /** Unsecured JWT — opt-in only. Rejected by parser unless `allowUnsecured(true)`. */
    public data object None : SigningAlgorithm("none") {
        public object SimpleProcessor : JwsProcessor {
            override val algorithm: SigningAlgorithm = this@None
            override val keyId: String? = null

            override suspend fun sign(data: ByteArray): ByteArray = ByteArray(0)

            override suspend fun verify(data: ByteArray, signature: ByteArray): Boolean =
                signature.isEmpty()
        }
    }

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
                Ed25519,
                Ed448,
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
