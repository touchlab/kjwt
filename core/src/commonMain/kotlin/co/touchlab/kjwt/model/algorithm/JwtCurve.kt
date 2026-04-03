package co.touchlab.kjwt.model.algorithm

/** Elliptic curve used within a JWA algorithm descriptor. */
public enum class JwtCurve {
    /** NIST P-256 elliptic curve, used with [SigningAlgorithm.ES256]. */
    P256,

    /** NIST P-384 elliptic curve, used with [SigningAlgorithm.ES384]. */
    P384,

    /** NIST P-521 elliptic curve, used with [SigningAlgorithm.ES512]. */
    P521,
}
