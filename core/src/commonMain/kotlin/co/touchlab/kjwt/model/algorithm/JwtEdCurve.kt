package co.touchlab.kjwt.model.algorithm

/**
 * Elliptic curves supported for EdDSA signing as defined in RFC 8037.
 */
public enum class JwtEdCurve {
    /** Edwards-curve Digital Signature Algorithm over Curve25519. */
    Ed25519,

    /** Edwards-curve Digital Signature Algorithm over Curve448. */
    Ed448,
}
