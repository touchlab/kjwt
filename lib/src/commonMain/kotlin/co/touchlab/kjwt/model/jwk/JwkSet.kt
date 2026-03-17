package co.touchlab.kjwt.model.jwk

import kotlinx.serialization.Serializable

/**
 * A JSON Web Key Set (JWKS) — a container for one or more [Jwk] objects.
 *
 * Typically served from a JWKS discovery endpoint (e.g. `/.well-known/jwks.json`).
 */
@Serializable
public data class JwkSet(
    /**
     * The list of JWK values contained in this key set (RFC 7517 §5.1 `keys` parameter).
     */
    val keys: List<Jwk>,
) {
    /** Returns the first key whose [Jwk.kid] matches [kid], or null if not found. */
    public fun findById(kid: String): Jwk? = keys.firstOrNull { it.kid == kid }

    /** Returns all keys whose [Jwk.use] matches [use] (e.g. "sig" or "enc"). */
    public fun findByUse(use: String): List<Jwk> = keys.filter { it.use == use }

    /** Returns a new [JwkSet] containing only public keys (no private key material). */
    public fun publicKeys(): JwkSet = JwkSet(keys.filter { !it.isPrivate })
}
