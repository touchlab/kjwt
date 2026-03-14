package co.touchlab.kjwt.model.jwk

import kotlinx.serialization.Serializable

/**
 * A JSON Web Key Set (JWKS) — a container for one or more [Jwk] objects.
 *
 * Typically served from a JWKS discovery endpoint (e.g. `/.well-known/jwks.json`).
 */
@Serializable
data class JwkSet(val keys: List<Jwk>) {
    /** Returns the first key whose [Jwk.kid] matches [kid], or null if not found. */
    fun findById(kid: String): Jwk? = keys.firstOrNull { it.kid == kid }

    /** Returns all keys whose [Jwk.use] matches [use] (e.g. "sig" or "enc"). */
    fun findByUse(use: String): List<Jwk> = keys.filter { it.use == use }

    /** Returns a new [JwkSet] containing only public keys (no private key material). */
    fun publicKeys(): JwkSet = JwkSet(keys.filter { !it.isPrivate })
}
