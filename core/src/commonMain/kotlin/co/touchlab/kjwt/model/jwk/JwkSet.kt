package co.touchlab.kjwt.model.jwk

import co.touchlab.kjwt.annotations.ExperimentalKJWTApi
import kotlinx.serialization.Serializable

/**
 * A JSON Web Key Set (JWKS) — a container for one or more [Jwk] objects.
 *
 * Typically served from a JWKS discovery endpoint (e.g. `/.well-known/jwks.json`).
 */
@Serializable
@ExperimentalKJWTApi
public data class JwkSet(
    /**
     * The list of JWK values contained in this key set (RFC 7517 §5.1 `keys` parameter).
     */
    val keys: List<Jwk>,
) {
    /**
     * Returns the first key whose [Jwk.kid] matches [kid], or `null` if not found.
     *
     * @param kid the key ID to search for
     * @return the matching [Jwk], or `null` if no key with that ID is present.
     */
    public fun findById(kid: String): Jwk? = keys.firstOrNull { it.kid == kid }

    /**
     * Returns all keys whose [Jwk.use] matches [use] (e.g. `"sig"` or `"enc"`).
     *
     * @param use the intended key use to filter by
     * @return the list of [Jwk] entries with the specified use; empty if none match.
     */
    public fun findByUse(use: String): List<Jwk> = keys.filter { it.use == use }

    /**
     * Returns a new [JwkSet] containing only public keys (no private key material).
     *
     * @return a [JwkSet] whose [keys] list contains only entries where [Jwk.isPrivate] is `false`.
     */
    public fun publicKeys(): JwkSet = JwkSet(keys.filter { !it.isPrivate })
}
