package co.touchlab.kjwt.jwk

import co.touchlab.kjwt.model.jwk.Jwk
import co.touchlab.kjwt.model.jwk.JwkSet
import io.kotest.core.spec.style.FunSpec
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class JwkSetTest : FunSpec({

    val rsaPublicKey = Jwk.Rsa(n = "n", e = "AQAB", kid = "rsa-pub", use = "sig")
    val rsaPrivateKey = Jwk.Rsa(n = "n", e = "AQAB", d = "d", p = "p", q = "q", dp = "dp", dq = "dq", qi = "qi", kid = "rsa-priv", use = "sig")
    val ecPublicKey = Jwk.Ec(crv = "P-256", x = "x", y = "y", kid = "ec-pub", use = "enc")
    val octKey = Jwk.Oct(k = "key", kid = "hmac", use = "sig")

    val jwks = JwkSet(listOf(rsaPublicKey, rsaPrivateKey, ecPublicKey, octKey))

    test("findById returns matching key") {
        assertEquals(rsaPublicKey, jwks.findById("rsa-pub"))
        assertEquals(ecPublicKey, jwks.findById("ec-pub"))
        assertEquals(octKey, jwks.findById("hmac"))
    }

    test("findById returns null when not found") {
        assertNull(jwks.findById("nonexistent"))
    }

    test("findByUse returns all matching keys") {
        val sigKeys = jwks.findByUse("sig")
        assertEquals(3, sigKeys.size)
        assertTrue(sigKeys.contains(rsaPublicKey))
        assertTrue(sigKeys.contains(rsaPrivateKey))
        assertTrue(sigKeys.contains(octKey))
    }

    test("findByUse enc returns EC key") {
        val encKeys = jwks.findByUse("enc")
        assertEquals(1, encKeys.size)
        assertEquals(ecPublicKey, encKeys[0])
    }

    test("publicKeys filters out private key material") {
        val publicJwks = jwks.publicKeys()
        // rsaPublicKey + ecPublicKey = 2; rsaPrivateKey and octKey are excluded
        assertEquals(2, publicJwks.keys.size)
        assertTrue(!publicJwks.keys.contains(rsaPrivateKey))
        assertTrue(!publicJwks.keys.contains(octKey))  // oct keys are always private
        assertTrue(publicJwks.keys.contains(rsaPublicKey))
        assertTrue(publicJwks.keys.contains(ecPublicKey))
    }

    test("empty JWKS public keys is empty") {
        val empty = JwkSet(emptyList())
        assertEquals(0, empty.publicKeys().keys.size)
    }
})
