package co.touchlab.kjwt

import co.touchlab.kjwt.algorithm.JwsAlgorithm
import co.touchlab.kjwt.model.Claims
import co.touchlab.kjwt.model.JwtInstance
import co.touchlab.kjwt.model.audienceOrNull
import co.touchlab.kjwt.model.expirationOrNull
import co.touchlab.kjwt.model.getClaimOrNull
import co.touchlab.kjwt.model.issuedAtOrNull
import co.touchlab.kjwt.model.issuerOrNull
import co.touchlab.kjwt.model.notBeforeOrNull
import co.touchlab.kjwt.model.subjectOrNull
import dev.whyoleg.cryptography.algorithms.EC
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant
import kotlinx.coroutines.test.runTest

class JwsDecodeTest {

    // ---- Parse known HS256 token ----

    @Test
    fun parseHs256_validToken() = runTest {
        val key = hs256Key()
        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.HS256, key)
            .build()
            .parseSignedClaims(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
                        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyLCJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZX0" +
                        "._-A3B6dTUb8NrJi2SlUH_9jxmaU3plM2sxf-OyXnWiw",
            )

        assertEquals("HS256", jws.header.algorithm)
        assertEquals("JWT", jws.header.type)
        assertEquals("1234567890", jws.payload.subjectOrNull)
        assertEquals(Instant.fromEpochSeconds(1516239022), jws.payload.issuedAtOrNull)
        assertEquals("John Doe", jws.payload.getClaimOrNull("name"))
        assertEquals(true, jws.payload.getClaimOrNull("admin"))
    }

    @Test
    fun parseHs384_validToken() = runTest {
        val key = hs384Key()
        val token = Jwt.builder()
            .subject("hs384-user")
            .issuedAt(Instant.fromEpochSeconds(1_700_000_000))
            .signWith(JwsAlgorithm.HS384, key)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.HS384, key)
            .build()
            .parseSignedClaims(token)

        assertEquals("HS384", jws.header.algorithm)
        assertEquals("hs384-user", jws.payload.subjectOrNull)
    }

    @Test
    fun parseHs512_validToken() = runTest {
        val key = hs512Key()
        val token = Jwt.builder()
            .subject("hs512-user")
            .issuedAt(Instant.fromEpochSeconds(1_700_000_000))
            .signWith(JwsAlgorithm.HS512, key)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.HS512, key)
            .build()
            .parseSignedClaims(token)

        assertEquals("HS512", jws.header.algorithm)
        assertEquals("hs512-user", jws.payload.subjectOrNull)
    }

    @Test
    fun parseRs256_validToken() = runTest {
        val keyPair = rsaPkcs1KeyPair()
        val token = Jwt.builder()
            .subject("rs256-user")
            .signWith(JwsAlgorithm.RS256, keyPair.privateKey)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.RS256, keyPair.publicKey)
            .build()
            .parseSignedClaims(token)

        assertEquals("RS256", jws.header.algorithm)
        assertEquals("rs256-user", jws.payload.subjectOrNull)
        assertNotNull(jws.signature)
    }

    @Test
    fun parseEs256_validToken() = runTest {
        val keyPair = ecKeyPair(EC.Curve.P256)
        val token = Jwt.builder()
            .subject("es256-user")
            .signWith(JwsAlgorithm.ES256, keyPair.privateKey)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.ES256, keyPair.publicKey)
            .build()
            .parseSignedClaims(token)

        assertEquals("ES256", jws.header.algorithm)
        assertEquals("es256-user", jws.payload.subjectOrNull)
    }

    @Test
    fun parsePs256_validToken() = runTest {
        val keyPair = rsaPssKeyPair()
        val token = Jwt.builder()
            .subject("ps256-user")
            .signWith(JwsAlgorithm.PS256, keyPair.privateKey)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.PS256, keyPair.publicKey)
            .build()
            .parseSignedClaims(token)

        assertEquals("PS256", jws.header.algorithm)
        assertEquals("ps256-user", jws.payload.subjectOrNull)
    }

    // ---- None algorithm (opt-in) ----

    @Test
    fun parseNone_withAllowUnsecured() = runTest {
        val token = Jwt.builder()
            .subject("none-user")
            .signWith(JwsAlgorithm.None)

        val jws = Jwt.parser()
            .allowUnsecured(true)
            .build()
            .parseSignedClaims(token)

        assertEquals("none", jws.header.algorithm)
        assertEquals("none-user", jws.payload.subjectOrNull)
    }

    // ---- Audience normalization ----

    @Test
    fun parseHs256_audienceNormalized_singleString() = runTest {
        val key = hs256Key()
        // Build a token with single audience (serialized as plain string)
        val token = Jwt.builder()
            .audience("api.example.com")
            .signWith(JwsAlgorithm.HS256, key)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.HS256, key)
            .build()
            .parseSignedClaims(token)

        assertEquals(setOf("api.example.com"), jws.payload.audienceOrNull)
    }

    @Test
    fun parseHs256_audienceNormalized_array() = runTest {
        val key = hs256Key()
        // Build a token with multiple audiences (serialized as JSON array)
        val token = Jwt.builder()
            .audience("aud1", "aud2")
            .signWith(JwsAlgorithm.HS256, key)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.HS256, key)
            .build()
            .parseSignedClaims(token)

        assertEquals(setOf("aud1", "aud2"), jws.payload.audienceOrNull)
    }

    // ---- Typed custom claim access ----

    @Test
    fun parseHs256_customClaims_typedAccess() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .claim("role", "admin")
            .claim("level", 5)
            .claim("active", true)
            .signWith(JwsAlgorithm.HS256, key)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.HS256, key)
            .build()
            .parseSignedClaims(token)

        assertEquals("admin", jws.payload.getClaimOrNull<String>("role"))
        assertEquals(5, jws.payload.getClaimOrNull<Int>("level"))
        assertEquals(true, jws.payload.getClaimOrNull<Boolean>("active"))
    }

    // ---- Auto-detect ----

    @Test
    fun parseAutoDetect_jwsToken_returnsJws() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .subject("auto-detect-user")
            .signWith(JwsAlgorithm.HS256, key)

        val result = Jwt.parser()
            .verifyWith(JwsAlgorithm.HS256, key)
            .build()
            .parse(token)

        assertIs<JwtInstance.Jws<Claims>>(result)
        assertEquals("auto-detect-user", result.payload.subjectOrNull)
    }

    // ---- Claim validation happy paths ----

    @Test
    fun validateIssuer_match() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .issuer("my-issuer")
            .expiration(Clock.System.now() + 1.hours)
            .signWith(JwsAlgorithm.HS256, key)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.HS256, key)
            .requireIssuer("my-issuer")
            .build()
            .parseSignedClaims(token)

        assertEquals("my-issuer", jws.payload.issuerOrNull)
    }

    @Test
    fun validateSubject_match() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .subject("my-subject")
            .expiration(Clock.System.now() + 1.hours)
            .signWith(JwsAlgorithm.HS256, key)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.HS256, key)
            .requireSubject("my-subject")
            .build()
            .parseSignedClaims(token)

        assertEquals("my-subject", jws.payload.subjectOrNull)
    }

    @Test
    fun validateAudience_match_single() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .audience("my-api")
            .expiration(Clock.System.now() + 1.hours)
            .signWith(JwsAlgorithm.HS256, key)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.HS256, key)
            .requireAudience("my-api")
            .build()
            .parseSignedClaims(token)

        assertEquals(setOf("my-api"), jws.payload.audienceOrNull)
    }

    @Test
    fun validateAudience_match_oneOfMany() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .audience("api1", "api2", "api3")
            .expiration(Clock.System.now() + 1.hours)
            .signWith(JwsAlgorithm.HS256, key)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.HS256, key)
            .requireAudience("api2")
            .build()
            .parseSignedClaims(token)

        assertEquals(setOf("api1", "api2", "api3"), jws.payload.audienceOrNull)
    }

    @Test
    fun validateExp_notExpired() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .expiration(Clock.System.now() + 1.hours)
            .signWith(JwsAlgorithm.HS256, key)

        // Should not throw
        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.HS256, key)
            .build()
            .parseSignedClaims(token)

        assertNotNull(jws.payload.expirationOrNull)
    }

    @Test
    fun validateNbf_pastTime_allowed() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .notBefore(Clock.System.now() - 1.hours) // already past, so valid
            .signWith(JwsAlgorithm.HS256, key)

        // Should not throw
        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.HS256, key)
            .build()
            .parseSignedClaims(token)

        assertNotNull(jws.payload.notBeforeOrNull)
    }

    @Test
    fun validateClockSkew_slightlyExpiredWithinSkew() = runTest {
        val key = hs256Key()
        // Expired 3 seconds ago
        val token = Jwt.builder()
            .expiration(Clock.System.now() - 3.seconds)
            .signWith(JwsAlgorithm.HS256, key)

        // With 5-second skew, it should pass
        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.HS256, key)
            .clockSkew(5L)
            .build()
            .parseSignedClaims(token)

        assertNotNull(jws.payload.expirationOrNull)
    }
}
