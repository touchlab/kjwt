package co.touchlab.kjwt

import co.touchlab.kjwt.algorithm.JwsAlgorithm
import co.touchlab.kjwt.exception.ExpiredJwtException
import co.touchlab.kjwt.exception.IncorrectClaimException
import co.touchlab.kjwt.exception.MissingClaimException
import co.touchlab.kjwt.exception.PrematureJwtException
import co.touchlab.kjwt.model.expirationOrNull
import co.touchlab.kjwt.model.subjectOrNull
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.test.runTest

class ClaimsValidationTest {

    // ---- Expiration ----

    @Test
    fun parseExpiredToken_throwsExpiredJwtException() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .expiration(Clock.System.now() - 1.hours) // expired 1 hour ago
            .signWith(JwsAlgorithm.HS256, key)

        assertFailsWith<ExpiredJwtException> {
            Jwt.parser()
                .verifyWith(JwsAlgorithm.HS256, key)
                .build()
                .parseSignedClaims(token)
        }
    }

    @Test
    fun parseExpiredToken_containsClaimsInException() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .subject("expired-user")
            .expiration(Clock.System.now() - 1.hours)
            .signWith(JwsAlgorithm.HS256, key)

        val ex = assertFailsWith<ExpiredJwtException> {
            Jwt.parser()
                .verifyWith(JwsAlgorithm.HS256, key)
                .build()
                .parseSignedClaims(token)
        }

        assertEquals("expired-user", ex.claims.subjectOrNull)
        assertNotNull(ex.claims.expirationOrNull)
        assertNotNull(ex.header)
    }

    @Test
    fun parseExpiredToken_withinClockSkew_passes() = runTest {
        val key = hs256Key()
        // Expired 30 seconds ago
        val token = Jwt.builder()
            .expiration(Clock.System.now() - 30.seconds)
            .signWith(JwsAlgorithm.HS256, key)

        // With 60-second skew, should pass
        Jwt.parser()
            .verifyWith(JwsAlgorithm.HS256, key)
            .clockSkew(60L)
            .build()
            .parseSignedClaims(token) // should not throw
    }

    @Test
    fun parseExpiredToken_outsideClockSkew_throws() = runTest {
        val key = hs256Key()
        // Expired 120 seconds ago
        val token = Jwt.builder()
            .expiration(Clock.System.now() - 120.seconds)
            .signWith(JwsAlgorithm.HS256, key)

        assertFailsWith<ExpiredJwtException> {
            Jwt.parser()
                .verifyWith(JwsAlgorithm.HS256, key)
                .clockSkew(60L) // skew of 60s is not enough for 120s expired
                .build()
                .parseSignedClaims(token)
        }
    }

    // ---- Not Before ----

    @Test
    fun parsePrematureToken_throwsPrematureJwtException() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .notBefore(Clock.System.now() + 1.hours) // not valid for another hour
            .signWith(JwsAlgorithm.HS256, key)

        assertFailsWith<PrematureJwtException> {
            Jwt.parser()
                .verifyWith(JwsAlgorithm.HS256, key)
                .build()
                .parseSignedClaims(token)
        }
    }

    @Test
    fun parsePrematureToken_withinClockSkew_passes() = runTest {
        val key = hs256Key()
        // Not valid for another 30 seconds
        val token = Jwt.builder()
            .notBefore(Clock.System.now() + 30.seconds)
            .signWith(JwsAlgorithm.HS256, key)

        // With 60-second skew, should pass
        Jwt.parser()
            .verifyWith(JwsAlgorithm.HS256, key)
            .clockSkew(60L)
            .build()
            .parseSignedClaims(token) // should not throw
    }

    @Test
    fun parsePrematureToken_outsideClockSkew_throws() = runTest {
        val key = hs256Key()
        // Not valid for another 120 seconds
        val token = Jwt.builder()
            .notBefore(Clock.System.now() + 120.seconds)
            .signWith(JwsAlgorithm.HS256, key)

        assertFailsWith<PrematureJwtException> {
            Jwt.parser()
                .verifyWith(JwsAlgorithm.HS256, key)
                .clockSkew(60L)
                .build()
                .parseSignedClaims(token)
        }
    }

    // ---- Issuer ----

    @Test
    fun requireIssuer_mismatch_throwsIncorrectClaimException() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .issuer("actual-issuer")
            .signWith(JwsAlgorithm.HS256, key)

        val ex = assertFailsWith<IncorrectClaimException> {
            Jwt.parser()
                .verifyWith(JwsAlgorithm.HS256, key)
                .requireIssuer("expected-issuer")
                .build()
                .parseSignedClaims(token)
        }

        assertEquals("iss", ex.claimName)
        assertEquals("expected-issuer", ex.expected)
    }

    @Test
    fun requireIssuer_missing_throwsMissingClaimException() = runTest {
        val key = hs256Key()
        // Token with no issuer claim
        val token = Jwt.builder()
            .subject("someone")
            .signWith(JwsAlgorithm.HS256, key)

        val ex = assertFailsWith<MissingClaimException> {
            Jwt.parser()
                .verifyWith(JwsAlgorithm.HS256, key)
                .requireIssuer("expected-issuer")
                .build()
                .parseSignedClaims(token)
        }

        assertEquals("iss", ex.claimName)
    }

    // ---- Subject ----

    @Test
    fun requireSubject_mismatch_throwsIncorrectClaimException() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .subject("actual-subject")
            .signWith(JwsAlgorithm.HS256, key)

        val ex = assertFailsWith<IncorrectClaimException> {
            Jwt.parser()
                .verifyWith(JwsAlgorithm.HS256, key)
                .requireSubject("expected-subject")
                .build()
                .parseSignedClaims(token)
        }

        assertEquals("sub", ex.claimName)
    }

    @Test
    fun requireSubject_missing_throwsMissingClaimException() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .issuer("issuer")
            .signWith(JwsAlgorithm.HS256, key)

        val ex = assertFailsWith<MissingClaimException> {
            Jwt.parser()
                .verifyWith(JwsAlgorithm.HS256, key)
                .requireSubject("expected-subject")
                .build()
                .parseSignedClaims(token)
        }

        assertEquals("sub", ex.claimName)
    }

    // ---- Audience ----

    @Test
    fun requireAudience_mismatch_throwsIncorrectClaimException() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .audience("actual-aud")
            .signWith(JwsAlgorithm.HS256, key)

        assertFailsWith<IncorrectClaimException> {
            Jwt.parser()
                .verifyWith(JwsAlgorithm.HS256, key)
                .requireAudience("expected-aud")
                .build()
                .parseSignedClaims(token)
        }
    }

    @Test
    fun requireAudience_notInArray_throwsIncorrectClaimException() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .audience("aud1", "aud2")
            .signWith(JwsAlgorithm.HS256, key)

        assertFailsWith<IncorrectClaimException> {
            Jwt.parser()
                .verifyWith(JwsAlgorithm.HS256, key)
                .requireAudience("aud3")
                .build()
                .parseSignedClaims(token)
        }
    }

    @Test
    fun requireAudience_missing_throwsMissingClaimException() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .subject("user")
            .signWith(JwsAlgorithm.HS256, key)

        val ex = assertFailsWith<MissingClaimException> {
            Jwt.parser()
                .verifyWith(JwsAlgorithm.HS256, key)
                .requireAudience("expected-aud")
                .build()
                .parseSignedClaims(token)
        }

        assertEquals("aud", ex.claimName)
    }

    // ---- Custom required claims ----

    @Test
    fun requireCustomClaim_present_match_passes() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .claim("role", "admin")
            .signWith(JwsAlgorithm.HS256, key)

        // Should not throw
        Jwt.parser()
            .verifyWith(JwsAlgorithm.HS256, key)
            .require("role", "admin")
            .build()
            .parseSignedClaims(token)
    }

    @Test
    fun requireCustomClaim_present_mismatch_throwsIncorrectClaimException() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .claim("role", "user")
            .signWith(JwsAlgorithm.HS256, key)

        val ex = assertFailsWith<IncorrectClaimException> {
            Jwt.parser()
                .verifyWith(JwsAlgorithm.HS256, key)
                .require("role", "admin")
                .build()
                .parseSignedClaims(token)
        }

        assertEquals("role", ex.claimName)
        assertEquals("admin", ex.expected)
    }

    @Test
    fun requireCustomClaim_missing_throwsMissingClaimException() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .subject("user")
            .signWith(JwsAlgorithm.HS256, key)

        val ex = assertFailsWith<MissingClaimException> {
            Jwt.parser()
                .verifyWith(JwsAlgorithm.HS256, key)
                .require("role", "admin")
                .build()
                .parseSignedClaims(token)
        }

        assertEquals("role", ex.claimName)
    }
}
