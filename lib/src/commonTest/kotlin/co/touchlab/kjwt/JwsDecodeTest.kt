package co.touchlab.kjwt

import co.touchlab.kjwt.ext.audienceOrNull
import co.touchlab.kjwt.ext.expirationOrNull
import co.touchlab.kjwt.ext.getClaimOrNull
import co.touchlab.kjwt.ext.issuedAtOrNull
import co.touchlab.kjwt.ext.issuerOrNull
import co.touchlab.kjwt.ext.notBeforeOrNull
import co.touchlab.kjwt.ext.subjectOrNull
import co.touchlab.kjwt.ext.type
import co.touchlab.kjwt.model.JwtInstance
import io.kotest.core.spec.style.FunSpec
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

class JwsDecodeTest : FunSpec({

    context("parse known HS256 token") {

        test("parse Hs256 valid token") {
            val signingKey = hs256SigningKey()
            val jws = Jwt.parser()
                .verifyWith(signingKey)
                .build()
                .parseSigned(
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

        test("parse Hs384 valid token") {
            val signingKey = hs384SigningKey()
            val token = Jwt.builder()
                .subject("hs384-user")
                .issuedAt(Instant.fromEpochSeconds(1_700_000_000))
                .signWith(signingKey)
                .compact()

            val jws = Jwt.parser()
                .verifyWith(signingKey)
                .build()
                .parseSigned(token)

            assertEquals("HS384", jws.header.algorithm)
            assertEquals("hs384-user", jws.payload.subjectOrNull)
        }

        test("parse Hs512 valid token") {
            val signingKey = hs512SigningKey()
            val token = Jwt.builder()
                .subject("hs512-user")
                .issuedAt(Instant.fromEpochSeconds(1_700_000_000))
                .signWith(signingKey)
                .compact()

            val jws = Jwt.parser()
                .verifyWith(signingKey)
                .build()
                .parseSigned(token)

            assertEquals("HS512", jws.header.algorithm)
            assertEquals("hs512-user", jws.payload.subjectOrNull)
        }

        test("parse Rs256 valid token") {
            val keyPair = rs256SigningKey()
            val token = Jwt.builder()
                .subject("rs256-user")
                .signWith(keyPair)
                .compact()

            val jws = Jwt.parser()
                .verifyWith(keyPair)
                .build()
                .parseSigned(token)

            assertEquals("RS256", jws.header.algorithm)
            assertEquals("rs256-user", jws.payload.subjectOrNull)
            assertNotNull(jws.signature)
        }

        test("parse Es256 valid token") {
            val keyPair = es256SigningKey()
            val token = Jwt.builder()
                .subject("es256-user")
                .signWith(keyPair)
                .compact()

            val jws = Jwt.parser()
                .verifyWith(keyPair)
                .build()
                .parseSigned(token)

            assertEquals("ES256", jws.header.algorithm)
            assertEquals("es256-user", jws.payload.subjectOrNull)
        }

        test("parse Ps256 valid token") {
            val keyPair = ps256SigningKey()
            val token = Jwt.builder()
                .subject("ps256-user")
                .signWith(keyPair)
                .compact()

            val jws = Jwt.parser()
                .verifyWith(keyPair)
                .build()
                .parseSigned(token)

            assertEquals("PS256", jws.header.algorithm)
            assertEquals("ps256-user", jws.payload.subjectOrNull)
        }
    }

    context("none algorithm opt-in") {

        test("parse none with allow unsecured") {
            val token = Jwt.builder()
                .subject("none-user")
                .build()
                .compact()

            val jws = Jwt.parser()
                .allowUnsecured(true)
                .build()
                .parseSigned(token)

            assertEquals("none", jws.header.algorithm)
            assertEquals("none-user", jws.payload.subjectOrNull)
        }

        test("parse none with no verify succeeds") {
            val token = Jwt.builder()
                .subject("none-user")
                .build()
                .compact()

            val jws = Jwt.parser()
                .noVerify()
                .build()
                .parseSigned(token)

            assertEquals("none", jws.header.algorithm)
            assertEquals("none-user", jws.payload.subjectOrNull)
        }

        test("no verify with signed token skips verification") {
            val signingKey = hs256SigningKey()
            val token = Jwt.builder()
                .subject("user")
                .signWith(signingKey)
                .compact()

            // noVerify() matches any algorithm and None.verify() always returns true
            val jws = Jwt.parser()
                .noVerify()
                .build()
                .parseSigned(token)

            assertEquals("HS256", jws.header.algorithm)
            assertEquals("user", jws.payload.subjectOrNull)
        }
    }

    context("audience normalization") {

        test("parse Hs256 audience normalized single string") {
            val signingKey = hs256SigningKey()
            // Build a token with single audience (serialized as plain string)
            val token = Jwt.builder()
                .audience("api.example.com")
                .signWith(signingKey)
                .compact()

            val jws = Jwt.parser()
                .verifyWith(signingKey)
                .build()
                .parseSigned(token)

            assertEquals(setOf("api.example.com"), jws.payload.audienceOrNull)
        }

        test("parse Hs256 audience normalized array") {
            val signingKey = hs256SigningKey()
            // Build a token with multiple audiences (serialized as JSON array)
            val token = Jwt.builder()
                .audience("aud1", "aud2")
                .signWith(signingKey)
                .compact()

            val jws = Jwt.parser()
                .verifyWith(signingKey)
                .build()
                .parseSigned(token)

            assertEquals(setOf("aud1", "aud2"), jws.payload.audienceOrNull)
        }
    }

    context("typed custom claim access") {

        test("parse Hs256 custom claims typed access") {
            val signingKey = hs256SigningKey()
            val token = Jwt.builder()
                .claim("role", "admin")
                .claim("level", 5)
                .claim("active", true)
                .signWith(signingKey)
                .compact()

            val jws = Jwt.parser()
                .verifyWith(signingKey)
                .build()
                .parseSigned(token)

            assertEquals("admin", jws.payload.getClaimOrNull<String>("role"))
            assertEquals(5, jws.payload.getClaimOrNull<Int>("level"))
            assertEquals(true, jws.payload.getClaimOrNull<Boolean>("active"))
        }
    }

    context("auto-detect") {

        test("parse auto detect JWS token returns Jws") {
            val signingKey = hs256SigningKey()
            val token = Jwt.builder()
                .subject("auto-detect-user")
                .signWith(signingKey)
                .compact()

            val result = Jwt.parser()
                .verifyWith(signingKey)
                .build()
                .parse(token)

            assertIs<JwtInstance.Jws>(result)
            assertEquals("auto-detect-user", result.payload.subjectOrNull)
        }
    }

    context("claim validation happy paths") {

        test("validate issuer match") {
            val signingKey = hs256SigningKey()
            val token = Jwt.builder()
                .issuer("my-issuer")
                .expiration(Clock.System.now() + 1.hours)
                .signWith(signingKey)
                .compact()

            val jws = Jwt.parser()
                .verifyWith(signingKey)
                .requireIssuer("my-issuer")
                .build()
                .parseSigned(token)

            assertEquals("my-issuer", jws.payload.issuerOrNull)
        }

        test("validate subject match") {
            val signingKey = hs256SigningKey()
            val token = Jwt.builder()
                .subject("my-subject")
                .expiration(Clock.System.now() + 1.hours)
                .signWith(signingKey)
                .compact()

            val jws = Jwt.parser()
                .verifyWith(signingKey)
                .requireSubject("my-subject")
                .build()
                .parseSigned(token)

            assertEquals("my-subject", jws.payload.subjectOrNull)
        }

        test("validate audience match single") {
            val signingKey = hs256SigningKey()
            val token = Jwt.builder()
                .audience("my-api")
                .expiration(Clock.System.now() + 1.hours)
                .signWith(signingKey)
                .compact()

            val jws = Jwt.parser()
                .verifyWith(signingKey)
                .requireAudience("my-api")
                .build()
                .parseSigned(token)

            assertEquals(setOf("my-api"), jws.payload.audienceOrNull)
        }

        test("validate audience match one of many") {
            val signingKey = hs256SigningKey()
            val token = Jwt.builder()
                .audience("api1", "api2", "api3")
                .expiration(Clock.System.now() + 1.hours)
                .signWith(signingKey)
                .compact()

            val jws = Jwt.parser()
                .verifyWith(signingKey)
                .requireAudience("api2")
                .build()
                .parseSigned(token)

            assertEquals(setOf("api1", "api2", "api3"), jws.payload.audienceOrNull)
        }

        test("validate exp not expired") {
            val signingKey = hs256SigningKey()
            val token = Jwt.builder()
                .expiration(Clock.System.now() + 1.hours)
                .signWith(signingKey)
                .compact()

            // Should not throw
            val jws = Jwt.parser()
                .verifyWith(signingKey)
                .build()
                .parseSigned(token)

            assertNotNull(jws.payload.expirationOrNull)
        }

        test("validate nbf past time allowed") {
            val signingKey = hs256SigningKey()
            val token = Jwt.builder()
                .notBefore(Clock.System.now() - 1.hours) // already past, so valid
                .signWith(signingKey)
                .compact()

            // Should not throw
            val jws = Jwt.parser()
                .verifyWith(signingKey)
                .build()
                .parseSigned(token)

            assertNotNull(jws.payload.notBeforeOrNull)
        }

        test("validate clock skew slightly expired within skew") {
            val signingKey = hs256SigningKey()
            // Expired 3 seconds ago
            val token = Jwt.builder()
                .expiration(Clock.System.now() - 3.seconds)
                .signWith(signingKey)
                .compact()

            // With 5-second skew, it should pass
            val jws = Jwt.parser()
                .verifyWith(signingKey)
                .clockSkew(5L)
                .build()
                .parseSigned(token)

            assertNotNull(jws.payload.expirationOrNull)
        }
    }
})
