package co.touchlab.kjwt

import co.touchlab.kjwt.ext.audienceOrNull
import co.touchlab.kjwt.ext.expirationOrNull
import co.touchlab.kjwt.ext.getClaimOrNull
import co.touchlab.kjwt.ext.issuedAtOrNull
import co.touchlab.kjwt.ext.issuerOrNull
import co.touchlab.kjwt.ext.jwtIdOrNull
import co.touchlab.kjwt.ext.keyId
import co.touchlab.kjwt.ext.notBeforeOrNull
import co.touchlab.kjwt.ext.subjectOrNull
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import dev.whyoleg.cryptography.algorithms.EC
import dev.whyoleg.cryptography.algorithms.SHA384
import dev.whyoleg.cryptography.algorithms.SHA512
import io.kotest.core.spec.style.FunSpec
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours
import kotlinx.serialization.json.JsonPrimitive

class JwsEncodeTest : FunSpec({

    context("HMAC known-token tests") {

        test("sign Hs256 produces known token") {
            val key = hs256Key()
            val token = Jwt.builder()
                .subject("1234567890")
                .claim("name", "John Doe")
                .claim("admin", true)
                .issuedAt(kotlin.time.Instant.fromEpochSeconds(1516239022))
                .signWith(SigningAlgorithm.HS256, key)
                .compact()

            assertEquals(
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" +
                        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0" +
                        ".pUreHG4uYuv50ST4Sn4ZGZiB104ItoBnvrhBsEoDS1M",
                token,
            )
        }

        test("sign Hs384 round trip") {
            val key = hs384Key()
            val token = Jwt.builder()
                .subject("user-384")
                .issuedAt(kotlin.time.Instant.fromEpochSeconds(1516239022))
                .signWith(SigningAlgorithm.HS384, key)
                .compact()

            val jws = Jwt.parser()
                .verifyWith(SigningAlgorithm.HS384, key)
                .build()
                .parseSigned(token)

            assertEquals("HS384", jws.header.algorithm)
            assertEquals("user-384", jws.payload.subjectOrNull)
        }

        test("sign Hs512 round trip") {
            val key = hs512Key()
            val token = Jwt.builder()
                .subject("user-512")
                .issuedAt(kotlin.time.Instant.fromEpochSeconds(1516239022))
                .signWith(SigningAlgorithm.HS512, key)
                .compact()

            val jws = Jwt.parser()
                .verifyWith(SigningAlgorithm.HS512, key)
                .build()
                .parseSigned(token)

            assertEquals("HS512", jws.header.algorithm)
            assertEquals("user-512", jws.payload.subjectOrNull)
        }
    }

    context("all registered claims") {

        test("sign Hs256 with all registered claims") {
            val key = hs256Key()
            val now = Clock.System.now()
            val token = Jwt.builder()
                .issuer("test-issuer")
                .subject("test-subject")
                .audience("test-audience")
                .expiration(now + 1.hours)
                .notBefore(now - 1.hours)
                .issuedAt(now)
                .id("unique-jwt-id")
                .signWith(SigningAlgorithm.HS256, key)
                .compact()

            val jws = Jwt.parser()
                .verifyWith(SigningAlgorithm.HS256, key)
                .build()
                .parseSigned(token)

            assertEquals("test-issuer", jws.payload.issuerOrNull)
            assertEquals("test-subject", jws.payload.subjectOrNull)
            assertEquals(setOf("test-audience"), jws.payload.audienceOrNull)
            assertEquals((now + 1.hours).epochSeconds, jws.payload.expirationOrNull?.epochSeconds)
            assertEquals((now - 1.hours).epochSeconds, jws.payload.notBeforeOrNull?.epochSeconds)
            assertEquals(now.epochSeconds, jws.payload.issuedAtOrNull?.epochSeconds)
            assertEquals("unique-jwt-id", jws.payload.jwtIdOrNull)
        }
    }

    context("custom claims") {

        test("sign Hs256 with custom claims") {
            val key = hs256Key()
            val token = Jwt.builder()
                .claim("strClaim", "hello")
                .claim("numClaim", 42)
                .claim("boolClaim", true)
                .signWith(SigningAlgorithm.HS256, key)
                .compact()

            val jws = Jwt.parser()
                .verifyWith(SigningAlgorithm.HS256, key)
                .build()
                .parseSigned(token)

            assertEquals("hello", jws.payload.getClaimOrNull<String>("strClaim"))
            assertEquals(42, jws.payload.getClaimOrNull<Int>("numClaim"))
            assertEquals(true, jws.payload.getClaimOrNull<Boolean>("boolClaim"))
        }
    }

    context("audience serialization") {

        test("sign Hs256 audience single string") {
            val key = hs256Key()
            val token = Jwt.builder()
                .audience("single-aud")
                .signWith(SigningAlgorithm.HS256, key)
                .compact()

            val payloadJson = decodeTokenPayload(token)
            // Single audience must be serialized as a plain string, not an array
            assertTrue(payloadJson.contains("\"aud\":\"single-aud\""), "Expected plain string aud, got: $payloadJson")
        }

        test("sign Hs256 audience multiple") {
            val key = hs256Key()
            val token = Jwt.builder()
                .audience("aud1", "aud2", "aud3")
                .signWith(SigningAlgorithm.HS256, key)
                .compact()

            val payloadJson = decodeTokenPayload(token)
            // Multiple audiences must be serialized as JSON array
            assertTrue(payloadJson.contains("\"aud\":["), "Expected array aud, got: $payloadJson")
        }
    }

    context("header fields") {

        test("sign Hs256 header kid included") {
            val key = hs256Key()
            val token = Jwt.builder()
                .keyId("my-key-id")
                .subject("test")
                .signWith(SigningAlgorithm.HS256, key)
                .compact()

            val jws = Jwt.parser()
                .verifyWith(SigningAlgorithm.HS256, key)
                .build()
                .parseSigned(token)

            assertEquals("my-key-id", jws.header.keyId)
        }

        test("sign Hs256 custom header fields") {
            val key = hs256Key()
            val token = Jwt.builder()
                .header { extra("x-custom", JsonPrimitive("custom-value")) }
                .subject("test")
                .signWith(SigningAlgorithm.HS256, key)
                .compact()

            val headerJson = decodeTokenHeader(token)
            assertTrue(headerJson.contains("x-custom"), "Expected custom header field, got: $headerJson")
        }
    }

    context("RSA PKCS1 round-trips") {

        test("sign Rs256 round trip") {
            val keyPair = rsaPkcs1KeyPair()
            val token = Jwt.builder()
                .subject("rs256-subject")
                .signWith(SigningAlgorithm.RS256, keyPair.privateKey)
                .compact()

            val jws = Jwt.parser()
                .verifyWith(SigningAlgorithm.RS256, keyPair.publicKey)
                .build()
                .parseSigned(token)

            assertEquals("RS256", jws.header.algorithm)
            assertEquals("rs256-subject", jws.payload.subjectOrNull)
        }

        test("sign Rs384 round trip") {
            val keyPair = rsaPkcs1KeyPair(SHA384)
            val token = Jwt.builder()
                .subject("rs384-subject")
                .signWith(SigningAlgorithm.RS384, keyPair.privateKey)
                .compact()

            val jws = Jwt.parser()
                .verifyWith(SigningAlgorithm.RS384, keyPair.publicKey)
                .build()
                .parseSigned(token)

            assertEquals("rs384-subject", jws.payload.subjectOrNull)
        }

        test("sign Rs512 round trip") {
            val keyPair = rsaPkcs1KeyPair(SHA512)
            val token = Jwt.builder()
                .subject("rs512-subject")
                .signWith(SigningAlgorithm.RS512, keyPair.privateKey)
                .compact()

            val jws = Jwt.parser()
                .verifyWith(SigningAlgorithm.RS512, keyPair.publicKey)
                .build()
                .parseSigned(token)

            assertEquals("rs512-subject", jws.payload.subjectOrNull)
        }
    }

    context("RSA PSS round-trips") {

        test("sign Ps256 round trip") {
            val keyPair = rsaPssKeyPair()
            val token = Jwt.builder()
                .subject("ps256-subject")
                .signWith(SigningAlgorithm.PS256, keyPair.privateKey)
                .compact()

            val jws = Jwt.parser()
                .verifyWith(SigningAlgorithm.PS256, keyPair.publicKey)
                .build()
                .parseSigned(token)

            assertEquals("PS256", jws.header.algorithm)
            assertEquals("ps256-subject", jws.payload.subjectOrNull)
        }

        test("sign Ps384 round trip") {
            val keyPair = rsaPssKeyPair(SHA384)
            val token = Jwt.builder()
                .subject("ps384-subject")
                .signWith(SigningAlgorithm.PS384, keyPair.privateKey)
                .compact()

            val jws = Jwt.parser()
                .verifyWith(SigningAlgorithm.PS384, keyPair.publicKey)
                .build()
                .parseSigned(token)

            assertEquals("ps384-subject", jws.payload.subjectOrNull)
        }

        test("sign Ps512 round trip") {
            val keyPair = rsaPssKeyPair(SHA512)
            val token = Jwt.builder()
                .subject("ps512-subject")
                .signWith(SigningAlgorithm.PS512, keyPair.privateKey)
                .compact()

            val jws = Jwt.parser()
                .verifyWith(SigningAlgorithm.PS512, keyPair.publicKey)
                .build()
                .parseSigned(token)

            assertEquals("ps512-subject", jws.payload.subjectOrNull)
        }
    }

    context("ECDSA round-trips") {

        test("sign Es256 round trip") {
            val keyPair = ecKeyPair(EC.Curve.P256)
            val token = Jwt.builder()
                .subject("es256-subject")
                .signWith(SigningAlgorithm.ES256, keyPair.privateKey)
                .compact()

            val jws = Jwt.parser()
                .verifyWith(SigningAlgorithm.ES256, keyPair.publicKey)
                .build()
                .parseSigned(token)

            assertEquals("ES256", jws.header.algorithm)
            assertEquals("es256-subject", jws.payload.subjectOrNull)
        }

        test("sign Es384 round trip") {
            val keyPair = ecKeyPair(EC.Curve.P384)
            val token = Jwt.builder()
                .subject("es384-subject")
                .signWith(SigningAlgorithm.ES384, keyPair.privateKey)
                .compact()

            val jws = Jwt.parser()
                .verifyWith(SigningAlgorithm.ES384, keyPair.publicKey)
                .build()
                .parseSigned(token)

            assertEquals("es384-subject", jws.payload.subjectOrNull)
        }

        test("sign Es512 round trip") {
            val keyPair = ecKeyPair(EC.Curve.P521)
            val token = Jwt.builder()
                .subject("es512-subject")
                .signWith(SigningAlgorithm.ES512, keyPair.privateKey)
                .compact()

            val jws = Jwt.parser()
                .verifyWith(SigningAlgorithm.ES512, keyPair.publicKey)
                .build()
                .parseSigned(token)

            assertEquals("es512-subject", jws.payload.subjectOrNull)
        }

        test("sign Es256 signature is raw format") {
            // ES256 RAW signature = R‖S, each 32 bytes for P-256 → 64 bytes total
            val keyPair = ecKeyPair(EC.Curve.P256)
            val token = Jwt.builder()
                .subject("test")
                .signWith(SigningAlgorithm.ES256, keyPair.privateKey)
                .compact()

            val signatureB64 = token.split('.')[2]
            val signatureBytes = decodeBase64Url(signatureB64)
            assertEquals(64, signatureBytes.size, "ES256 RAW signature must be exactly 64 bytes (R‖S for P-256)")
        }
    }

    context("none algorithm") {

        test("sign none produces empty signature part") {
            val token = Jwt.builder()
                .subject("test")
                .signWith(SigningAlgorithm.None)
                .compact()

            val parts = token.split('.')
            assertEquals(3, parts.size)
            assertTrue(token.endsWith("."), "None token must end with '.'")
            assertEquals("", parts[2], "Signature part must be empty for alg=none")
        }
    }

    context("determinism") {

        test("sign Hs256 two calls produce same token") {
            // HMAC is deterministic — same input must produce the same token
            val key = hs256Key()
            val iat = kotlin.time.Instant.fromEpochSeconds(1_700_000_000)
            val t1 = Jwt.builder().subject("user").issuedAt(iat).signWith(SigningAlgorithm.HS256, key)
                .compact()
            val t2 = Jwt.builder().subject("user").issuedAt(iat).signWith(SigningAlgorithm.HS256, key)
                .compact()
            assertEquals(t1, t2)
        }

        test("sign Es256 two calls produce different tokens") {
            // ECDSA is non-deterministic (uses random nonce) — different signatures each call
            val keyPair = ecKeyPair(EC.Curve.P256)
            val iat = kotlin.time.Instant.fromEpochSeconds(1_700_000_000)
            val t1 = Jwt.builder().subject("user").issuedAt(iat).signWith(SigningAlgorithm.ES256, keyPair.privateKey)
                .compact()
            val t2 = Jwt.builder().subject("user").issuedAt(iat).signWith(SigningAlgorithm.ES256, keyPair.privateKey)
                .compact()
            assertNotEquals(t1, t2, "ECDSA signatures should differ across calls due to random nonce")
        }
    }
})
