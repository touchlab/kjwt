package co.touchlab.kjwt

import co.touchlab.kjwt.algorithm.JwsAlgorithm
import co.touchlab.kjwt.model.audienceOrNull
import co.touchlab.kjwt.model.expirationOrNull
import co.touchlab.kjwt.model.getClaimOrNull
import co.touchlab.kjwt.model.issuedAtOrNull
import co.touchlab.kjwt.model.issuerOrNull
import co.touchlab.kjwt.model.jwtIdOrNull
import co.touchlab.kjwt.model.notBeforeOrNull
import co.touchlab.kjwt.model.subjectOrNull
import dev.whyoleg.cryptography.algorithms.EC
import dev.whyoleg.cryptography.algorithms.SHA384
import dev.whyoleg.cryptography.algorithms.SHA512
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonPrimitive

class JwsEncodeTest {

    // ---- HMAC known-token tests ----

    @Test
    fun signHs256_producesKnownToken() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .subject("1234567890")
            .claim("name", "John Doe")
            .claim("admin", true)
            .issuedAt(kotlin.time.Instant.fromEpochSeconds(1516239022))
            .signWith(JwsAlgorithm.HS256, key)

        assertEquals(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
                    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0" +
                    ".KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30",
            token,
        )
    }

    @Test
    fun signHs384_roundTrip() = runTest {
        val key = hs384Key()
        val token = Jwt.builder()
            .subject("user-384")
            .issuedAt(kotlin.time.Instant.fromEpochSeconds(1516239022))
            .signWith(JwsAlgorithm.HS384, key)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.HS384, key)
            .build()
            .parseSignedClaims(token)

        assertEquals("HS384", jws.header.algorithm)
        assertEquals("user-384", jws.payload.subjectOrNull)
    }

    @Test
    fun signHs512_roundTrip() = runTest {
        val key = hs512Key()
        val token = Jwt.builder()
            .subject("user-512")
            .issuedAt(kotlin.time.Instant.fromEpochSeconds(1516239022))
            .signWith(JwsAlgorithm.HS512, key)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.HS512, key)
            .build()
            .parseSignedClaims(token)

        assertEquals("HS512", jws.header.algorithm)
        assertEquals("user-512", jws.payload.subjectOrNull)
    }

    // ---- All registered claims ----

    @Test
    fun signHs256_withAllRegisteredClaims() = runTest {
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
            .signWith(JwsAlgorithm.HS256, key)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.HS256, key)
            .build()
            .parseSignedClaims(token)

        assertEquals("test-issuer", jws.payload.issuerOrNull)
        assertEquals("test-subject", jws.payload.subjectOrNull)
        assertEquals(setOf("test-audience"), jws.payload.audienceOrNull)
        assertEquals((now + 1.hours).epochSeconds, jws.payload.expirationOrNull?.epochSeconds)
        assertEquals((now - 1.hours).epochSeconds, jws.payload.notBeforeOrNull?.epochSeconds)
        assertEquals(now.epochSeconds, jws.payload.issuedAtOrNull?.epochSeconds)
        assertEquals("unique-jwt-id", jws.payload.jwtIdOrNull)
    }

    // ---- Custom claims ----

    @Test
    fun signHs256_withCustomClaims() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .claim("strClaim", "hello")
            .claim("numClaim", 42)
            .claim("boolClaim", true)
            .signWith(JwsAlgorithm.HS256, key)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.HS256, key)
            .build()
            .parseSignedClaims(token)

        assertEquals("hello", jws.payload.getClaimOrNull<String>("strClaim"))
        assertEquals(42, jws.payload.getClaimOrNull<Int>("numClaim"))
        assertEquals(true, jws.payload.getClaimOrNull<Boolean>("boolClaim"))
    }

    // ---- Audience serialization ----

    @Test
    fun signHs256_audienceSingleString() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .audience("single-aud")
            .signWith(JwsAlgorithm.HS256, key)

        val payloadJson = decodeTokenPayload(token)
        // Single audience must be serialized as a plain string, not an array
        assertTrue(payloadJson.contains("\"aud\":\"single-aud\""), "Expected plain string aud, got: $payloadJson")
    }

    @Test
    fun signHs256_audienceMultiple() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .audience("aud1", "aud2", "aud3")
            .signWith(JwsAlgorithm.HS256, key)

        val payloadJson = decodeTokenPayload(token)
        // Multiple audiences must be serialized as JSON array
        assertTrue(payloadJson.contains("\"aud\":["), "Expected array aud, got: $payloadJson")
    }

    // ---- Header fields ----

    @Test
    fun signHs256_headerKidIncluded() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .keyId("my-key-id")
            .subject("test")
            .signWith(JwsAlgorithm.HS256, key)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.HS256, key)
            .build()
            .parseSignedClaims(token)

        assertEquals("my-key-id", jws.header.keyId)
    }

    @Test
    fun signHs256_customHeaderFields() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .header { extra("x-custom", JsonPrimitive("custom-value")) }
            .subject("test")
            .signWith(JwsAlgorithm.HS256, key)

        val headerJson = decodeTokenHeader(token)
        assertTrue(headerJson.contains("x-custom"), "Expected custom header field, got: $headerJson")
    }

    // ---- RSA PKCS1 round-trips ----

    @Test
    fun signRs256_roundTrip() = runTest {
        val keyPair = rsaPkcs1KeyPair()
        val token = Jwt.builder()
            .subject("rs256-subject")
            .signWith(JwsAlgorithm.RS256, keyPair.privateKey)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.RS256, keyPair.publicKey)
            .build()
            .parseSignedClaims(token)

        assertEquals("RS256", jws.header.algorithm)
        assertEquals("rs256-subject", jws.payload.subjectOrNull)
    }

    @Test
    fun signRs384_roundTrip() = runTest {
        val keyPair = rsaPkcs1KeyPair(SHA384)
        val token = Jwt.builder()
            .subject("rs384-subject")
            .signWith(JwsAlgorithm.RS384, keyPair.privateKey)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.RS384, keyPair.publicKey)
            .build()
            .parseSignedClaims(token)

        assertEquals("rs384-subject", jws.payload.subjectOrNull)
    }

    @Test
    fun signRs512_roundTrip() = runTest {
        val keyPair = rsaPkcs1KeyPair(SHA512)
        val token = Jwt.builder()
            .subject("rs512-subject")
            .signWith(JwsAlgorithm.RS512, keyPair.privateKey)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.RS512, keyPair.publicKey)
            .build()
            .parseSignedClaims(token)

        assertEquals("rs512-subject", jws.payload.subjectOrNull)
    }

    // ---- RSA PSS round-trips ----

    @Test
    fun signPs256_roundTrip() = runTest {
        val keyPair = rsaPssKeyPair()
        val token = Jwt.builder()
            .subject("ps256-subject")
            .signWith(JwsAlgorithm.PS256, keyPair.privateKey)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.PS256, keyPair.publicKey)
            .build()
            .parseSignedClaims(token)

        assertEquals("PS256", jws.header.algorithm)
        assertEquals("ps256-subject", jws.payload.subjectOrNull)
    }

    @Test
    fun signPs384_roundTrip() = runTest {
        val keyPair = rsaPssKeyPair(SHA384)
        val token = Jwt.builder()
            .subject("ps384-subject")
            .signWith(JwsAlgorithm.PS384, keyPair.privateKey)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.PS384, keyPair.publicKey)
            .build()
            .parseSignedClaims(token)

        assertEquals("ps384-subject", jws.payload.subjectOrNull)
    }

    @Test
    fun signPs512_roundTrip() = runTest {
        val keyPair = rsaPssKeyPair(SHA512)
        val token = Jwt.builder()
            .subject("ps512-subject")
            .signWith(JwsAlgorithm.PS512, keyPair.privateKey)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.PS512, keyPair.publicKey)
            .build()
            .parseSignedClaims(token)

        assertEquals("ps512-subject", jws.payload.subjectOrNull)
    }

    // ---- ECDSA round-trips ----

    @Test
    fun signEs256_roundTrip() = runTest {
        val keyPair = ecKeyPair(EC.Curve.P256)
        val token = Jwt.builder()
            .subject("es256-subject")
            .signWith(JwsAlgorithm.ES256, keyPair.privateKey)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.ES256, keyPair.publicKey)
            .build()
            .parseSignedClaims(token)

        assertEquals("ES256", jws.header.algorithm)
        assertEquals("es256-subject", jws.payload.subjectOrNull)
    }

    @Test
    fun signEs384_roundTrip() = runTest {
        val keyPair = ecKeyPair(EC.Curve.P384)
        val token = Jwt.builder()
            .subject("es384-subject")
            .signWith(JwsAlgorithm.ES384, keyPair.privateKey)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.ES384, keyPair.publicKey)
            .build()
            .parseSignedClaims(token)

        assertEquals("es384-subject", jws.payload.subjectOrNull)
    }

    @Test
    fun signEs512_roundTrip() = runTest {
        val keyPair = ecKeyPair(EC.Curve.P521)
        val token = Jwt.builder()
            .subject("es512-subject")
            .signWith(JwsAlgorithm.ES512, keyPair.privateKey)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.ES512, keyPair.publicKey)
            .build()
            .parseSignedClaims(token)

        assertEquals("es512-subject", jws.payload.subjectOrNull)
    }

    @Test
    fun signEs256_signatureIsRawFormat() = runTest {
        // ES256 RAW signature = R‖S, each 32 bytes for P-256 → 64 bytes total
        val keyPair = ecKeyPair(EC.Curve.P256)
        val token = Jwt.builder()
            .subject("test")
            .signWith(JwsAlgorithm.ES256, keyPair.privateKey)

        val signatureB64 = token.split('.')[2]
        val signatureBytes = decodeBase64Url(signatureB64)
        assertEquals(64, signatureBytes.size, "ES256 RAW signature must be exactly 64 bytes (R‖S for P-256)")
    }

    // ---- None algorithm ----

    @Test
    fun signNone_producesEmptySignaturePart() = runTest {
        val token = Jwt.builder()
            .subject("test")
            .signWith(JwsAlgorithm.None)

        val parts = token.split('.')
        assertEquals(3, parts.size)
        assertTrue(token.endsWith("."), "None token must end with '.'")
        assertEquals("", parts[2], "Signature part must be empty for alg=none")
    }

    @Test
    fun signHs256_twoCallsProduceSameToken() = runTest {
        // HMAC is deterministic — same input must produce the same token
        val key = hs256Key()
        val iat = kotlin.time.Instant.fromEpochSeconds(1_700_000_000)
        val t1 = Jwt.builder().subject("user").issuedAt(iat).signWith(JwsAlgorithm.HS256, key)
        val t2 = Jwt.builder().subject("user").issuedAt(iat).signWith(JwsAlgorithm.HS256, key)
        assertEquals(t1, t2)
    }

    @Test
    fun signEs256_twoCallsProduceDifferentTokens() = runTest {
        // ECDSA is non-deterministic (uses random nonce) — different signatures each call
        val keyPair = ecKeyPair(EC.Curve.P256)
        val iat = kotlin.time.Instant.fromEpochSeconds(1_700_000_000)
        val t1 = Jwt.builder().subject("user").issuedAt(iat).signWith(JwsAlgorithm.ES256, keyPair.privateKey)
        val t2 = Jwt.builder().subject("user").issuedAt(iat).signWith(JwsAlgorithm.ES256, keyPair.privateKey)
        assertNotEquals(t1, t2, "ECDSA signatures should differ across calls due to random nonce")
    }
}
