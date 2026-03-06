package co.touchlab.kjwt

import co.touchlab.kjwt.algorithm.JweKeyAlgorithm
import co.touchlab.kjwt.algorithm.JwsAlgorithm
import co.touchlab.kjwt.exception.MalformedJwtException
import co.touchlab.kjwt.exception.SignatureException
import co.touchlab.kjwt.exception.UnsupportedJwtException
import dev.whyoleg.cryptography.materials.key.EncodableKey
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlinx.coroutines.test.runTest

class MalformedTokenTest {

    // ---- Structure errors ----

    @Test
    fun parse_emptyString_throwsMalformedJwtException() = runTest {
        val key = hs256Key()
        assertFailsWith<MalformedJwtException> {
            Jwt.parser().verifyWith(JwsAlgorithm.HS256, key).build().parseSignedClaims("")
        }
    }

    @Test
    fun parse_onlyTwoParts_throwsMalformedJwtException() = runTest {
        val key = hs256Key()
        assertFailsWith<MalformedJwtException> {
            Jwt.parser()
                .verifyWith(JwsAlgorithm.HS256, key)
                .build()
                .parseSignedClaims("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0")
        }
    }

    @Test
    fun parse_fourParts_forJws_throwsMalformedJwtException() = runTest {
        val key = hs256Key()
        assertFailsWith<MalformedJwtException> {
            Jwt.parser()
                .verifyWith(JwsAlgorithm.HS256, key)
                .build()
                .parseSignedClaims("part1.part2.part3.part4")
        }
    }

    @Test
    fun parse_headerNotBase64_throwsMalformedJwtException() = runTest {
        val key = hs256Key()
        assertFailsWith<MalformedJwtException> {
            Jwt.parser()
                .verifyWith(JwsAlgorithm.HS256, key)
                .build()
                // First part contains invalid base64url characters
                .parseSignedClaims("not!!valid!!base64.eyJzdWIiOiJ0ZXN0In0.signature")
        }
    }

    @Test
    fun parse_headerNotJson_throwsMalformedJwtException() = runTest {
        val key = hs256Key()
        // Valid base64url but not JSON: "not-json"
        val notJsonB64 = "bm90LWpzb24" // base64url("not-json")
        assertFailsWith<MalformedJwtException> {
            Jwt.parser()
                .verifyWith(JwsAlgorithm.HS256, key)
                .build()
                .parseSignedClaims("$notJsonB64.eyJzdWIiOiJ0ZXN0In0.signature")
        }
    }

    @Test
    fun parse_payloadNotJson_throwsMalformedJwtException() = runTest {
        val key = hs256Key()
        // Valid HS256 header B64
        val headerB64 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        // Valid base64url but not JSON: "not-json"
        val notJsonB64 = "bm90LWpzb24"
        assertFailsWith<MalformedJwtException> {
            Jwt.parser()
                .verifyWith(JwsAlgorithm.HS256, key)
                .build()
                .parseSignedClaims("$headerB64.$notJsonB64.signature")
        }
    }

    // ---- Signature errors ----

    @Test
    fun parse_tamperedPayload_throwsSignatureException() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .subject("original-subject")
            .signWith(JwsAlgorithm.HS256, key)

        val parts = token.split('.')
        // Replace the payload with a different base64url payload ({"sub":"hacked"})
        val tamperedPayload = "eyJzdWIiOiJoYWNrZWQifQ"
        val tamperedToken = "${parts[0]}.$tamperedPayload.${parts[2]}"

        assertFailsWith<SignatureException> {
            Jwt.parser()
                .verifyWith(JwsAlgorithm.HS256, key)
                .build()
                .parseSignedClaims(tamperedToken)
        }
    }

    @Test
    fun parse_tamperedSignature_throwsSignatureException() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .subject("user")
            .signWith(JwsAlgorithm.HS256, key)

        val parts = token.split('.')
        // Replace last char of signature to corrupt it
        val sig = parts[2]
        val corruptedSig = sig.dropLast(1) + (if (sig.last() == 'A') 'B' else 'A')
        val tamperedToken = "${parts[0]}.${parts[1]}.$corruptedSig"

        assertFailsWith<SignatureException> {
            Jwt.parser()
                .verifyWith(JwsAlgorithm.HS256, key)
                .build()
                .parseSignedClaims(tamperedToken)
        }
    }

    @Test
    fun parse_wrongKey_throwsSignatureException() = runTest {
        val signingKey = hs256Key()
        val wrongKey = hmacKey(
            dev.whyoleg.cryptography.algorithms.SHA256,
            "completely-different-secret-key-here".encodeToByteArray(),
        )

        val token = Jwt.builder()
            .subject("user")
            .signWith(JwsAlgorithm.HS256, signingKey)

        assertFailsWith<SignatureException> {
            Jwt.parser()
                .verifyWith(JwsAlgorithm.HS256, wrongKey)
                .build()
                .parseSignedClaims(token)
        }
    }

    @Test
    fun parse_wrongPublicKey_throwsSignatureException() = runTest {
        val signingKeyPair = rsaPkcs1KeyPair()
        val differentKeyPair = rsaPkcs1KeyPair()

        val token = Jwt.builder()
            .subject("user")
            .signWith(JwsAlgorithm.RS256, signingKeyPair.privateKey)

        val algo: JwsAlgorithm<EncodableKey<*>> = JwsAlgorithm.RS256
        assertFailsWith<SignatureException> {
            Jwt.parser()
                .verifyWith(algo, differentKeyPair.publicKey) // wrong public key
                .build()
                .parseSignedClaims(token)
        }
    }

    // ---- Algorithm errors ----

    @Test
    fun parse_none_withoutAllowUnsecured_throwsUnsupportedJwtException() = runTest {
        val noneToken = Jwt.builder()
            .subject("user")
            .signWith(JwsAlgorithm.None)

        assertFailsWith<UnsupportedJwtException> {
            Jwt.parser()
                // No allowUnsecured(true) call
                .build()
                .parseSignedClaims(noneToken)
        }
    }

    @Test
    fun parse_unknownAlgorithm_throwsUnsupportedJwtException() = runTest {
        // Craft a token with an unknown algorithm in the header
        // Header: {"alg":"XY999","typ":"JWT"} -> base64url
        val fakeHeaderB64 = "eyJhbGciOiJYWTk5OSIsInR5cCI6IkpXVCJ9"
        val payloadB64 = "eyJzdWIiOiJ1c2VyIn0"
        val fakeToken = "$fakeHeaderB64.$payloadB64.fakesig"

        val key = hs256Key()
        assertFailsWith<UnsupportedJwtException> {
            Jwt.parser()
                .verifyWith(JwsAlgorithm.HS256, key)
                .build()
                .parseSignedClaims(fakeToken)
        }
    }

    @Test
    fun parse_algorithmMismatch_noMatchingVerifier_throwsIllegalState() = runTest {
        val rsaKeyPair = rsaPkcs1KeyPair()
        // Token signed with RS256
        val token = Jwt.builder()
            .subject("user")
            .signWith(JwsAlgorithm.RS256, rsaKeyPair.privateKey)

        val hs256Key = hs256Key()
        // Parser configured only with HS256 verifier, but token is RS256
        assertFailsWith<IllegalStateException> {
            Jwt.parser()
                .verifyWith(JwsAlgorithm.HS256, hs256Key)
                .build()
                .parseSignedClaims(token)
        }
    }

    // ---- JWE structure errors from parseSignedClaims ----

    @Test
    fun parseSignedClaims_fiveParts_throwsMalformedJwtException() = runTest {
        val key = hs256Key()
        // A 5-part token passed to parseSignedClaims (JWS expects 3)
        assertFailsWith<MalformedJwtException> {
            Jwt.parser()
                .verifyWith(JwsAlgorithm.HS256, key)
                .build()
                .parseSignedClaims("a.b.c.d.e")
        }
    }

    @Test
    fun parseEncryptedClaims_threeParts_throwsMalformedJwtException() = runTest {
        val cek = aesSimpleKey(256)
        // A 3-part token passed to parseEncryptedClaims (JWE expects 5)
        assertFailsWith<MalformedJwtException> {
            Jwt.parser()
                .decryptWith(JweKeyAlgorithm.RsaOaep, cek)
                .build()
                .parseEncryptedClaims("a.b.c")
        }
    }

    @Test
    fun parse_autoDetect_wrongPartCount_throwsMalformedJwtException() = runTest {
        val key = hs256Key()
        assertFailsWith<MalformedJwtException> {
            Jwt.parser()
                .verifyWith(JwsAlgorithm.HS256, key)
                .build()
                .parse("a.b.c.d") // 4 parts — neither JWS nor JWE
        }
    }
}
