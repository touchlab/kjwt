@file:OptIn(dev.whyoleg.cryptography.DelicateCryptographyApi::class)

package co.touchlab.kjwt

import co.touchlab.kjwt.algorithm.JweContentAlgorithm
import co.touchlab.kjwt.algorithm.JweKeyAlgorithm
import co.touchlab.kjwt.exception.ExpiredJwtException
import co.touchlab.kjwt.exception.IncorrectClaimException
import co.touchlab.kjwt.exception.MalformedJwtException
import co.touchlab.kjwt.exception.SignatureException
import co.touchlab.kjwt.model.Claims
import co.touchlab.kjwt.model.JwtInstance
import co.touchlab.kjwt.model.audienceOrNull
import co.touchlab.kjwt.model.expirationOrNull
import co.touchlab.kjwt.model.getClaimOrNull
import co.touchlab.kjwt.model.issuedAtOrNull
import co.touchlab.kjwt.model.issuerOrNull
import co.touchlab.kjwt.model.jwtIdOrNull
import co.touchlab.kjwt.model.subjectOrNull
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours
import kotlinx.coroutines.test.runTest

class JweDecodeTest {

    // ---- Dir + GCM decryption ----

    @Test
    fun decryptDir_A128GCM_allClaims() = runTest {
        val cek = aesSimpleKey(128)
        val now = Clock.System.now()
        val token = Jwt.builder()
            .issuer("test-iss")
            .subject("test-sub")
            .audience("test-aud")
            .expiration(now + 1.hours)
            .issuedAt(now)
            .id("jti-1")
            .encryptWith(cek, JweKeyAlgorithm.Dir, JweContentAlgorithm.A128GCM)

        val jwe = Jwt.parser().decryptWith(JweKeyAlgorithm.Dir, cek).build().parseEncryptedClaims(token)

        assertEquals("test-iss", jwe.payload.issuerOrNull)
        assertEquals("test-sub", jwe.payload.subjectOrNull)
        assertEquals(setOf("test-aud"), jwe.payload.audienceOrNull)
        assertEquals(now.epochSeconds, jwe.payload.issuedAtOrNull?.epochSeconds)
        assertEquals("jti-1", jwe.payload.jwtIdOrNull)
        assertNotNull(jwe.payload.expirationOrNull)
    }

    @Test
    fun decryptDir_A192GCM_allClaims() = runTest {
        val cek = aesSimpleKey(192)
        val token = Jwt.builder()
            .subject("a192gcm-sub")
            .encryptWith(cek, JweKeyAlgorithm.Dir, JweContentAlgorithm.A192GCM)

        val jwe = Jwt.parser().decryptWith(JweKeyAlgorithm.Dir, cek).build().parseEncryptedClaims(token)
        assertEquals("a192gcm-sub", jwe.payload.subjectOrNull)
    }

    @Test
    fun decryptDir_A256GCM_allClaims() = runTest {
        val cek = aesSimpleKey(256)
        val token = Jwt.builder()
            .subject("a256gcm-sub")
            .encryptWith(cek, JweKeyAlgorithm.Dir, JweContentAlgorithm.A256GCM)

        val jwe = Jwt.parser().decryptWith(JweKeyAlgorithm.Dir, cek).build().parseEncryptedClaims(token)
        assertEquals("a256gcm-sub", jwe.payload.subjectOrNull)
    }

    @Test
    fun decryptDir_A128CbcHs256_allClaims() = runTest {
        val cek = aesSimpleKey(256) // 32 bytes
        val token = Jwt.builder()
            .subject("a128cbc-sub")
            .encryptWith(cek, JweKeyAlgorithm.Dir, JweContentAlgorithm.A128CbcHs256)

        val jwe = Jwt.parser().decryptWith(JweKeyAlgorithm.Dir, cek).build().parseEncryptedClaims(token)
        assertEquals("a128cbc-sub", jwe.payload.subjectOrNull)
    }

    @Test
    fun decryptDir_A192CbcHs384_allClaims() = runTest {
        val cek = aesSimpleKey(384) // 48 bytes
        val token = Jwt.builder()
            .subject("a192cbc-sub")
            .encryptWith(cek, JweKeyAlgorithm.Dir, JweContentAlgorithm.A192CbcHs384)

        val jwe = Jwt.parser().decryptWith(JweKeyAlgorithm.Dir, cek).build().parseEncryptedClaims(token)
        assertEquals("a192cbc-sub", jwe.payload.subjectOrNull)
    }

    @Test
    fun decryptDir_A256CbcHs512_allClaims() = runTest {
        val cek = aesSimpleKey(512) // 64 bytes
        val token = Jwt.builder()
            .subject("a256cbc-sub")
            .encryptWith(cek, JweKeyAlgorithm.Dir, JweContentAlgorithm.A256CbcHs512)

        val jwe = Jwt.parser().decryptWith(JweKeyAlgorithm.Dir, cek).build().parseEncryptedClaims(token)
        assertEquals("a256cbc-sub", jwe.payload.subjectOrNull)
    }

    @Test
    fun decryptRsaOaep_A256GCM_allClaims() = runTest {
        val keyPair = rsaOaepKeyPair()
        val token = Jwt.builder()
            .subject("rsa-oaep-sub")
            .encryptWith(keyPair.publicKey, JweKeyAlgorithm.RsaOaep, JweContentAlgorithm.A256GCM)

        val jwe =
            Jwt.parser().decryptWith(JweKeyAlgorithm.RsaOaep, keyPair.privateKey).build().parseEncryptedClaims(token)
        assertEquals("rsa-oaep-sub", jwe.payload.subjectOrNull)
    }

    @Test
    fun decryptRsaOaep256_A256GCM_allClaims() = runTest {
        val keyPair = rsaOaep256KeyPair()
        val token = Jwt.builder()
            .subject("rsa-oaep256-sub")
            .encryptWith(keyPair.publicKey, JweKeyAlgorithm.RsaOaep256, JweContentAlgorithm.A256GCM)

        val jwe =
            Jwt.parser().decryptWith(JweKeyAlgorithm.RsaOaep256, keyPair.privateKey).build().parseEncryptedClaims(token)
        assertEquals("rsa-oaep256-sub", jwe.payload.subjectOrNull)
    }

    @Test
    fun decryptRsaOaep256_A256CbcHs512_allClaims() = runTest {
        val keyPair = rsaOaep256KeyPair()
        val token = Jwt.builder()
            .subject("rsa-oaep256-cbc-sub")
            .encryptWith(keyPair.publicKey, JweKeyAlgorithm.RsaOaep256, JweContentAlgorithm.A256CbcHs512)

        val jwe =
            Jwt.parser().decryptWith(JweKeyAlgorithm.RsaOaep256, keyPair.privateKey).build().parseEncryptedClaims(token)
        assertEquals("rsa-oaep256-cbc-sub", jwe.payload.subjectOrNull)
    }

    // ---- Claim access ----

    @Test
    fun decryptDir_A256GCM_customClaims() = runTest {
        val cek = aesSimpleKey(256)
        val token = Jwt.builder()
            .claim("role", "admin")
            .claim("level", 7)
            .claim("active", true)
            .encryptWith(cek, JweKeyAlgorithm.Dir, JweContentAlgorithm.A256GCM)

        val jwe = Jwt.parser().decryptWith(JweKeyAlgorithm.Dir, cek).build().parseEncryptedClaims(token)

        assertEquals("admin", jwe.payload.getClaimOrNull<String>("role"))
        assertEquals(7, jwe.payload.getClaimOrNull<Int>("level"))
        assertEquals(true, jwe.payload.getClaimOrNull<Boolean>("active"))
    }

    @Test
    fun decryptDir_A256GCM_audienceNormalized() = runTest {
        val cek = aesSimpleKey(256)
        // Single audience — must come back as Set<String>
        val token = Jwt.builder()
            .audience("single-aud")
            .encryptWith(cek, JweKeyAlgorithm.Dir, JweContentAlgorithm.A256GCM)

        val jwe = Jwt.parser().decryptWith(JweKeyAlgorithm.Dir, cek).build().parseEncryptedClaims(token)
        assertEquals(setOf("single-aud"), jwe.payload.audienceOrNull)
    }

    // ---- Header fields ----

    @Test
    fun decryptDir_A256GCM_headerFields() = runTest {
        val cek = aesSimpleKey(256)
        val token = Jwt.builder()
            .subject("test")
            .encryptWith(cek, JweKeyAlgorithm.Dir, JweContentAlgorithm.A256GCM)

        val jwe = Jwt.parser().decryptWith(JweKeyAlgorithm.Dir, cek).build().parseEncryptedClaims(token)

        assertEquals("dir", jwe.header.algorithm)
        assertEquals("A256GCM", jwe.header.encryption)
        assertEquals("JWT", jwe.header.type)
    }

    // ---- Auto-detect ----

    @Test
    fun parseAutoDetect_jweToken_returnsJweClaims() = runTest {
        val cek = aesSimpleKey(256)
        val token = Jwt.builder()
            .subject("auto-detect-jwe")
            .encryptWith(cek, JweKeyAlgorithm.Dir, JweContentAlgorithm.A256GCM)

        val result = Jwt.parser().decryptWith(JweKeyAlgorithm.Dir, cek).build().parse(token)

        assertIs<JwtInstance.Jwe<Claims>>(result)
        assertEquals("auto-detect-jwe", result.payload.subjectOrNull)
    }

    // ---- Error cases ----

    @Test
    fun decryptDir_A256GCM_wrongKey_throwsSignatureException() = runTest {
        val cek = aesSimpleKey(256)
        val wrongCek = aesSimpleKey(256) // different random key

        val token = Jwt.builder()
            .subject("test")
            .encryptWith(cek, JweKeyAlgorithm.Dir, JweContentAlgorithm.A256GCM)

        assertFailsWith<SignatureException> {
            Jwt.parser().decryptWith(JweKeyAlgorithm.Dir, wrongCek).build().parseEncryptedClaims(token)
        }
    }

    @Test
    fun decryptRsaOaep_wrongPrivateKey_throwsJwtException() = runTest {
        val correctKeyPair = rsaOaepKeyPair()
        val wrongKeyPair = rsaOaepKeyPair()

        val token = Jwt.builder()
            .subject("test")
            .encryptWith(correctKeyPair.publicKey, JweKeyAlgorithm.RsaOaep, JweContentAlgorithm.A256GCM)

        assertFailsWith<SignatureException> {
            Jwt.parser().decryptWith(JweKeyAlgorithm.RsaOaep, wrongKeyPair.privateKey).build()
                .parseEncryptedClaims(token)
        }
    }

    @Test
    fun decryptDir_A256GCM_tamperedCiphertext_throwsSignatureException() = runTest {
        val cek = aesSimpleKey(256)
        val token = Jwt.builder()
            .subject("test")
            .encryptWith(cek, JweKeyAlgorithm.Dir, JweContentAlgorithm.A256GCM)

        val parts = token.split('.').toMutableList()
        // Corrupt the ciphertext (index 3) by appending 'X'
        parts[3] = parts[3] + "X"
        val tamperedToken = parts.joinToString(".")

        assertFailsWith<SignatureException> {
            Jwt.parser().decryptWith(JweKeyAlgorithm.Dir, cek).build().parseEncryptedClaims(tamperedToken)
        }
    }

    @Test
    fun decryptDir_A256GCM_tamperedTag_throwsSignatureException() = runTest {
        val cek = aesSimpleKey(256)
        val token = Jwt.builder()
            .subject("test")
            .encryptWith(cek, JweKeyAlgorithm.Dir, JweContentAlgorithm.A256GCM)

        val parts = token.split('.').toMutableList()
        // Corrupt the tag (index 4)
        val tag = parts[4]
        parts[4] = tag.dropLast(1) + (if (tag.last() == 'A') 'B' else 'A')
        val tamperedToken = parts.joinToString(".")

        assertFailsWith<SignatureException> {
            Jwt.parser().decryptWith(JweKeyAlgorithm.Dir, cek).build().parseEncryptedClaims(tamperedToken)
        }
    }

    @Test
    fun decryptDir_A256GCM_tamperedIv_throwsSignatureException() = runTest {
        val cek = aesSimpleKey(256)
        val token = Jwt.builder()
            .subject("test")
            .encryptWith(cek, JweKeyAlgorithm.Dir, JweContentAlgorithm.A256GCM)

        val parts = token.split('.').toMutableList()
        // Corrupt the IV (index 2)
        val iv = parts[2]
        parts[2] = iv.dropLast(1) + (if (iv.last() == 'A') 'B' else 'A')
        val tamperedToken = parts.joinToString(".")

        assertFailsWith<SignatureException> {
            Jwt.parser().decryptWith(JweKeyAlgorithm.Dir, cek).build().parseEncryptedClaims(tamperedToken)
        }
    }

    @Test
    fun decryptDir_wrongFiveParts_throwsMalformedJwtException() = runTest {
        val cek = aesSimpleKey(256)
        // Pass a 3-part JWS token to parseEncryptedClaims
        assertFailsWith<MalformedJwtException> {
            Jwt.parser()
                .decryptWith(JweKeyAlgorithm.Dir, cek)
                .build()
                .parseEncryptedClaims("eyJhbGciOiJkaXIifQ.eyJzdWIiOiJ0ZXN0In0.signature")
        }
    }

    @Test
    fun decryptDir_A256GCM_expiredPayload_throwsExpiredJwtException() = runTest {
        val cek = aesSimpleKey(256)
        val token = Jwt.builder()
            .subject("test")
            .expiration(Clock.System.now() - 1.hours) // already expired
            .encryptWith(cek, JweKeyAlgorithm.Dir, JweContentAlgorithm.A256GCM)

        assertFailsWith<ExpiredJwtException> {
            Jwt.parser().decryptWith(JweKeyAlgorithm.Dir, cek).build().parseEncryptedClaims(token)
        }
    }

    @Test
    fun decryptDir_A256GCM_issuerMismatch_throwsIncorrectClaimException() = runTest {
        val cek = aesSimpleKey(256)
        val token = Jwt.builder()
            .issuer("actual-issuer")
            .encryptWith(cek, JweKeyAlgorithm.Dir, JweContentAlgorithm.A256GCM)

        assertFailsWith<IncorrectClaimException> {
            Jwt.parser()
                .decryptWith(JweKeyAlgorithm.Dir, cek)
                .requireIssuer("expected-issuer")
                .build()
                .parseEncryptedClaims(token)
        }
    }
}
