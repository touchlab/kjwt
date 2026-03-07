package co.touchlab.kjwt.ext

import co.touchlab.kjwt.Jwt
import co.touchlab.kjwt.algorithm.JweContentAlgorithm
import co.touchlab.kjwt.algorithm.JweKeyAlgorithm
import co.touchlab.kjwt.algorithm.JwsAlgorithm
import co.touchlab.kjwt.cryptography.SimpleKey
import co.touchlab.kjwt.ecKeyPair
import co.touchlab.kjwt.hs256Key
import co.touchlab.kjwt.hs256Secret
import co.touchlab.kjwt.hs384Key
import co.touchlab.kjwt.hs384Secret
import co.touchlab.kjwt.hs512Key
import co.touchlab.kjwt.hs512Secret
import co.touchlab.kjwt.model.subjectOrNull
import co.touchlab.kjwt.rsaPkcs1KeyPair
import co.touchlab.kjwt.rsaPssKeyPair
import dev.whyoleg.cryptography.algorithms.EC
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.algorithms.SHA384
import dev.whyoleg.cryptography.algorithms.SHA512
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.test.runTest

class JwtBuilderExtTest {

    // ---- signWith(String key) — HMAC ----

    @Test
    fun signHs256_stringKey_roundTrip() = runTest {
        val token = Jwt.builder()
            .subject("ext-hs256")
            .signWith(JwsAlgorithm.HS256, hs256Secret.decodeToString(), HMAC.Key.Format.RAW)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.HS256, hs256Key())
            .build()
            .parseSignedClaims(token)

        assertEquals("HS256", jws.header.algorithm)
        assertEquals("ext-hs256", jws.payload.subjectOrNull)
    }

    @Test
    fun signHs384_stringKey_roundTrip() = runTest {
        val token = Jwt.builder()
            .subject("ext-hs384")
            .signWith(JwsAlgorithm.HS384, hs384Secret.decodeToString(), HMAC.Key.Format.RAW)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.HS384, hs384Key())
            .build()
            .parseSignedClaims(token)

        assertEquals("ext-hs384", jws.payload.subjectOrNull)
    }

    @Test
    fun signHs512_stringKey_roundTrip() = runTest {
        val token = Jwt.builder()
            .subject("ext-hs512")
            .signWith(JwsAlgorithm.HS512, hs512Secret.decodeToString(), HMAC.Key.Format.RAW)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.HS512, hs512Key())
            .build()
            .parseSignedClaims(token)

        assertEquals("ext-hs512", jws.payload.subjectOrNull)
    }

    // ---- signWith(String key) — RSA PKCS1 ----
    // PEM is used because PEM is ASCII and survives the String → encodeToByteArray() round-trip.

    @Test
    fun signRs256_stringPemKey_roundTrip() = runTest {
        val keyPair = rsaPkcs1KeyPair()
        val privatePem = keyPair.privateKey.encodeToByteArray(RSA.PrivateKey.Format.PEM).decodeToString()

        val token = Jwt.builder()
            .subject("ext-rs256")
            .signWith(JwsAlgorithm.RS256, privatePem, RSA.PrivateKey.Format.PEM)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.RS256, keyPair.publicKey)
            .build()
            .parseSignedClaims(token)

        assertEquals("RS256", jws.header.algorithm)
        assertEquals("ext-rs256", jws.payload.subjectOrNull)
    }

    @Test
    fun signRs512_stringPemKey_roundTrip() = runTest {
        val keyPair = rsaPkcs1KeyPair(SHA512)
        val privatePem = keyPair.privateKey.encodeToByteArray(RSA.PrivateKey.Format.PEM).decodeToString()

        val token = Jwt.builder()
            .subject("ext-rs512")
            .signWith(JwsAlgorithm.RS512, privatePem, RSA.PrivateKey.Format.PEM)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.RS512, keyPair.publicKey)
            .build()
            .parseSignedClaims(token)

        assertEquals("ext-rs512", jws.payload.subjectOrNull)
    }

    // ---- signWith(String key) — RSA PSS ----

    @Test
    fun signPs256_stringPemKey_roundTrip() = runTest {
        val keyPair = rsaPssKeyPair()
        val privatePem = keyPair.privateKey.encodeToByteArray(RSA.PrivateKey.Format.PEM).decodeToString()

        val token = Jwt.builder()
            .subject("ext-ps256")
            .signWith(JwsAlgorithm.PS256, privatePem, RSA.PrivateKey.Format.PEM)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.PS256, keyPair.publicKey)
            .build()
            .parseSignedClaims(token)

        assertEquals("PS256", jws.header.algorithm)
        assertEquals("ext-ps256", jws.payload.subjectOrNull)
    }

    @Test
    fun signPs384_stringPemKey_roundTrip() = runTest {
        val keyPair = rsaPssKeyPair(SHA384)
        val privatePem = keyPair.privateKey.encodeToByteArray(RSA.PrivateKey.Format.PEM).decodeToString()

        val token = Jwt.builder()
            .subject("ext-ps384")
            .signWith(JwsAlgorithm.PS384, privatePem, RSA.PrivateKey.Format.PEM)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.PS384, keyPair.publicKey)
            .build()
            .parseSignedClaims(token)

        assertEquals("ext-ps384", jws.payload.subjectOrNull)
    }

    // ---- signWith(String key) — ECDSA ----

    @Test
    fun signEs256_stringPemKey_roundTrip() = runTest {
        val keyPair = ecKeyPair(EC.Curve.P256)
        val privatePem = keyPair.privateKey.encodeToByteArray(EC.PrivateKey.Format.PEM).decodeToString()

        val token = Jwt.builder()
            .subject("ext-es256")
            .signWith(JwsAlgorithm.ES256, privatePem, EC.PrivateKey.Format.PEM)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.ES256, keyPair.publicKey)
            .build()
            .parseSignedClaims(token)

        assertEquals("ES256", jws.header.algorithm)
        assertEquals("ext-es256", jws.payload.subjectOrNull)
    }

    @Test
    fun signEs512_stringPemKey_roundTrip() = runTest {
        val keyPair = ecKeyPair(EC.Curve.P521)
        val privatePem = keyPair.privateKey.encodeToByteArray(EC.PrivateKey.Format.PEM).decodeToString()

        val token = Jwt.builder()
            .subject("ext-es512")
            .signWith(JwsAlgorithm.ES512, privatePem, EC.PrivateKey.Format.PEM)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.ES512, keyPair.publicKey)
            .build()
            .parseSignedClaims(token)

        assertEquals("ext-es512", jws.payload.subjectOrNull)
    }

    // ---- encryptWith(ByteArray) ----

    @Test
    fun encryptWith_byteArrayKey_roundTrip() = runTest {
        val keyBytes = Random.nextBytes(32) // 256-bit key for A256GCM

        val token = Jwt.builder()
            .subject("ext-encrypt-bytes")
            .encryptWith(keyBytes, JweKeyAlgorithm.Dir, JweContentAlgorithm.A256GCM)

        val jwe = Jwt.parser()
            .decryptWith(JweKeyAlgorithm.Dir, SimpleKey(keyBytes))
            .build()
            .parseEncryptedClaims(token)

        assertEquals("ext-encrypt-bytes", jwe.payload.subjectOrNull)
    }

    @Test
    fun encryptWith_byteArrayKey_cbcAlgorithm_roundTrip() = runTest {
        val keyBytes = Random.nextBytes(64) // 512-bit key for A256CBC-HS512

        val token = Jwt.builder()
            .subject("ext-encrypt-cbc")
            .encryptWith(keyBytes, JweKeyAlgorithm.Dir, JweContentAlgorithm.A256CbcHs512)

        val jwe = Jwt.parser()
            .decryptWith(JweKeyAlgorithm.Dir, SimpleKey(keyBytes))
            .build()
            .parseEncryptedClaims(token)

        assertEquals("ext-encrypt-cbc", jwe.payload.subjectOrNull)
    }

    // ---- encryptWith(String) ----

    @Test
    fun encryptWith_stringKey_roundTrip() = runTest {
        // 32 ASCII chars → 32 bytes → 256-bit key for A256GCM
        val keyString = "12345678901234567890123456789012"

        val token = Jwt.builder()
            .subject("ext-encrypt-string")
            .encryptWith(keyString, JweKeyAlgorithm.Dir, JweContentAlgorithm.A256GCM)

        val jwe = Jwt.parser()
            .decryptWith(JweKeyAlgorithm.Dir, SimpleKey(keyString.encodeToByteArray()))
            .build()
            .parseEncryptedClaims(token)

        assertEquals("ext-encrypt-string", jwe.payload.subjectOrNull)
    }
}