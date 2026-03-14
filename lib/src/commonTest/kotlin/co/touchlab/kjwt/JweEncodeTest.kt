@file:OptIn(dev.whyoleg.cryptography.DelicateCryptographyApi::class)

package co.touchlab.kjwt

import co.touchlab.kjwt.ext.subjectOrNull
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.EncryptionContentAlgorithm
import io.kotest.core.spec.style.FunSpec
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class JweEncodeTest : FunSpec({

    context("Dir + GCM round-trips") {

        test("encrypt Dir A128GCM round trip") {
            val cek = aesSimpleKey(128)
            val token = Jwt.builder()
                .subject("a128gcm-user")
                .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A128GCM)
                .compact()

            val jwe = Jwt.parser()
                .decryptWith(EncryptionAlgorithm.Dir, cek)
                .build()
                .parseEncrypted(token)

            assertEquals("a128gcm-user", jwe.payload.subjectOrNull)
        }

        test("encrypt Dir A192GCM round trip").config(enabled = !isWebBrowserPlatform()) {
            val cek = aesSimpleKey(192)
            val token = Jwt.builder()
                .subject("a192gcm-user")
                .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A192GCM)
                .compact()

            val jwe = Jwt.parser()
                .decryptWith(EncryptionAlgorithm.Dir, cek)
                .build()
                .parseEncrypted(token)

            assertEquals("a192gcm-user", jwe.payload.subjectOrNull)
        }

        test("encrypt Dir A256GCM round trip") {
            val cek = aesSimpleKey(256)
            val token = Jwt.builder()
                .subject("a256gcm-user")
                .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A256GCM)
                .compact()

            val jwe = Jwt.parser()
                .decryptWith(EncryptionAlgorithm.Dir, cek)
                .build()
                .parseEncrypted(token)

            assertEquals("a256gcm-user", jwe.payload.subjectOrNull)
        }
    }

    context("Dir + CBC-HMAC round-trips") {

        test("encrypt Dir A128CbcHs256 round trip") {
            val cek = aesSimpleKey(256) // 32 bytes: 16 MAC + 16 ENC
            val token = Jwt.builder()
                .subject("a128cbc-user")
                .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A128CbcHs256)
                .compact()

            val jwe = Jwt.parser()
                .decryptWith(EncryptionAlgorithm.Dir, cek)
                .build()
                .parseEncrypted(token)

            assertEquals("a128cbc-user", jwe.payload.subjectOrNull)
        }

        test("encrypt Dir A192CbcHs384 round trip").config(enabled = !isWebBrowserPlatform()) {
            val cek = aesSimpleKey(384) // 48 bytes: 24 MAC + 24 ENC
            val token = Jwt.builder()
                .subject("a192cbc-user")
                .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A192CbcHs384)
                .compact()

            val jwe = Jwt.parser()
                .decryptWith(EncryptionAlgorithm.Dir, cek)
                .build()
                .parseEncrypted(token)

            assertEquals("a192cbc-user", jwe.payload.subjectOrNull)
        }

        test("encrypt Dir A256CbcHs512 round trip") {
            val cek = aesSimpleKey(512) // 64 bytes: 32 MAC + 32 ENC
            val token = Jwt.builder()
                .subject("a256cbc-user")
                .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A256CbcHs512)
                .compact()

            val jwe = Jwt.parser()
                .decryptWith(EncryptionAlgorithm.Dir, cek)
                .build()
                .parseEncrypted(token)

            assertEquals("a256cbc-user", jwe.payload.subjectOrNull)
        }
    }

    context("RSA-OAEP (SHA-1) round-trips") {

        test("encrypt RsaOaep A128GCM round trip") {
            val keyPair = rsaOaepKeyPair()
            val token = Jwt.builder()
                .subject("rsa-oaep-a128gcm")
                .encryptWith(keyPair.publicKey, EncryptionAlgorithm.RsaOaep, EncryptionContentAlgorithm.A128GCM)
                .compact()

            val jwe = Jwt.parser()
                .decryptWith(EncryptionAlgorithm.RsaOaep, keyPair.privateKey)
                .build()
                .parseEncrypted(token)

            assertEquals("rsa-oaep-a128gcm", jwe.payload.subjectOrNull)
        }

        test("encrypt RsaOaep A256GCM round trip") {
            val keyPair = rsaOaepKeyPair()
            val token = Jwt.builder()
                .subject("rsa-oaep-a256gcm")
                .encryptWith(keyPair.publicKey, EncryptionAlgorithm.RsaOaep, EncryptionContentAlgorithm.A256GCM)
                .compact()

            val jwe = Jwt.parser()
                .decryptWith(EncryptionAlgorithm.RsaOaep, keyPair.privateKey)
                .build()
                .parseEncrypted(token)

            assertEquals("rsa-oaep-a256gcm", jwe.payload.subjectOrNull)
        }

        test("encrypt RsaOaep A256CbcHs512 round trip") {
            val keyPair = rsaOaepKeyPair()
            val token = Jwt.builder()
                .subject("rsa-oaep-cbc512")
                .encryptWith(keyPair.publicKey, EncryptionAlgorithm.RsaOaep, EncryptionContentAlgorithm.A256CbcHs512)
                .compact()

            val jwe = Jwt.parser()
                .decryptWith(EncryptionAlgorithm.RsaOaep, keyPair.privateKey)
                .build()
                .parseEncrypted(token)

            assertEquals("rsa-oaep-cbc512", jwe.payload.subjectOrNull)
        }
    }

    context("RSA-OAEP-256 (SHA-256) round-trips") {

        test("encrypt RsaOaep256 A128GCM round trip") {
            val keyPair = rsaOaep256KeyPair()
            val token = Jwt.builder()
                .subject("rsa-oaep256-a128gcm")
                .encryptWith(keyPair.publicKey, EncryptionAlgorithm.RsaOaep256, EncryptionContentAlgorithm.A128GCM)
                .compact()

            val jwe = Jwt.parser()
                .decryptWith(EncryptionAlgorithm.RsaOaep256, keyPair.privateKey)
                .build()
                .parseEncrypted(token)

            assertEquals("rsa-oaep256-a128gcm", jwe.payload.subjectOrNull)
        }

        test("encrypt RsaOaep256 A256GCM round trip") {
            val keyPair = rsaOaep256KeyPair()
            val token = Jwt.builder()
                .subject("rsa-oaep256-a256gcm")
                .encryptWith(keyPair.publicKey, EncryptionAlgorithm.RsaOaep256, EncryptionContentAlgorithm.A256GCM)
                .compact()

            val jwe = Jwt.parser()
                .decryptWith(EncryptionAlgorithm.RsaOaep256, keyPair.privateKey)
                .build()
                .parseEncrypted(token)

            assertEquals("rsa-oaep256-a256gcm", jwe.payload.subjectOrNull)
        }

        test("encrypt RsaOaep256 A256CbcHs512 round trip") {
            val keyPair = rsaOaep256KeyPair()
            val token = Jwt.builder()
                .subject("rsa-oaep256-cbc512")
                .encryptWith(keyPair.publicKey, EncryptionAlgorithm.RsaOaep256, EncryptionContentAlgorithm.A256CbcHs512)
                .compact()

            val jwe = Jwt.parser()
                .decryptWith(EncryptionAlgorithm.RsaOaep256, keyPair.privateKey)
                .build()
                .parseEncrypted(token)

            assertEquals("rsa-oaep256-cbc512", jwe.payload.subjectOrNull)
        }
    }

    context("structure / header checks") {

        test("encrypt Dir A256GCM compact has five parts") {
            val cek = aesSimpleKey(256)
            val token = Jwt.builder()
                .subject("test")
                .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A256GCM)
                .compact()

            val parts = token.split('.')
            assertEquals(5, parts.size, "JWE compact token must have exactly 5 parts")
        }

        test("encrypt Dir A256GCM header contains alg and enc") {
            val cek = aesSimpleKey(256)
            val token = Jwt.builder()
                .subject("test")
                .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A256GCM)
                .compact()

            val headerJson = decodeTokenHeader(token)
            assertTrue(headerJson.contains("\"alg\":\"dir\""), "Header must contain alg=dir, got: $headerJson")
            assertTrue(headerJson.contains("\"enc\":\"A256GCM\""), "Header must contain enc=A256GCM, got: $headerJson")
        }

        test("encrypt Dir A256GCM encrypted key segment empty") {
            val cek = aesSimpleKey(256)
            val token = Jwt.builder()
                .subject("test")
                .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A256GCM)
                .compact()

            val encryptedKeyPart = token.split('.')[1]
            assertEquals("", encryptedKeyPart, "For Dir algorithm, encrypted key segment must be empty")
        }

        test("encrypt Dir A256GCM IV length") {
            val cek = aesSimpleKey(256)
            val token = Jwt.builder()
                .subject("test")
                .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A256GCM)
                .compact()

            val ivBytes = decodeBase64Url(token.split('.')[2])
            assertEquals(12, ivBytes.size, "AES-GCM IV must be 12 bytes")
        }

        test("encrypt Dir A128CbcHs256 IV length") {
            val cek = aesSimpleKey(256) // 32 bytes for A128CBC-HS256
            val token = Jwt.builder()
                .subject("test")
                .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A128CbcHs256)
                .compact()

            val ivBytes = decodeBase64Url(token.split('.')[2])
            assertEquals(16, ivBytes.size, "AES-CBC IV must be 16 bytes")
        }

        test("encrypt Dir A256GCM tag length") {
            val cek = aesSimpleKey(256)
            val token = Jwt.builder()
                .subject("test")
                .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A256GCM)
                .compact()

            val tagBytes = decodeBase64Url(token.split('.')[4])
            assertEquals(16, tagBytes.size, "AES-GCM auth tag must be 16 bytes")
        }

        test("encrypt Dir A256GCM with kid") {
            val cek = aesSimpleKey(256)
            val token = Jwt.builder()
                .keyId("enc-key-id")
                .subject("test")
                .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A256GCM)
                .compact()

            val headerJson = decodeTokenHeader(token)
            assertTrue(headerJson.contains("\"kid\":\"enc-key-id\""), "Header must contain kid, got: $headerJson")
        }
    }

    context("uniqueness") {

        test("encrypt Dir A256GCM two calls produce different tokens") {
            val cek = aesSimpleKey(256)
            val t1 = Jwt.builder()
                .subject("test")
                .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A256GCM)
                .compact()
            val t2 = Jwt.builder()
                .subject("test")
                .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A256GCM)
                .compact()

            assertNotEquals(t1, t2, "Each JWE encryption call must produce a unique token (random IV)")
        }
    }
})
