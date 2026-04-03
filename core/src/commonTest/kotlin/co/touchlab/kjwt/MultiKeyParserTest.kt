package co.touchlab.kjwt

import co.touchlab.kjwt.cryptography.ext.encryptWith
import co.touchlab.kjwt.cryptography.ext.key
import co.touchlab.kjwt.cryptography.ext.parse
import co.touchlab.kjwt.ext.subjectOrNull
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.EncryptionContentAlgorithm
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import io.kotest.core.spec.style.FunSpec
import kotlin.random.Random
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class MultiKeyParserTest :
    FunSpec({

        context("multi-key JWS verification") {

            test("exact match — token kid matches registered kid") {
                val signingKey = hs256SigningKey(keyId = "k1")
                val token =
                    Jwt
                        .builder()
                        .subject("user")
                        .signWith(signingKey)
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(signingKey)
                        .build()
                        .parseSigned(token)

                assertEquals("user", jws.payload.subjectOrNull)
            }

            test("fallback — token has kid but parser has algo-only key") {
                val signingKey = hs256SigningKey(keyId = "k1")
                val token =
                    Jwt
                        .builder()
                        .subject("user")
                        .signWith(signingKey)
                        .compact()

                // No keyId on verifyWith → algo-only key, matches any kid for HS256
                val fallbackKey = hs256SigningKey()
                val jws =
                    Jwt
                        .parser()
                        .verifyWith(fallbackKey)
                        .build()
                        .parseSigned(token)

                assertEquals("user", jws.payload.subjectOrNull)
            }

            test("no kid token — parser has algo-only key") {
                val signingKey = hs256SigningKey()
                val token =
                    Jwt
                        .builder()
                        .subject("user")
                        .signWith(signingKey)
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(signingKey)
                        .build()
                        .parseSigned(token)

                assertEquals("user", jws.payload.subjectOrNull)
            }

            test("multiple keys same algo — correct kid selected") {
                val key1 =
                    SigningAlgorithm.HS256.parse(
                        "secret-for-k1-at-least-256-bits-long".encodeToByteArray(),
                        keyId = "k1",
                    )
                val key2 =
                    SigningAlgorithm.HS256.parse(
                        "secret-for-k2-at-least-256-bits-long".encodeToByteArray(),
                        keyId = "k2",
                    )

                val token =
                    Jwt
                        .builder()
                        .subject("user")
                        .signWith(key2)
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(key1)
                        .verifyWith(key2)
                        .build()
                        .parseSigned(token)

                assertEquals("user", jws.payload.subjectOrNull)
            }

            test("multiple keys same algo — unmatched kid falls back to algo-only key") {
                val keyFallback = hs256SigningKey() // algo-only, same secret as hs256Secret
                val key1 =
                    SigningAlgorithm.HS256.parse(
                        "secret-for-k1-at-least-256-bits-long".encodeToByteArray(),
                        keyId = "k1",
                    )

                val token =
                    Jwt
                        .builder()
                        .subject("user")
                        .signWith(hs256SigningKey(keyId = "k-unknown"))
                        .compact()

                // kid="k-unknown" doesn't match "k1", so falls back to algo-only key
                val jws =
                    Jwt
                        .parser()
                        .verifyWith(key1)
                        .verifyWith(keyFallback)
                        .build()
                        .parseSigned(token)

                assertEquals("user", jws.payload.subjectOrNull)
            }

            test("no key found — token with kid, parser has only different kid") {
                val signingKey = hs256SigningKey(keyId = "k1")
                val token =
                    Jwt
                        .builder()
                        .subject("user")
                        .signWith(signingKey)
                        .compact()

                assertFailsWith<IllegalStateException> {
                    Jwt
                        .parser()
                        .verifyWith(hs256SigningKey(keyId = "k2"))
                        .build()
                        .parseSigned(token)
                }
            }

            test("no key found — token has no kid, parser has only keyed entries") {
                val signingKey = hs256SigningKey()
                val token =
                    Jwt
                        .builder()
                        .subject("user")
                        .signWith(signingKey)
                        .compact()

                // Token has no kid → only (HS256, null) is looked up, but parser only has (HS256, "k1")
                assertFailsWith<IllegalStateException> {
                    Jwt
                        .parser()
                        .verifyWith(hs256SigningKey(keyId = "k1"))
                        .build()
                        .parseSigned(token)
                }
            }

            test("none algorithm fallback — no matching key, noVerify registered") {
                val key = hs256SigningKey(keyId = "k-unknown")
                val key1 =
                    SigningAlgorithm.HS256.parse(
                        "secret-for-k1-at-least-256-bits-long".encodeToByteArray(),
                        keyId = "k1",
                    )

                val token =
                    Jwt
                        .builder()
                        .subject("user")
                        .signWith(key)
                        .compact()

                // kid="k-unknown" matches neither "k1" nor algo-only (none registered);
                // falls back to the None verifier registered by noVerify()
                val jws =
                    Jwt
                        .parser()
                        .verifyWith(key1)
                        .noVerify()
                        .build()
                        .parseSigned(token)

                assertEquals("user", jws.payload.subjectOrNull)
            }

            test("duplicate signing key registration throws") {
                assertFailsWith<IllegalArgumentException> {
                    Jwt
                        .parser()
                        .verifyWith(hs256SigningKey(keyId = "k1"))
                        .verifyWith(hs256SigningKey(keyId = "k1"))
                }
            }

            test("duplicate algo-only signing key registration throws") {
                assertFailsWith<IllegalArgumentException> {
                    Jwt
                        .parser()
                        .verifyWith(hs256SigningKey())
                        .verifyWith(hs256SigningKey())
                }
            }
        }

        context("multi-key JWE decryption") {

            test("exact match — token kid matches registered kid") {
                val encKey = dirEncKey(256, keyId = "k1")
                val token =
                    Jwt
                        .builder()
                        .subject("user")
                        .encryptWith(encKey, EncryptionContentAlgorithm.A256GCM)
                        .compact()

                val jwe =
                    Jwt
                        .parser()
                        .decryptWith(encKey)
                        .build()
                        .parseEncrypted(token)

                assertEquals("user", jwe.payload.subjectOrNull)
            }

            test("fallback — token has kid but parser has algo-only decryptor") {
                val bytes = Random.Default.nextBytes(32)
                val encKey = EncryptionAlgorithm.Dir.key(bytes, "k1") // token encrypted with kid="k1"
                val fallbackKey = EncryptionAlgorithm.Dir.key(bytes) // same bytes, algo-only (no kid)

                val token =
                    Jwt
                        .builder()
                        .subject("user")
                        .encryptWith(encKey, EncryptionContentAlgorithm.A256GCM)
                        .compact()

                // No keyId on decryptWith → algo-only, matches any kid for Dir
                val jwe =
                    Jwt
                        .parser()
                        .decryptWith(fallbackKey)
                        .build()
                        .parseEncrypted(token)

                assertEquals("user", jwe.payload.subjectOrNull)
            }

            test("no kid token — parser has algo-only decryptor") {
                val encKey = dirEncKey(256)
                val token =
                    Jwt
                        .builder()
                        .subject("user")
                        .encryptWith(encKey, EncryptionContentAlgorithm.A256GCM)
                        .compact()

                val jwe =
                    Jwt
                        .parser()
                        .decryptWith(encKey)
                        .build()
                        .parseEncrypted(token)

                assertEquals("user", jwe.payload.subjectOrNull)
            }

            test("multiple keys same algo — correct kid selected") {
                val encKey1 = dirEncKey(256, keyId = "k1")
                val encKey2 = dirEncKey(256, keyId = "k2")

                val token =
                    Jwt
                        .builder()
                        .subject("user")
                        .encryptWith(encKey2, EncryptionContentAlgorithm.A256GCM)
                        .compact()

                val jwe =
                    Jwt
                        .parser()
                        .decryptWith(encKey1)
                        .decryptWith(encKey2)
                        .build()
                        .parseEncrypted(token)

                assertEquals("user", jwe.payload.subjectOrNull)
            }

            test("duplicate decryption key registration throws") {
                assertFailsWith<IllegalArgumentException> {
                    Jwt
                        .parser()
                        .decryptWith(dirEncKey(256, keyId = "k1"))
                        .decryptWith(dirEncKey(256, keyId = "k1"))
                }
            }
        }
    })
