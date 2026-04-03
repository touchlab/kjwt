package co.touchlab.kjwt

import co.touchlab.kjwt.cryptography.ext.decryptWith
import co.touchlab.kjwt.cryptography.ext.encryptWith
import co.touchlab.kjwt.cryptography.ext.signWith
import co.touchlab.kjwt.cryptography.ext.verifyWith
import co.touchlab.kjwt.ext.contentType
import co.touchlab.kjwt.ext.getHeader
import co.touchlab.kjwt.ext.getHeaderOrNull
import co.touchlab.kjwt.ext.type
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.EncryptionContentAlgorithm
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import io.kotest.core.spec.style.FunSpec
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.assertEquals
import kotlin.test.assertNull

class JwtBuilderHeaderTest :
    FunSpec({
        context("JWS") {
            test("type sets typ header") {
                val key = hs256Key()
                val token =
                    Jwt
                        .builder()
                        .subject("user")
                        .type("at+JWT")
                        .signWith(SigningAlgorithm.HS256, key)
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(SigningAlgorithm.HS256, key)
                        .build()
                        .parseSigned(token)

                assertEquals("at+JWT", jws.header.type)
            }

            test("contentType sets cty header") {
                val key = hs256Key()
                val token =
                    Jwt
                        .builder()
                        .subject("user")
                        .contentType("JWT")
                        .signWith(SigningAlgorithm.HS256, key)
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(SigningAlgorithm.HS256, key)
                        .build()
                        .parseSigned(token)

                assertEquals("JWT", jws.header.contentType)
            }

            test("header with JsonElement sets custom extra header") {
                val key = hs256Key()
                val token =
                    Jwt
                        .builder()
                        .subject("user")
                        .header("x-str", JsonPrimitive("hello"))
                        .signWith(SigningAlgorithm.HS256, key)
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(SigningAlgorithm.HS256, key)
                        .build()
                        .parseSigned(token)

                assertEquals("hello", jws.header.getHeader("x-str"))
            }

            test("header with explicit serializer sets custom extra header") {
                val key = hs256Key()
                val token =
                    Jwt
                        .builder()
                        .subject("user")
                        .header("x-num", Int.serializer(), 42)
                        .signWith(SigningAlgorithm.HS256, key)
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(SigningAlgorithm.HS256, key)
                        .build()
                        .parseSigned(token)

                assertEquals(42, jws.header.getHeader("x-num"))
            }

            test("header with explicit serializer and null value removes extra header") {
                val key = hs256Key()
                val token =
                    Jwt
                        .builder()
                        .subject("user")
                        .header("x-str", String.serializer(), null)
                        .signWith(SigningAlgorithm.HS256, key)
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(SigningAlgorithm.HS256, key)
                        .build()
                        .parseSigned(token)

                assertNull(jws.header.getHeaderOrNull<String>("x-str"))
            }

            test("header reified infers serializer for custom extra header") {
                val key = hs256Key()
                val token =
                    Jwt
                        .builder()
                        .subject("user")
                        .header("x-str", "world")
                        .signWith(SigningAlgorithm.HS256, key)
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(SigningAlgorithm.HS256, key)
                        .build()
                        .parseSigned(token)

                assertEquals("world", jws.header.getHeader("x-str"))
            }
        }

        context("JWE") {

            test("type sets typ header") {
                val cek = aesSimpleKey(128)
                val token =
                    Jwt
                        .builder()
                        .subject("user")
                        .type("at+JWT")
                        .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A128GCM)
                        .compact()

                val jwe =
                    Jwt
                        .parser()
                        .decryptWith(EncryptionAlgorithm.Dir, cek)
                        .build()
                        .parseEncrypted(token)

                assertEquals("at+JWT", jwe.header.type)
            }

            test("contentType sets cty header") {
                val cek = aesSimpleKey(128)
                val token =
                    Jwt
                        .builder()
                        .subject("user")
                        .contentType("JWT")
                        .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A128GCM)
                        .compact()

                val jwe =
                    Jwt
                        .parser()
                        .decryptWith(EncryptionAlgorithm.Dir, cek)
                        .build()
                        .parseEncrypted(token)

                assertEquals("JWT", jwe.header.contentType)
            }

            test("header with JsonElement sets custom extra header") {
                val cek = aesSimpleKey(128)
                val token =
                    Jwt
                        .builder()
                        .subject("user")
                        .header("x-str", JsonPrimitive("hello"))
                        .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A128GCM)
                        .compact()

                val jwe =
                    Jwt
                        .parser()
                        .decryptWith(EncryptionAlgorithm.Dir, cek)
                        .build()
                        .parseEncrypted(token)

                assertEquals("hello", jwe.header.getHeader("x-str"))
            }

            test("header reified infers serializer for custom extra header") {
                val cek = aesSimpleKey(128)
                val token =
                    Jwt
                        .builder()
                        .subject("user")
                        .header("x-str", "world")
                        .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A128GCM)
                        .compact()

                val jwe =
                    Jwt
                        .parser()
                        .decryptWith(EncryptionAlgorithm.Dir, cek)
                        .build()
                        .parseEncrypted(token)

                assertEquals("world", jwe.header.getHeader("x-str"))
            }
        }
    })
