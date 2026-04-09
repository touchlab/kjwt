@file:OptIn(dev.whyoleg.cryptography.DelicateCryptographyApi::class)

package co.touchlab.kjwt

import co.touchlab.kjwt.cryptography.ext.decryptWith
import co.touchlab.kjwt.cryptography.ext.encryptWith
import co.touchlab.kjwt.cryptography.ext.signWith
import co.touchlab.kjwt.cryptography.ext.verifyWith
import co.touchlab.kjwt.model.JwtHeader
import co.touchlab.kjwt.model.JwtPayload
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.EncryptionContentAlgorithm
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import io.kotest.core.spec.style.FunSpec
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours

// ---- Custom types used in all tests in this file ----

@Serializable
data class CustomHeader(
    @SerialName(JwtHeader.ALG) val algorithm: String? = null,
    @SerialName(JwtHeader.TYP) val type: String? = null,
    @SerialName("kid") val keyId: String? = null,
    @SerialName("x-custom") val custom: String? = null,
)

@Serializable
data class UserClaims(
    @SerialName(JwtPayload.SUB) val subject: String? = null,
    @SerialName("role") val role: String? = null,
    @SerialName("level") val level: Int? = null,
    @SerialName("exp") val expSeconds: Long? = null,
)

class CustomTypeParsing :
    FunSpec({

        context("JWS") {

            test("parse signed Jwt custom type direct property access") {
                val key = hs256Key()
                val token =
                    Jwt
                        .builder()
                        .subject("user-42")
                        .claim("role", "admin")
                        .claim("level", 7)
                        .signWith(SigningAlgorithm.HS256, key)
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(SigningAlgorithm.HS256, key)
                        .build()
                        .parseSigned(token)

                val payload = jws.getPayload<UserClaims>()
                assertEquals("user-42", payload.subject)
                assertEquals("admin", payload.role)
                assertEquals(7, payload.level)
            }

            test("parse signed Jwt custom type missing optional field is null") {
                val key = hs256Key()
                // Token has no "role" or "level" claims
                val token =
                    Jwt
                        .builder()
                        .subject("minimal-user")
                        .signWith(SigningAlgorithm.HS256, key)
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(SigningAlgorithm.HS256, key)
                        .build()
                        .parseSigned(token)

                val payload = jws.getPayload<UserClaims>()
                assertEquals("minimal-user", payload.subject)
                assertNull(payload.role)
                assertNull(payload.level)
            }
        }

        context("getHeader") {

            test("JWS - deserializes standard header fields into custom type") {
                val key = hs256Key()
                val token =
                    Jwt
                        .builder()
                        .subject("user-1")
                        .signWith(SigningAlgorithm.HS256, key)
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(SigningAlgorithm.HS256, key)
                        .build()
                        .parseSigned(token)

                val header = jws.getHeader<CustomHeader>()
                assertEquals("HS256", header.algorithm)
                assertEquals("JWT", header.type)
            }

            test("JWS - custom extra header field is deserialized") {
                val key = hs256Key()
                val token =
                    Jwt
                        .builder()
                        .subject("user-2")
                        .header { extra("x-custom", "hello") }
                        .signWith(SigningAlgorithm.HS256, key)
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(SigningAlgorithm.HS256, key)
                        .build()
                        .parseSigned(token)

                val header = jws.getHeader<CustomHeader>()
                assertEquals("hello", header.custom)
            }

            test("JWS - absent optional header field is null") {
                val key = hs256Key()
                val token =
                    Jwt
                        .builder()
                        .subject("user-3")
                        .signWith(SigningAlgorithm.HS256, key)
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(SigningAlgorithm.HS256, key)
                        .build()
                        .parseSigned(token)

                val header = jws.getHeader<CustomHeader>()
                assertNull(header.keyId)
                assertNull(header.custom)
            }

            test("JWE - deserializes standard header fields into custom type") {
                val cek = aesSimpleKey(128)
                val token =
                    Jwt
                        .builder()
                        .subject("enc-user-1")
                        .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A128GCM)
                        .compact()

                val jwe =
                    Jwt
                        .parser()
                        .decryptWith(cek, EncryptionAlgorithm.Dir)
                        .build()
                        .parseEncrypted(token)

                val header = jwe.getHeader<CustomHeader>()
                assertEquals("dir", header.algorithm)
                assertEquals("JWT", header.type)
            }

            test("JWE - custom extra header field is deserialized") {
                val cek = aesSimpleKey(128)
                val token =
                    Jwt
                        .builder()
                        .subject("enc-user-2")
                        .header { extra("x-custom", "world") }
                        .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A128GCM)
                        .compact()

                val jwe =
                    Jwt
                        .parser()
                        .decryptWith(cek, EncryptionAlgorithm.Dir)
                        .build()
                        .parseEncrypted(token)

                val header = jwe.getHeader<CustomHeader>()
                assertEquals("world", header.custom)
            }
        }

        context("JWE") {

            test("parse encrypted Jwt custom type direct property access") {
                val cek = aesSimpleKey(128)
                val token =
                    Jwt
                        .builder()
                        .subject("enc-user")
                        .claim("role", "operator")
                        .claim("level", 3)
                        .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A128GCM)
                        .compact()

                val jwe =
                    Jwt
                        .parser()
                        .decryptWith(cek, EncryptionAlgorithm.Dir)
                        .build()
                        .parseEncrypted(token)

                val payload = jwe.getPayload<UserClaims>()
                assertEquals("enc-user", payload.subject)
                assertEquals("operator", payload.role)
                assertEquals(3, payload.level)
            }

            test("parse encrypted Jwt custom type expiration validation not expired") {
                val cek = aesSimpleKey(128)
                val expiry = Clock.System.now() + 1.hours
                val token =
                    Jwt
                        .builder()
                        .subject("enc-timed-user")
                        .expiration(expiry)
                        .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A128GCM)
                        .compact()

                val jwe =
                    Jwt
                        .parser()
                        .decryptWith(cek, EncryptionAlgorithm.Dir)
                        .build()
                        .parseEncrypted(token)

                val payload = jwe.getPayload<UserClaims>()
                assertEquals(expiry.epochSeconds, payload.expSeconds)
            }
        }
    })
