package co.touchlab.kjwt

import co.touchlab.kjwt.cryptography.ext.decryptWith
import co.touchlab.kjwt.cryptography.ext.encryptWith
import co.touchlab.kjwt.cryptography.ext.signWith
import co.touchlab.kjwt.cryptography.ext.verifyWith
import co.touchlab.kjwt.ext.audience
import co.touchlab.kjwt.ext.getClaim
import co.touchlab.kjwt.ext.getClaimOrNull
import co.touchlab.kjwt.ext.getHeader
import co.touchlab.kjwt.ext.subject
import co.touchlab.kjwt.ext.type
import co.touchlab.kjwt.model.JwtHeader
import co.touchlab.kjwt.model.JwtPayload
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.EncryptionContentAlgorithm
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import io.kotest.core.spec.style.FunSpec
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.serializer
import kotlin.test.assertEquals

@Serializable private data class TakeFromPayload(
    @SerialName(JwtPayload.SUB) val userId: String,
    val role: String,
)

@Serializable private data class TakeFromHeader(
    @SerialName(JwtHeader.TYP) val type: String,
    val version: Int,
)

class JwtBuilderTakeFromTest :
    FunSpec({
        context("JwtBuilder.payload()") {
            test("explicit serializer merges payload fields (JWS)") {
                val key = hs256Key()
                val token =
                    Jwt.builder()
                        .payload(serializer<TakeFromPayload>(), TakeFromPayload("u1", "admin"))
                        .signWith(SigningAlgorithm.HS256, key)
                        .compact()

                val jws = Jwt.parser().verifyWith(SigningAlgorithm.HS256, key).build().parseSigned(token)

                assertEquals("u1", jws.payload.subject)
                assertEquals("admin", jws.payload.getClaim("role"))
            }

            test("reified generic merges payload fields (JWS)") {
                val key = hs256Key()
                val token =
                    Jwt.builder()
                        .payload(TakeFromPayload("u2", "viewer"))
                        .signWith(SigningAlgorithm.HS256, key)
                        .compact()

                val jws = Jwt.parser().verifyWith(SigningAlgorithm.HS256, key).build().parseSigned(token)

                assertEquals("u2", jws.payload.subject)
                assertEquals("viewer", jws.payload.getClaim("role"))
            }

            test("payload() is additive — previously set claims survive") {
                val key = hs256Key()
                val token =
                    Jwt.builder()
                        .audience("prior-aud")
                        .payload(TakeFromPayload("u3", "editor"))
                        .signWith(SigningAlgorithm.HS256, key)
                        .compact()

                val jws = Jwt.parser().verifyWith(SigningAlgorithm.HS256, key).build().parseSigned(token)

                assertEquals("prior-aud", jws.payload.audience.first())
                assertEquals("u3", jws.payload.subject)
                assertEquals("editor", jws.payload.getClaimOrNull("role"))
            }

            test("payload() is additive — existing keys are replaced") {
                val key = hs256Key()
                val token =
                    Jwt.builder()
                        .subject("sub")
                        .payload(TakeFromPayload("u3", "editor"))
                        .signWith(SigningAlgorithm.HS256, key)
                        .compact()

                val jws = Jwt.parser().verifyWith(SigningAlgorithm.HS256, key).build().parseSigned(token)

                assertEquals("u3", jws.payload.subject)
                assertEquals("editor", jws.payload.getClaimOrNull("role"))
            }

            test("values taken from another type can be replaced") {
                val key = hs256Key()
                val token =
                    Jwt.builder()
                        .payload(TakeFromPayload("u4", "editor"))
                        .subject("sub")
                        .signWith(SigningAlgorithm.HS256, key)
                        .compact()

                val jws = Jwt.parser().verifyWith(SigningAlgorithm.HS256, key).build().parseSigned(token)

                assertEquals("sub", jws.payload.subject)
                assertEquals("editor", jws.payload.getClaimOrNull("role"))
            }

            test("explicit serializer merges payload fields (JWE)") {
                val cek = aesSimpleKey(256)
                val token =
                    Jwt.builder()
                        .payload(serializer<TakeFromPayload>(), TakeFromPayload("u4", "guest"))
                        .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A256GCM)
                        .compact()

                val jwe = Jwt.parser().decryptWith(cek, EncryptionAlgorithm.Dir).build().parseEncrypted(token)

                assertEquals("u4", jwe.payload.subject)
                assertEquals("guest", jwe.payload.getClaim("role"))
            }
        }

        context("JwtBuilder.header()") {
            test("explicit serializer merges header fields (JWS)") {
                val key = hs256Key()
                val token =
                    Jwt.builder()
                        .subject("user")
                        .header(serializer<TakeFromHeader>(), TakeFromHeader("at+JWT", 2))
                        .signWith(SigningAlgorithm.HS256, key)
                        .compact()

                val jws = Jwt.parser().verifyWith(SigningAlgorithm.HS256, key).build().parseSigned(token)

                assertEquals("at+JWT", jws.header.type)
                assertEquals(2, jws.header.getHeader<Int>("version"))
            }

            test("reified generic merges header fields (JWS)") {
                val key = hs256Key()
                val token =
                    Jwt.builder()
                        .subject("user")
                        .header(TakeFromHeader("at+JWT", 3))
                        .signWith(SigningAlgorithm.HS256, key)
                        .compact()

                val jws = Jwt.parser().verifyWith(SigningAlgorithm.HS256, key).build().parseSigned(token)

                assertEquals("at+JWT", jws.header.type)
                assertEquals(3, jws.header.getHeader<Int>("version"))
            }

            test("header() is additive — pre-existing parameters survive") {
                val key = hs256Key()
                val token =
                    Jwt.builder()
                        .subject("user")
                        .contentType("JWT")
                        .header(TakeFromHeader("at+JWT", 1))
                        .signWith(SigningAlgorithm.HS256, key)
                        .compact()

                val jws = Jwt.parser().verifyWith(SigningAlgorithm.HS256, key).build().parseSigned(token)

                assertEquals("JWT", jws.header.getHeader("cty"))
                assertEquals("at+JWT", jws.header.type)
                assertEquals(1, jws.header.getHeader<Int>("version"))
            }
        }

        context("JwtPayload.Builder.takeFrom()") {
            test("explicit serializer merges claims via DSL block") {
                val key = hs256Key()
                val token = Jwt.builder().claims {
                    takeFrom(serializer<TakeFromPayload>(), TakeFromPayload("u5", "ops"))
                }.signWith(SigningAlgorithm.HS256, key).compact()

                val jws = Jwt.parser().verifyWith(SigningAlgorithm.HS256, key).build().parseSigned(token)

                assertEquals("u5", jws.payload.subject)
                assertEquals("ops", jws.payload.getClaim("role"))
            }

            test("reified generic merges claims via DSL block") {
                val key = hs256Key()
                val token = Jwt.builder().claims {
                    takeFrom(TakeFromPayload("u6", "dev"))
                }.signWith(SigningAlgorithm.HS256, key).compact()

                val jws = Jwt.parser().verifyWith(SigningAlgorithm.HS256, key).build().parseSigned(token)

                assertEquals("u6", jws.payload.subject)
                assertEquals("dev", jws.payload.getClaim("role"))
            }
        }

        context("JwtHeader.Builder.takeFrom()") {
            test("explicit serializer merges header params via DSL block") {
                val key = hs256Key()
                val token = Jwt.builder().subject("user").header {
                    takeFrom(serializer<TakeFromHeader>(), TakeFromHeader("at+JWT", 4))
                }.signWith(SigningAlgorithm.HS256, key).compact()

                val jws = Jwt.parser().verifyWith(SigningAlgorithm.HS256, key).build().parseSigned(token)

                assertEquals("at+JWT", jws.header.type)
                assertEquals(4, jws.header.getHeader<Int>("version"))
            }

            test("reified generic merges header params via DSL block") {
                val key = hs256Key()
                val token = Jwt.builder().subject("user").header {
                    takeFrom(TakeFromHeader("at+JWT", 5))
                }.signWith(SigningAlgorithm.HS256, key).compact()

                val jws = Jwt.parser().verifyWith(SigningAlgorithm.HS256, key).build().parseSigned(token)

                assertEquals("at+JWT", jws.header.type)
                assertEquals(5, jws.header.getHeader<Int>("version"))
            }
        }
    })
