package co.touchlab.kjwt.jwk

import co.touchlab.kjwt.Jwt
import co.touchlab.kjwt.exception.MalformedJwkException
import co.touchlab.kjwt.exception.UnsupportedJwtException
import co.touchlab.kjwt.model.jwk.Jwk
import co.touchlab.kjwt.model.jwk.JwkSet
import io.kotest.core.spec.style.FunSpec
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class JwkSerializationTest :
    FunSpec({

        context("RSA round-trip") {

            test("rsa public key round trip") {
                val jwk: Jwk =
                    Jwk.Rsa(
                        n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                        e = "AQAB",
                        kid = "2011-04-29",
                        use = "sig",
                    )

                val serialized = Jwt.defaultJsonParser.encodeToString(jwk)
                assertTrue(serialized.contains("\"kty\":\"RSA\""))
                assertTrue(serialized.contains("\"kid\":\"2011-04-29\""))
                assertTrue(serialized.contains("\"use\":\"sig\""))

                val deserialized = Jwt.defaultJsonParser.decodeFromString<Jwk>(serialized)
                assertEquals(jwk, deserialized)
                assertTrue(deserialized is Jwk.Rsa)
            }

            test("rsa private key round trip") {
                val jwk: Jwk =
                    Jwk.Rsa(
                        n = "modulus",
                        e = "AQAB",
                        d = "privateExp",
                        p = "prime1",
                        q = "prime2",
                        dp = "dp",
                        dq = "dq",
                        qi = "qi",
                        kid = "test-private",
                    )

                val serialized = Jwt.defaultJsonParser.encodeToString(jwk)
                assertTrue(serialized.contains("\"d\":"))
                assertTrue(serialized.contains("\"p\":"))

                val deserialized = Jwt.defaultJsonParser.decodeFromString<Jwk>(serialized) as Jwk.Rsa
                assertEquals(jwk, deserialized)
                assertTrue(deserialized.isPrivate)
            }

            test("rsa public key is not private") {
                val jwk: Jwk = Jwk.Rsa(n = "modulus", e = "AQAB")
                assertTrue(!jwk.isPrivate)
            }

            test("rsa key null fields omitted") {
                val jwk: Jwk = Jwk.Rsa(n = "modulus", e = "AQAB")
                val serialized = Jwt.defaultJsonParser.encodeToString(jwk)
                assertTrue(!serialized.contains("\"d\""))
                assertTrue(!serialized.contains("\"kid\""))
                assertTrue(!serialized.contains("\"use\""))
            }
        }

        context("EC round-trip") {

            test("ec public key round trip") {
                val jwk: Jwk =
                    Jwk.Ec(
                        crv = "P-256",
                        x = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                        y = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                        use = "enc",
                        kid = "1",
                    )

                val serialized = Jwt.defaultJsonParser.encodeToString(jwk)
                assertTrue(serialized.contains("\"kty\":\"EC\""))
                assertTrue(serialized.contains("\"crv\":\"P-256\""))

                val deserialized = Jwt.defaultJsonParser.decodeFromString<Jwk>(serialized)
                assertEquals(jwk, deserialized)
                assertTrue(deserialized is Jwk.Ec)
                assertTrue(!deserialized.isPrivate)
            }

            test("ec private key is private") {
                val jwk: Jwk = Jwk.Ec(crv = "P-256", x = "xCoord", y = "yCoord", d = "privateD")
                assertTrue(jwk.isPrivate)
                val serialized = Jwt.defaultJsonParser.encodeToString(jwk)
                assertTrue(serialized.contains("\"d\":"))
            }
        }

        context("oct round-trip") {

            test("oct key round trip") {
                val jwk: Jwk =
                    Jwk.Oct(
                        k = "GawgguFyGrWKav7AX4VKUg",
                        alg = "HS256",
                        kid = "symmetric-key",
                    )

                val serialized = Jwt.defaultJsonParser.encodeToString(jwk)
                assertTrue(serialized.contains("\"kty\":\"oct\""))
                assertTrue(serialized.contains("\"k\":"))

                val deserialized = Jwt.defaultJsonParser.decodeFromString<Jwk>(serialized)
                assertEquals(jwk, deserialized)
                assertTrue(deserialized is Jwk.Oct)
                assertTrue(deserialized.isPrivate)
            }
        }

        context("key_ops field") {

            test("keyOps serialized with underscore") {
                val jwk: Jwk = Jwk.Rsa(n = "n", e = "e", keyOps = listOf("sign", "verify"))
                val serialized = Jwt.defaultJsonParser.encodeToString(jwk)
                assertTrue(serialized.contains("\"key_ops\""))
                assertTrue(!serialized.contains("\"keyOps\""))

                val deserialized = Jwt.defaultJsonParser.decodeFromString<Jwk>(serialized) as Jwk.Rsa
                assertEquals(listOf("sign", "verify"), deserialized.keyOps)
            }
        }

        context("unknown kty") {

            test("unknown kty throws UnsupportedJwtException") {
                assertFailsWith<UnsupportedJwtException> {
                    Jwt.defaultJsonParser.decodeFromString<Jwk>("""{"kty":"OKPT","crv":"Ed25519","x":"abc"}""")
                }
            }

            test("missing kty throws MalformedJwkException") {
                assertFailsWith<MalformedJwkException> {
                    Jwt.defaultJsonParser.decodeFromString<Jwk>("""{"n":"mod","e":"AQAB"}""")
                }
            }

            test("missing required field throws MalformedJwkException") {
                assertFailsWith<MalformedJwkException> {
                    Jwt.defaultJsonParser.decodeFromString<Jwk.Rsa>("""{"kty":"RSA","e":"AQAB"}""") // missing "n"
                }
            }
        }

        context("subtype-typed serialization (kty always present)") {

            test("rsa subtype kty included when typed as concrete") {
                val jwk = Jwk.Rsa(n = "modulus", e = "AQAB")
                assertTrue(Jwt.defaultJsonParser.encodeToString(jwk).contains("\"kty\":\"RSA\""))
            }

            test("ec subtype kty included when typed as concrete") {
                val jwk = Jwk.Ec(crv = "P-256", x = "x", y = "y")
                assertTrue(Jwt.defaultJsonParser.encodeToString(jwk).contains("\"kty\":\"EC\""))
            }

            test("oct subtype kty included when typed as concrete") {
                val jwk = Jwk.Oct(k = "secret")
                assertTrue(Jwt.defaultJsonParser.encodeToString(jwk).contains("\"kty\":\"oct\""))
            }

            test("rsa subtype round trip when typed as concrete") {
                val original = Jwk.Rsa(n = "modulus", e = "AQAB", kid = "test")
                assertEquals(
                    original,
                    Jwt.defaultJsonParser.decodeFromString<Jwk.Rsa>(Jwt.defaultJsonParser.encodeToString(original))
                )
            }

            test("no duplicate kty when typed as parent") {
                val jwk: Jwk = Jwk.Rsa(n = "n", e = "AQAB")
                val count = Jwt.defaultJsonParser.encodeToString(jwk).split("\"kty\"").size - 1
                assertEquals(1, count)
            }
        }

        context("OKP round-trip (RFC 8037)") {

            // RFC 8037 §A.1 — Ed25519 key pair
            val okpPrivateKeyJson = """{"kty":"OKP","crv":"Ed25519","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"""

            // RFC 8037 §A.2 — Ed25519 public key only
            val okpPublicKeyJson = """{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"""

            test("okp Ed25519 public key serialization round-trip") {
                val jwk = Jwt.defaultJsonParser.decodeFromString<Jwk>(okpPublicKeyJson)

                assertTrue(jwk is Jwk.Okp)
                assertEquals("OKP", Jwk.Okp.KTY)
                assertEquals("Ed25519", jwk.crv)
                assertEquals("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", jwk.x)
                assertNull(jwk.d)
                assertTrue(!jwk.isPrivate)

                val reserialized = Jwt.defaultJsonParser.encodeToString(jwk)
                assertTrue(reserialized.contains("\"kty\":\"OKP\""))
                assertTrue(reserialized.contains("\"crv\":\"Ed25519\""))
                assertEquals(jwk, Jwt.defaultJsonParser.decodeFromString<Jwk>(reserialized))
            }

            test("okp Ed25519 private key serialization round-trip") {
                val jwk = Jwt.defaultJsonParser.decodeFromString<Jwk>(okpPrivateKeyJson)

                assertTrue(jwk is Jwk.Okp)
                assertEquals("Ed25519", jwk.crv)
                assertEquals("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A", jwk.d)
                assertTrue(jwk.isPrivate)

                val reserialized = Jwt.defaultJsonParser.encodeToString(jwk)
                assertTrue(reserialized.contains("\"d\":"))
                assertEquals(jwk, Jwt.defaultJsonParser.decodeFromString<Jwk>(reserialized))
            }

            test("okp isPrivate reflects d field presence") {
                val pub = Jwt.defaultJsonParser.decodeFromString<Jwk>(okpPublicKeyJson) as Jwk.Okp
                val priv = Jwt.defaultJsonParser.decodeFromString<Jwk>(okpPrivateKeyJson) as Jwk.Okp

                assertTrue(!pub.isPrivate)
                assertTrue(priv.isPrivate)
            }

            test("okp thumbprint contains only crv and x sorted alphabetically") {
                val jwk = Jwt.defaultJsonParser.decodeFromString<Jwk>(okpPrivateKeyJson) as Jwk.Okp
                val thumbprint = jwk.thumbprint

                assertTrue(thumbprint is Jwk.Okp.OkpThumbprint)
                assertEquals(jwk.crv, thumbprint.crv)
                assertEquals(jwk.x, thumbprint.x)
            }

            test("okp subtype kty included when typed as concrete") {
                val jwk = Jwk.Okp(crv = "Ed25519", x = "abc123")
                assertTrue(Jwt.defaultJsonParser.encodeToString(jwk).contains("\"kty\":\"OKP\""))
            }
        }

        context("parse from RFC 7517 Appendix A examples") {

            test("RFC Appendix A1 ec public keys") {
                val jwksJson =
                    """
                    {
                      "keys": [
                        {
                          "kty": "EC",
                          "crv": "P-256",
                          "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                          "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                          "use": "enc",
                          "kid": "1"
                        },
                        {
                          "kty": "RSA",
                          "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                          "e": "AQAB",
                          "alg": "RS256",
                          "kid": "2011-04-29"
                        }
                      ]
                    }
                    """.trimIndent()

                val jwks = Jwt.defaultJsonParser.decodeFromString<JwkSet>(jwksJson)
                assertEquals(2, jwks.keys.size)

                val ecKey = jwks.findById("1") as Jwk.Ec
                assertEquals("P-256", ecKey.crv)
                assertEquals("enc", ecKey.use)

                val rsaKey = jwks.findById("2011-04-29") as Jwk.Rsa
                assertEquals("RS256", rsaKey.alg)
                assertNull(rsaKey.d)
                assertTrue(!rsaKey.isPrivate)
            }
        }
    })
