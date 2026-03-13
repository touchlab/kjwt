package co.touchlab.kjwt

import co.touchlab.kjwt.exception.MalformedJwtException
import co.touchlab.kjwt.exception.SignatureException
import co.touchlab.kjwt.exception.UnsupportedJwtException
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import io.kotest.core.spec.style.FunSpec
import kotlin.test.assertFailsWith

class MalformedTokenTest : FunSpec({

    context("structure errors") {

        test("parse empty string throws MalformedJwtException") {
            val key = hs256Key()
            assertFailsWith<MalformedJwtException> {
                Jwt.parser().verifyWith(SigningAlgorithm.HS256, key).build().parseSigned("")
            }
        }

        test("parse only two parts throws MalformedJwtException") {
            val key = hs256Key()
            assertFailsWith<MalformedJwtException> {
                Jwt.parser()
                    .verifyWith(SigningAlgorithm.HS256, key)
                    .build()
                    .parseSigned("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0")
            }
        }

        test("parse four parts for JWS throws MalformedJwtException") {
            val key = hs256Key()
            assertFailsWith<MalformedJwtException> {
                Jwt.parser()
                    .verifyWith(SigningAlgorithm.HS256, key)
                    .build()
                    .parseSigned("part1.part2.part3.part4")
            }
        }

        test("parse header not base64 throws MalformedJwtException") {
            val key = hs256Key()
            assertFailsWith<MalformedJwtException> {
                Jwt.parser()
                    .verifyWith(SigningAlgorithm.HS256, key)
                    .build()
                    // First part contains invalid base64url characters
                    .parseSigned("not!!valid!!base64.eyJzdWIiOiJ0ZXN0In0.signature")
            }
        }

        test("parse header not json throws MalformedJwtException") {
            val key = hs256Key()
            // Valid base64url but not JSON: "not-json"
            val notJsonB64 = "bm90LWpzb24" // base64url("not-json")
            assertFailsWith<MalformedJwtException> {
                Jwt.parser()
                    .verifyWith(SigningAlgorithm.HS256, key)
                    .build()
                    .parseSigned("$notJsonB64.eyJzdWIiOiJ0ZXN0In0.signature")
            }
        }

        test("parse payload not json throws MalformedJwtException") {
            val key = hs256Key()
            // Valid HS256 header B64
            val headerB64 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            // Valid base64url but not JSON: "not-json"
            val notJsonB64 = "bm90LWpzb24"
            assertFailsWith<MalformedJwtException> {
                Jwt.parser()
                    .verifyWith(SigningAlgorithm.HS256, key)
                    .build()
                    .parseSigned("$headerB64.$notJsonB64.signature")
            }
        }
    }

    context("signature errors") {

        test("parse tampered payload throws SignatureException") {
            val key = hs256Key()
            val token = Jwt.builder()
                .subject("original-subject")
                .signWith(SigningAlgorithm.HS256, key)
                .compact()

            val parts = token.split('.')
            // Replace the payload with a different base64url payload ({"sub":"hacked"})
            val tamperedPayload = "eyJzdWIiOiJoYWNrZWQifQ"
            val tamperedToken = "${parts[0]}.$tamperedPayload.${parts[2]}"

            assertFailsWith<SignatureException> {
                Jwt.parser()
                    .verifyWith(SigningAlgorithm.HS256, key)
                    .build()
                    .parseSigned(tamperedToken)
            }
        }

        test("parse tampered signature throws SignatureException") {
            val key = hs256Key()
            val token = Jwt.builder()
                .subject("user")
                .signWith(SigningAlgorithm.HS256, key)
                .compact()

            val parts = token.split('.')
            // Replace last char of signature to corrupt it
            val sig = parts[2]
            val corruptedSig = sig.dropLast(1) + (if (sig.last() == 'A') 'B' else 'A')
            val tamperedToken = "${parts[0]}.${parts[1]}.$corruptedSig"

            assertFailsWith<SignatureException> {
                Jwt.parser()
                    .verifyWith(SigningAlgorithm.HS256, key)
                    .build()
                    .parseSigned(tamperedToken)
            }
        }

        test("parse wrong key throws SignatureException") {
            val signingKey = hs256Key()
            val wrongKey = hmacKey(
                dev.whyoleg.cryptography.algorithms.SHA256,
                "completely-different-secret-key-here".encodeToByteArray(),
            )

            val token = Jwt.builder()
                .subject("user")
                .signWith(SigningAlgorithm.HS256, signingKey)
                .compact()

            assertFailsWith<SignatureException> {
                Jwt.parser()
                    .verifyWith(SigningAlgorithm.HS256, wrongKey)
                    .build()
                    .parseSigned(token)
            }
        }

        test("parse wrong public key throws SignatureException") {
            val signingKeyPair = rsaPkcs1KeyPair()
            val differentKeyPair = rsaPkcs1KeyPair()

            val token = Jwt.builder()
                .subject("user")
                .signWith(SigningAlgorithm.RS256, signingKeyPair.privateKey)
                .compact()

            assertFailsWith<SignatureException> {
                Jwt.parser()
                    .verifyWith(SigningAlgorithm.RS256, differentKeyPair.publicKey) // wrong public key
                    .build()
                    .parseSigned(token)
            }
        }
    }

    context("algorithm errors") {

        test("parse none without allow unsecured throws UnsupportedJwtException") {
            val noneToken = Jwt.builder()
                .subject("user")
                .signWith(SigningAlgorithm.None)
                .compact()

            assertFailsWith<UnsupportedJwtException> {
                Jwt.parser()
                    // No allowUnsecured(true) call
                    .build()
                    .parseSigned(noneToken)
            }
        }

        test("parse unknown algorithm throws UnsupportedJwtException") {
            // Craft a token with an unknown algorithm in the header
            // Header: {"alg":"XY999","typ":"JWT"} -> base64url
            val fakeHeaderB64 = "eyJhbGciOiJYWTk5OSIsInR5cCI6IkpXVCJ9"
            val payloadB64 = "eyJzdWIiOiJ1c2VyIn0"
            val fakeToken = "$fakeHeaderB64.$payloadB64.fakesig"

            val key = hs256Key()
            assertFailsWith<UnsupportedJwtException> {
                Jwt.parser()
                    .verifyWith(SigningAlgorithm.HS256, key)
                    .build()
                    .parseSigned(fakeToken)
            }
        }

        test("parse algorithm mismatch no matching verifier throws IllegalState") {
            val rsaKeyPair = rsaPkcs1KeyPair()
            // Token signed with RS256
            val token = Jwt.builder()
                .subject("user")
                .signWith(SigningAlgorithm.RS256, rsaKeyPair.privateKey)
                .compact()

            val hs256Key = hs256Key()
            // Parser configured only with HS256 verifier, but token is RS256
            assertFailsWith<IllegalStateException> {
                Jwt.parser()
                    .verifyWith(SigningAlgorithm.HS256, hs256Key)
                    .build()
                    .parseSigned(token)
            }
        }
    }

    context("JWE structure errors from parseSignedClaims") {

        test("parse signed claims five parts throws MalformedJwtException") {
            val key = hs256Key()
            // A 5-part token passed to parseSignedClaims (JWS expects 3)
            assertFailsWith<MalformedJwtException> {
                Jwt.parser()
                    .verifyWith(SigningAlgorithm.HS256, key)
                    .build()
                    .parseSigned("a.b.c.d.e")
            }
        }

        test("parse encrypted claims three parts throws MalformedJwtException") {
            val key = rsaOaep256KeyPair().privateKey
            // A 3-part token passed to parseEncryptedClaims (JWE expects 5)
            assertFailsWith<MalformedJwtException> {
                Jwt.parser()
                    .decryptWith(EncryptionAlgorithm.RsaOaep, key)
                    .build()
                    .parseEncrypted("a.b.c")
            }
        }

        test("parse auto detect wrong part count throws MalformedJwtException") {
            val key = hs256Key()
            assertFailsWith<MalformedJwtException> {
                Jwt.parser()
                    .verifyWith(SigningAlgorithm.HS256, key)
                    .build()
                    .parse("a.b.c.d") // 4 parts — neither JWS nor JWE
            }
        }
    }
})
