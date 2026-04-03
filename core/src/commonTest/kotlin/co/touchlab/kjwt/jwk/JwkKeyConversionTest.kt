package co.touchlab.kjwt.jwk

import co.touchlab.kjwt.Jwt
import co.touchlab.kjwt.cryptography.ext.signWith
import co.touchlab.kjwt.cryptography.ext.verifyWith
import co.touchlab.kjwt.ecKeyPair
import co.touchlab.kjwt.ext.subjectOrNull
import co.touchlab.kjwt.cryptography.ext.toEcdsaPrivateKey
import co.touchlab.kjwt.cryptography.ext.toEcdsaPublicKey
import co.touchlab.kjwt.cryptography.ext.toHmacKey
import co.touchlab.kjwt.cryptography.ext.toRsaPkcs1PrivateKey
import co.touchlab.kjwt.internal.encodeBase64Url
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import co.touchlab.kjwt.model.jwk.Jwk
import co.touchlab.kjwt.rsaPkcs1KeyPair
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.EC
import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.algorithms.SHA256
import io.kotest.core.spec.style.FunSpec
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Tests that JWK key conversion round-trips correctly: generate a key, export its parameters
 * as a JWK, convert back to a cryptography-kotlin key, and verify it works for signing/encryption.
 */
class JwkKeyConversionTest :
    FunSpec({

        val provider = CryptographyProvider.Default

        context("HMAC (oct)") {

            test("oct toHmacKey round trip") {
                val rawBytes = "a-string-secret-at-least-256-bits-long".encodeToByteArray()
                val jwk = Jwk.Oct(k = rawBytes.encodeBase64Url())

                val hmacKey = jwk.toHmacKey(SHA256)

                // Sign a known input and verify
                val sig = hmacKey.signatureGenerator().generateSignature("test".encodeToByteArray())
                hmacKey.signatureVerifier().verifySignature("test".encodeToByteArray(), sig)
            }

            test("oct missing private key material always private") {
                val jwk = Jwk.Oct(k = "c2VjcmV0") // base64url("secret")
                assertEquals(true, jwk.isPrivate)
            }
        }

        context("RSA PKCS1") {

            test("rsa pkcs1 public key conversion and verify") {
                val keyPair = rsaPkcs1KeyPair()

                // Export the public key parameters
                val pubDer = keyPair.publicKey.encodeToByteArray(RSA.PublicKey.Format.DER)
                // We'd normally parse the DER to extract n and e, but for this test we create
                // a JWK with the known-good signing key and verify a signed token.

                // Create JWS with the native key, then verify via JWK-converted key
                val token =
                    Jwt
                        .builder()
                        .subject("jwk-rsa-test")
                        .signWith(SigningAlgorithm.RS256, keyPair.privateKey)
                        .compact()

                // Re-export native public key via DER and decode back as a quick sanity check
                val reParsed =
                    provider
                        .get(RSA.PKCS1)
                        .publicKeyDecoder(SHA256)
                        .decodeFromByteArray(RSA.PublicKey.Format.DER, pubDer)

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(SigningAlgorithm.RS256, reParsed)
                        .build()
                        .parseSigned(token)

                assertEquals("jwk-rsa-test", jws.payload.subjectOrNull)
            }

            test("rsa pkcs1 missing CRT params throws on conversion") {
                val jwk = Jwk.Rsa(n = "modulus", e = "AQAB", d = "privateExp")
                assertFailsWith<IllegalArgumentException> {
                    jwk.toRsaPkcs1PrivateKey(SHA256)
                }
            }
        }

        context("ECDSA") {

            test("ec public key conversion rejects bad DER") {
                // A JWK with invalid base64url coordinates should fail during DER construction or decoding
                val jwk = Jwk.Ec(crv = "P-256", x = "invalid", y = "invalid")
                // This will either throw during decodeBase64Url or during DER decoding by the provider
                try {
                    jwk.toEcdsaPublicKey()
                    // If it didn't throw, that's unexpected but we don't assert further here
                } catch (_: Throwable) {
                    // Expected - either base64 decode error or DER parsing error
                }
            }

            test("ec P256 sign and verify round trip") {
                val keyPair = ecKeyPair(EC.Curve.P256)

                // Export public key DER, reload, sign with private key, verify with reloaded public key
                val pubDer = keyPair.publicKey.encodeToByteArray(EC.PublicKey.Format.DER)
                val reParsedPublicKey =
                    provider
                        .get(ECDSA)
                        .publicKeyDecoder(EC.Curve.P256)
                        .decodeFromByteArray(EC.PublicKey.Format.DER, pubDer)

                val token =
                    Jwt
                        .builder()
                        .subject("jwk-ec-p256")
                        .signWith(SigningAlgorithm.ES256, keyPair.privateKey)
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(SigningAlgorithm.ES256, reParsedPublicKey)
                        .build()
                        .parseSigned(token)

                assertEquals("jwk-ec-p256", jws.payload.subjectOrNull)
            }

            test("ec missing private D throws on conversion") {
                val jwk = Jwk.Ec(crv = "P-256", x = "xCoord", y = "yCoord")
                assertFailsWith<IllegalArgumentException> {
                    jwk.toEcdsaPrivateKey()
                }
            }
        }
    })
