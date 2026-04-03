package co.touchlab.kjwt.ext

import co.touchlab.kjwt.Jwt
import co.touchlab.kjwt.cryptography.SimpleKey
import co.touchlab.kjwt.cryptography.ext.decryptWith
import co.touchlab.kjwt.cryptography.ext.encryptWith
import co.touchlab.kjwt.cryptography.ext.signWith
import co.touchlab.kjwt.cryptography.ext.verifyWith
import co.touchlab.kjwt.ecKeyPair
import co.touchlab.kjwt.hs256Key
import co.touchlab.kjwt.hs256Secret
import co.touchlab.kjwt.hs384Key
import co.touchlab.kjwt.hs384Secret
import co.touchlab.kjwt.hs512Key
import co.touchlab.kjwt.hs512Secret
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.EncryptionContentAlgorithm
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import co.touchlab.kjwt.rsaPkcs1KeyPair
import co.touchlab.kjwt.rsaPssKeyPair
import dev.whyoleg.cryptography.algorithms.EC
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.algorithms.SHA384
import dev.whyoleg.cryptography.algorithms.SHA512
import io.kotest.core.spec.style.FunSpec
import kotlin.random.Random
import kotlin.test.assertEquals

class JwtParserBuilderExtTest :
    FunSpec({

        context("verifyWith(String key) - HMAC") {

            test("verify Hs256 string key round trip") {
                val token =
                    Jwt
                        .builder()
                        .subject("parser-ext-hs256")
                        .signWith(SigningAlgorithm.HS256, hs256Key())
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(SigningAlgorithm.HS256, hs256Secret.decodeToString(), HMAC.Key.Format.RAW)
                        .build()
                        .parseSigned(token)

                assertEquals("HS256", jws.header.algorithm)
                assertEquals("parser-ext-hs256", jws.payload.subjectOrNull)
            }

            test("verify Hs384 string key round trip") {
                val token =
                    Jwt
                        .builder()
                        .subject("parser-ext-hs384")
                        .signWith(SigningAlgorithm.HS384, hs384Key())
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(SigningAlgorithm.HS384, hs384Secret.decodeToString(), HMAC.Key.Format.RAW)
                        .build()
                        .parseSigned(token)

                assertEquals("parser-ext-hs384", jws.payload.subjectOrNull)
            }

            test("verify Hs512 string key round trip") {
                val token =
                    Jwt
                        .builder()
                        .subject("parser-ext-hs512")
                        .signWith(SigningAlgorithm.HS512, hs512Key())
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(SigningAlgorithm.HS512, hs512Secret.decodeToString(), HMAC.Key.Format.RAW)
                        .build()
                        .parseSigned(token)

                assertEquals("parser-ext-hs512", jws.payload.subjectOrNull)
            }
        }

        context("verifyWith(String key) - RSA PKCS1") {
            // PEM is used because PEM is ASCII and survives the String → encodeToByteArray() round-trip.

            test("verify Rs256 string PEM key round trip") {
                val keyPair = rsaPkcs1KeyPair()
                val publicPem = keyPair.publicKey.encodeToByteArray(RSA.PublicKey.Format.PEM).decodeToString()

                val token =
                    Jwt
                        .builder()
                        .subject("parser-ext-rs256")
                        .signWith(SigningAlgorithm.RS256, keyPair.privateKey)
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(SigningAlgorithm.RS256, publicPem, RSA.PublicKey.Format.PEM)
                        .build()
                        .parseSigned(token)

                assertEquals("RS256", jws.header.algorithm)
                assertEquals("parser-ext-rs256", jws.payload.subjectOrNull)
            }

            test("verify Rs512 string PEM key round trip") {
                val keyPair = rsaPkcs1KeyPair(SHA512)
                val publicPem = keyPair.publicKey.encodeToByteArray(RSA.PublicKey.Format.PEM).decodeToString()

                val token =
                    Jwt
                        .builder()
                        .subject("parser-ext-rs512")
                        .signWith(SigningAlgorithm.RS512, keyPair.privateKey)
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(SigningAlgorithm.RS512, publicPem, RSA.PublicKey.Format.PEM)
                        .build()
                        .parseSigned(token)

                assertEquals("parser-ext-rs512", jws.payload.subjectOrNull)
            }
        }

        context("verifyWith(String key) - RSA PSS") {

            test("verify Ps256 string PEM key round trip") {
                val keyPair = rsaPssKeyPair()
                val publicPem = keyPair.publicKey.encodeToByteArray(RSA.PublicKey.Format.PEM).decodeToString()

                val token =
                    Jwt
                        .builder()
                        .subject("parser-ext-ps256")
                        .signWith(SigningAlgorithm.PS256, keyPair.privateKey)
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(SigningAlgorithm.PS256, publicPem, RSA.PublicKey.Format.PEM)
                        .build()
                        .parseSigned(token)

                assertEquals("PS256", jws.header.algorithm)
                assertEquals("parser-ext-ps256", jws.payload.subjectOrNull)
            }

            test("verify Ps384 string PEM key round trip") {
                val keyPair = rsaPssKeyPair(SHA384)
                val publicPem = keyPair.publicKey.encodeToByteArray(RSA.PublicKey.Format.PEM).decodeToString()

                val token =
                    Jwt
                        .builder()
                        .subject("parser-ext-ps384")
                        .signWith(SigningAlgorithm.PS384, keyPair.privateKey)
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(SigningAlgorithm.PS384, publicPem, RSA.PublicKey.Format.PEM)
                        .build()
                        .parseSigned(token)

                assertEquals("parser-ext-ps384", jws.payload.subjectOrNull)
            }
        }

        context("verifyWith(String key) - ECDSA") {

            test("verify Es256 string PEM key round trip") {
                val keyPair = ecKeyPair(EC.Curve.P256)
                val publicPem = keyPair.publicKey.encodeToByteArray(EC.PublicKey.Format.PEM).decodeToString()

                val token =
                    Jwt
                        .builder()
                        .subject("parser-ext-es256")
                        .signWith(SigningAlgorithm.ES256, keyPair.privateKey)
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(SigningAlgorithm.ES256, publicPem, EC.PublicKey.Format.PEM)
                        .build()
                        .parseSigned(token)

                assertEquals("ES256", jws.header.algorithm)
                assertEquals("parser-ext-es256", jws.payload.subjectOrNull)
            }

            test("verify Es512 string PEM key round trip") {
                val keyPair = ecKeyPair(EC.Curve.P521)
                val publicPem = keyPair.publicKey.encodeToByteArray(EC.PublicKey.Format.PEM).decodeToString()

                val token =
                    Jwt
                        .builder()
                        .subject("parser-ext-es512")
                        .signWith(SigningAlgorithm.ES512, keyPair.privateKey)
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(SigningAlgorithm.ES512, publicPem, EC.PublicKey.Format.PEM)
                        .build()
                        .parseSigned(token)

                assertEquals("parser-ext-es512", jws.payload.subjectOrNull)
            }
        }

        context("decryptWith(ByteArray)") {

            test("decrypt with byte array key round trip") {
                val keyBytes = Random.nextBytes(32) // 256-bit key for A256GCM

                val token =
                    Jwt
                        .builder()
                        .subject("parser-ext-decrypt-bytes")
                        .encryptWith(SimpleKey(keyBytes), EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A256GCM)
                        .compact()

                val jwe =
                    Jwt
                        .parser()
                        .decryptWith(keyBytes, EncryptionAlgorithm.Dir)
                        .build()
                        .parseEncrypted(token)

                assertEquals("parser-ext-decrypt-bytes", jwe.payload.subjectOrNull)
            }

            test("decrypt with byte array key CBC algorithm round trip") {
                val keyBytes = Random.nextBytes(64) // 512-bit key for A256CBC-HS512

                val token =
                    Jwt
                        .builder()
                        .subject("parser-ext-decrypt-cbc")
                        .encryptWith(
                            SimpleKey(keyBytes),
                            EncryptionAlgorithm.Dir,
                            EncryptionContentAlgorithm.A256CbcHs512
                        )
                        .compact()

                val jwe =
                    Jwt
                        .parser()
                        .decryptWith(keyBytes, EncryptionAlgorithm.Dir)
                        .build()
                        .parseEncrypted(token)

                assertEquals("parser-ext-decrypt-cbc", jwe.payload.subjectOrNull)
            }
        }

        context("decryptWith(String)") {

            test("decrypt with string key round trip") {
                // 32 ASCII chars → 32 bytes → 256-bit key for A256GCM
                val keyString = "12345678901234567890123456789012"

                val token =
                    Jwt
                        .builder()
                        .subject("parser-ext-decrypt-string")
                        .encryptWith(
                            SimpleKey(keyString.encodeToByteArray()),
                            EncryptionAlgorithm.Dir,
                            EncryptionContentAlgorithm.A256GCM
                        )
                        .compact()

                val jwe =
                    Jwt
                        .parser()
                        .decryptWith(keyString, EncryptionAlgorithm.Dir)
                        .build()
                        .parseEncrypted(token)

                assertEquals("parser-ext-decrypt-string", jwe.payload.subjectOrNull)
            }
        }
    })