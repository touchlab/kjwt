package co.touchlab.kjwt.ext

import co.touchlab.kjwt.Jwt
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

class JwtBuilderExtTest :
    FunSpec({

        context("signWith(String key) - HMAC") {

            test("sign Hs256 string key round trip") {
                val token =
                    Jwt
                        .builder()
                        .subject("ext-hs256")
                        .signWith(SigningAlgorithm.HS256, hs256Secret.decodeToString(), HMAC.Key.Format.RAW)
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(SigningAlgorithm.HS256, hs256Key())
                        .build()
                        .parseSigned(token)

                assertEquals("HS256", jws.header.algorithm)
                assertEquals("ext-hs256", jws.payload.subjectOrNull)
            }

            test("sign Hs384 string key round trip") {
                val token =
                    Jwt
                        .builder()
                        .subject("ext-hs384")
                        .signWith(SigningAlgorithm.HS384, hs384Secret.decodeToString(), HMAC.Key.Format.RAW)
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(SigningAlgorithm.HS384, hs384Key())
                        .build()
                        .parseSigned(token)

                assertEquals("ext-hs384", jws.payload.subjectOrNull)
            }

            test("sign Hs512 string key round trip") {
                val token =
                    Jwt
                        .builder()
                        .subject("ext-hs512")
                        .signWith(SigningAlgorithm.HS512, hs512Secret.decodeToString(), HMAC.Key.Format.RAW)
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(SigningAlgorithm.HS512, hs512Key())
                        .build()
                        .parseSigned(token)

                assertEquals("ext-hs512", jws.payload.subjectOrNull)
            }
        }

        context("signWith(String key) - RSA PKCS1") {
            // PEM is used because PEM is ASCII and survives the String → encodeToByteArray() round-trip.

            test("sign Rs256 string PEM key round trip") {
                val keyPair = rsaPkcs1KeyPair()
                val privatePem = keyPair.privateKey.encodeToByteArray(RSA.PrivateKey.Format.PEM).decodeToString()

                val token =
                    Jwt
                        .builder()
                        .subject("ext-rs256")
                        .signWith(SigningAlgorithm.RS256, privatePem, RSA.PrivateKey.Format.PEM)
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(SigningAlgorithm.RS256, keyPair.publicKey)
                        .build()
                        .parseSigned(token)

                assertEquals("RS256", jws.header.algorithm)
                assertEquals("ext-rs256", jws.payload.subjectOrNull)
            }

            test("sign Rs512 string PEM key round trip") {
                val keyPair = rsaPkcs1KeyPair(SHA512)
                val privatePem = keyPair.privateKey.encodeToByteArray(RSA.PrivateKey.Format.PEM).decodeToString()

                val token =
                    Jwt
                        .builder()
                        .subject("ext-rs512")
                        .signWith(SigningAlgorithm.RS512, privatePem, RSA.PrivateKey.Format.PEM)
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(SigningAlgorithm.RS512, keyPair.publicKey)
                        .build()
                        .parseSigned(token)

                assertEquals("ext-rs512", jws.payload.subjectOrNull)
            }
        }

        context("signWith(String key) - RSA PSS") {

            test("sign Ps256 string PEM key round trip") {
                val keyPair = rsaPssKeyPair()
                val privatePem = keyPair.privateKey.encodeToByteArray(RSA.PrivateKey.Format.PEM).decodeToString()

                val token =
                    Jwt
                        .builder()
                        .subject("ext-ps256")
                        .signWith(SigningAlgorithm.PS256, privatePem, RSA.PrivateKey.Format.PEM)
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(SigningAlgorithm.PS256, keyPair.publicKey)
                        .build()
                        .parseSigned(token)

                assertEquals("PS256", jws.header.algorithm)
                assertEquals("ext-ps256", jws.payload.subjectOrNull)
            }

            test("sign Ps384 string PEM key round trip") {
                val keyPair = rsaPssKeyPair(SHA384)
                val privatePem = keyPair.privateKey.encodeToByteArray(RSA.PrivateKey.Format.PEM).decodeToString()

                val token =
                    Jwt
                        .builder()
                        .subject("ext-ps384")
                        .signWith(SigningAlgorithm.PS384, privatePem, RSA.PrivateKey.Format.PEM)
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(SigningAlgorithm.PS384, keyPair.publicKey)
                        .build()
                        .parseSigned(token)

                assertEquals("ext-ps384", jws.payload.subjectOrNull)
            }
        }

        context("signWith(String key) - ECDSA") {

            test("sign Es256 string PEM key round trip") {
                val keyPair = ecKeyPair(EC.Curve.P256)
                val privatePem = keyPair.privateKey.encodeToByteArray(EC.PrivateKey.Format.PEM).decodeToString()

                val token =
                    Jwt
                        .builder()
                        .subject("ext-es256")
                        .signWith(SigningAlgorithm.ES256, privatePem, EC.PrivateKey.Format.PEM)
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(SigningAlgorithm.ES256, keyPair.publicKey)
                        .build()
                        .parseSigned(token)

                assertEquals("ES256", jws.header.algorithm)
                assertEquals("ext-es256", jws.payload.subjectOrNull)
            }

            test("sign Es512 string PEM key round trip") {
                val keyPair = ecKeyPair(EC.Curve.P521)
                val privatePem = keyPair.privateKey.encodeToByteArray(EC.PrivateKey.Format.PEM).decodeToString()

                val token =
                    Jwt
                        .builder()
                        .subject("ext-es512")
                        .signWith(SigningAlgorithm.ES512, privatePem, EC.PrivateKey.Format.PEM)
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(SigningAlgorithm.ES512, keyPair.publicKey)
                        .build()
                        .parseSigned(token)

                assertEquals("ext-es512", jws.payload.subjectOrNull)
            }
        }

        context("encryptWith(ByteArray)") {

            test("encrypt with byte array key round trip") {
                val keyBytes = Random.nextBytes(32) // 256-bit key for A256GCM

                val token =
                    Jwt
                        .builder()
                        .subject("ext-encrypt-bytes")
                        .encryptWith(keyBytes, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A256GCM)
                        .compact()

                val jwe =
                    Jwt
                        .parser()
                        .decryptWith(keyBytes, EncryptionAlgorithm.Dir)
                        .build()
                        .parseEncrypted(token)

                assertEquals("ext-encrypt-bytes", jwe.payload.subjectOrNull)
            }

            test("encrypt with byte array key CBC algorithm round trip") {
                val keyBytes = Random.nextBytes(64) // 512-bit key for A256CBC-HS512

                val token =
                    Jwt
                        .builder()
                        .subject("ext-encrypt-cbc")
                        .encryptWith(keyBytes, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A256CbcHs512)
                        .compact()

                val jwe =
                    Jwt
                        .parser()
                        .decryptWith(keyBytes, EncryptionAlgorithm.Dir)
                        .build()
                        .parseEncrypted(token)

                assertEquals("ext-encrypt-cbc", jwe.payload.subjectOrNull)
            }
        }

        context("encryptWith(String)") {

            test("encrypt with string key round trip") {
                // 32 ASCII chars → 32 bytes → 256-bit key for A256GCM
                val keyString = "12345678901234567890123456789012"

                val token =
                    Jwt
                        .builder()
                        .subject("ext-encrypt-string")
                        .encryptWith(keyString, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A256GCM)
                        .compact()

                val jwe =
                    Jwt
                        .parser()
                        .decryptWith(keyString.encodeToByteArray(), EncryptionAlgorithm.Dir)
                        .build()
                        .parseEncrypted(token)

                assertEquals("ext-encrypt-string", jwe.payload.subjectOrNull)
            }
        }
    })
