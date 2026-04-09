package co.touchlab.kjwt

import co.touchlab.kjwt.annotations.DelicateKJWTApi
import co.touchlab.kjwt.cryptography.EncryptionKey
import co.touchlab.kjwt.cryptography.SigningKey
import co.touchlab.kjwt.cryptography.ext.decryptWith
import co.touchlab.kjwt.cryptography.ext.encryptWith
import co.touchlab.kjwt.cryptography.ext.registerEncryptionKey
import co.touchlab.kjwt.cryptography.ext.registerSigningKey
import co.touchlab.kjwt.cryptography.ext.signWith
import co.touchlab.kjwt.cryptography.ext.verifyWith
import co.touchlab.kjwt.ext.subjectOrNull
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.EncryptionContentAlgorithm
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import co.touchlab.kjwt.model.registry.DefaultJwtProcessorRegistry
import io.kotest.core.spec.style.FunSpec
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

@OptIn(DelicateKJWTApi::class) class JwtProcessorRegistryTest :
    FunSpec({
        context("sign using registry") {
            test("sign HS256 using registry signing key") {
                val key = hs256Key()
                val registry = DefaultJwtProcessorRegistry()
                registry.registerSigningKey(
                    SigningKey.SigningOnlyKey(
                        identifier = SigningKey.Identifier(SigningAlgorithm.HS256, null),
                        privateKey = key,
                    ),
                )

                val token =
                    Jwt
                        .builder()
                        .subject("user")
                        .signWith(SigningAlgorithm.HS256, registry)
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(SigningAlgorithm.HS256, key)
                        .build()
                        .parseSigned(token)

                assertEquals("user", jws.payload.subjectOrNull)
            }

            test("sign HS256 using registry with kid") {
                val key = hs256Key()
                val registry = DefaultJwtProcessorRegistry()
                registry.registerSigningKey(
                    SigningKey.SigningOnlyKey(
                        identifier = SigningKey.Identifier(SigningAlgorithm.HS256, "sign-key"),
                        privateKey = key,
                    ),
                )

                val token =
                    Jwt
                        .builder()
                        .subject("user")
                        .signWith(SigningAlgorithm.HS256, registry, "sign-key")
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .verifyWith(SigningAlgorithm.HS256, key, "sign-key")
                        .build()
                        .parseSigned(token)

                assertEquals("user", jws.payload.subjectOrNull)
            }

            test("sign throws when no matching key in registry") {
                val registry = DefaultJwtProcessorRegistry()

                assertFailsWith<IllegalArgumentException> {
                    Jwt
                        .builder()
                        .subject("user")
                        .signWith(SigningAlgorithm.HS256, registry)
                }
            }
        }

        context("verify using useKeysFrom") {

            test("parser delegates verification to shared registry") {
                val key = hs256Key()
                val sharedRegistry = DefaultJwtProcessorRegistry()
                sharedRegistry.registerSigningKey(
                    SigningKey.VerifyOnlyKey(
                        identifier = SigningKey.Identifier(SigningAlgorithm.HS256, null),
                        publicKey = key,
                    ),
                )

                val token =
                    Jwt
                        .builder()
                        .subject("user")
                        .signWith(SigningAlgorithm.HS256, key)
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .useKeysFrom(sharedRegistry)
                        .build()
                        .parseSigned(token)

                assertEquals("user", jws.payload.subjectOrNull)
            }

            test("parser delegates verification to shared registry with kid") {
                val key = hs256Key()
                val sharedRegistry = DefaultJwtProcessorRegistry()
                sharedRegistry.registerSigningKey(
                    SigningKey.VerifyOnlyKey(
                        identifier = SigningKey.Identifier(SigningAlgorithm.HS256, "k1"),
                        publicKey = key,
                    ),
                )

                val token =
                    Jwt
                        .builder()
                        .subject("user")
                        .signWith(SigningAlgorithm.HS256, key, "k1")
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .useKeysFrom(sharedRegistry)
                        .build()
                        .parseSigned(token)

                assertEquals("user", jws.payload.subjectOrNull)
            }

            test("local parser keys take priority over shared registry") {
                val key = hs256Key()
                val wrongKey =
                    hmacKey(
                        dev.whyoleg.cryptography.algorithms.SHA256,
                        "wrong-secret-at-least-256-bits-long-padding".encodeToByteArray(),
                    )
                val sharedRegistry = DefaultJwtProcessorRegistry()
                sharedRegistry.registerSigningKey(
                    SigningKey.VerifyOnlyKey(
                        identifier = SigningKey.Identifier(SigningAlgorithm.HS256, null),
                        publicKey = wrongKey,
                    ),
                )

                val token =
                    Jwt
                        .builder()
                        .subject("user")
                        .signWith(SigningAlgorithm.HS256, key)
                        .compact()

                // Local key (correct) takes precedence over the shared registry (wrong key)
                val jws =
                    Jwt
                        .parser()
                        .verifyWith(SigningAlgorithm.HS256, key)
                        .useKeysFrom(sharedRegistry)
                        .build()
                        .parseSigned(token)

                assertEquals("user", jws.payload.subjectOrNull)
            }
        }

        context("encrypt using registry") {

            test("encrypt Dir A256GCM using registry encryption key") {
                val cek = aesSimpleKey(256)
                val registry = DefaultJwtProcessorRegistry()
                registry.registerEncryptionKey(
                    EncryptionKey.EncryptionOnlyKey(
                        identifier = EncryptionKey.Identifier(EncryptionAlgorithm.Dir, null),
                        publicKey = cek,
                    ),
                )

                val token =
                    Jwt
                        .builder()
                        .subject("user")
                        .encryptWith(registry, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A256GCM)
                        .compact()

                val jwe =
                    Jwt
                        .parser()
                        .decryptWith(cek, EncryptionAlgorithm.Dir)
                        .build()
                        .parseEncrypted(token)

                assertEquals("user", jwe.payload.subjectOrNull)
            }

            test("encrypt Dir A256GCM using registry with kid") {
                val cek = aesSimpleKey(256)
                val registry = DefaultJwtProcessorRegistry()
                registry.registerEncryptionKey(
                    EncryptionKey.EncryptionOnlyKey(
                        identifier = EncryptionKey.Identifier(EncryptionAlgorithm.Dir, "enc-k1"),
                        publicKey = cek,
                    ),
                )

                val token =
                    Jwt
                        .builder()
                        .subject("user")
                        .encryptWith(registry, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A256GCM, "enc-k1")
                        .compact()

                val jwe =
                    Jwt
                        .parser()
                        .decryptWith(cek, EncryptionAlgorithm.Dir, "enc-k1")
                        .build()
                        .parseEncrypted(token)

                assertEquals("user", jwe.payload.subjectOrNull)
            }

            test("encrypt throws when no matching key in registry") {
                val registry = DefaultJwtProcessorRegistry()

                assertFailsWith<IllegalArgumentException> {
                    Jwt
                        .builder()
                        .subject("user")
                        .encryptWith(registry, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A256GCM)
                }
            }
        }

        context("decrypt using useKeysFrom") {

            test("parser delegates decryption to shared registry") {
                val cek = aesSimpleKey(256)
                val sharedRegistry = DefaultJwtProcessorRegistry()
                sharedRegistry.registerEncryptionKey(
                    EncryptionKey.DecryptionOnlyKey(
                        identifier = EncryptionKey.Identifier(EncryptionAlgorithm.Dir, null),
                        privateKey = cek,
                    ),
                )

                val token =
                    Jwt
                        .builder()
                        .subject("user")
                        .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A256GCM)
                        .compact()

                val jwe =
                    Jwt
                        .parser()
                        .useKeysFrom(sharedRegistry)
                        .build()
                        .parseEncrypted(token)

                assertEquals("user", jwe.payload.subjectOrNull)
            }

            test("parser delegates decryption to shared registry with kid") {
                val cek = aesSimpleKey(256)
                val sharedRegistry = DefaultJwtProcessorRegistry()
                sharedRegistry.registerEncryptionKey(
                    EncryptionKey.DecryptionOnlyKey(
                        identifier = EncryptionKey.Identifier(EncryptionAlgorithm.Dir, "enc-k1"),
                        privateKey = cek,
                    ),
                )

                val token =
                    Jwt
                        .builder()
                        .subject("user")
                        .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A256GCM, "enc-k1")
                        .compact()

                val jwe =
                    Jwt
                        .parser()
                        .useKeysFrom(sharedRegistry)
                        .build()
                        .parseEncrypted(token)

                assertEquals("user", jwe.payload.subjectOrNull)
            }
        }

        context("delegation cycle detection") {

            test("self-delegation throws") {
                val registry = DefaultJwtProcessorRegistry()
                assertFailsWith<IllegalArgumentException> {
                    registry.delegateTo(registry)
                }
            }

            test("direct cycle throws") {
                val a = DefaultJwtProcessorRegistry()
                val b = DefaultJwtProcessorRegistry()
                a.delegateTo(b)
                assertFailsWith<IllegalArgumentException> {
                    b.delegateTo(a)
                }
            }

            test("transitive cycle throws") {
                val a = DefaultJwtProcessorRegistry()
                val b = DefaultJwtProcessorRegistry()
                val c = DefaultJwtProcessorRegistry()
                a.delegateTo(b)
                b.delegateTo(c)
                assertFailsWith<IllegalArgumentException> {
                    c.delegateTo(a)
                }
            }

            test("linear chain without cycle is allowed") {
                val a = DefaultJwtProcessorRegistry()
                val b = DefaultJwtProcessorRegistry()
                val c = DefaultJwtProcessorRegistry()
                a.delegateTo(b)
                b.delegateTo(c)
                // no exception expected
            }
        }

        context("full round-trip via merged registry") {

            test("sign and verify using a registry with merged SigningKeyPair") {
                val key = hs256Key()
                val sharedRegistry = DefaultJwtProcessorRegistry()
                // Registering complementary keys merges them into a SigningKeyPair
                sharedRegistry.registerSigningKey(
                    SigningKey.SigningOnlyKey(
                        identifier = SigningKey.Identifier(SigningAlgorithm.HS256, "k1"),
                        privateKey = key,
                    ),
                )
                sharedRegistry.registerSigningKey(
                    SigningKey.VerifyOnlyKey(
                        identifier = SigningKey.Identifier(SigningAlgorithm.HS256, "k1"),
                        publicKey = key,
                    ),
                )

                val token =
                    Jwt
                        .builder()
                        .subject("registry-user")
                        .signWith(SigningAlgorithm.HS256, sharedRegistry, "k1")
                        .compact()

                val jws =
                    Jwt
                        .parser()
                        .useKeysFrom(sharedRegistry)
                        .build()
                        .parseSigned(token)

                assertEquals("registry-user", jws.payload.subjectOrNull)
            }

            test("encrypt and decrypt using a registry with merged EncryptionKeyPair") {
                val cek = aesSimpleKey(256)
                val sharedRegistry = DefaultJwtProcessorRegistry()
                // Register DecryptionOnlyKey first, then EncryptionOnlyKey — merges into EncryptionKeyPair
                sharedRegistry.registerEncryptionKey(
                    EncryptionKey.DecryptionOnlyKey(
                        identifier = EncryptionKey.Identifier(EncryptionAlgorithm.Dir, "enc-k1"),
                        privateKey = cek,
                    ),
                )
                sharedRegistry.registerEncryptionKey(
                    EncryptionKey.EncryptionOnlyKey(
                        identifier = EncryptionKey.Identifier(EncryptionAlgorithm.Dir, "enc-k1"),
                        publicKey = cek,
                    ),
                )

                val token =
                    Jwt
                        .builder()
                        .subject("encrypted-user")
                        .encryptWith(
                            sharedRegistry,
                            EncryptionAlgorithm.Dir,
                            EncryptionContentAlgorithm.A256GCM,
                            "enc-k1"
                        )
                        .compact()

                val jwe =
                    Jwt
                        .parser()
                        .useKeysFrom(sharedRegistry)
                        .build()
                        .parseEncrypted(token)

                assertEquals("encrypted-user", jwe.payload.subjectOrNull)
            }
        }
    })
