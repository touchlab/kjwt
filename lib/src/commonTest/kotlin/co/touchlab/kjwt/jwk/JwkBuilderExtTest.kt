package co.touchlab.kjwt.jwk

import co.touchlab.kjwt.Jwt
import co.touchlab.kjwt.ext.signWith
import co.touchlab.kjwt.ext.subjectOrNull
import co.touchlab.kjwt.ext.verifyWith
import co.touchlab.kjwt.hs256Secret
import co.touchlab.kjwt.hs384Secret
import co.touchlab.kjwt.hs512Secret
import co.touchlab.kjwt.internal.encodeBase64Url
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import co.touchlab.kjwt.model.jwk.Jwk
import io.kotest.core.spec.style.FunSpec
import kotlin.test.assertEquals

/**
 * Tests the JWK builder/parser extensions end-to-end.
 *
 * HMAC (oct) tests use the existing TestFixtures secrets.
 * RSA/EC round-trip tests are deferred until JWK export is implemented, at which point we will
 * be able to generate a key pair, export it as a JWK, and verify the import-export round-trip.
 */
class JwkBuilderExtTest : FunSpec({

    context("HMAC (oct)") {

        test("sign with Hs256 JWK round trip") {
            val jwk = Jwk.Oct(k = hs256Secret.encodeBase64Url(), alg = "HS256")

            val token = Jwt.builder()
                .subject("jwk-hs256")
                .signWith(SigningAlgorithm.HS256, jwk)
                .compact()

            val jws = Jwt.parser()
                .verifyWith(SigningAlgorithm.HS256, jwk)
                .build()
                .parseSigned(token)

            assertEquals("HS256", jws.header.algorithm)
            assertEquals("jwk-hs256", jws.payload.subjectOrNull)
        }

        test("sign with Hs384 JWK round trip") {
            val jwk = Jwk.Oct(k = hs384Secret.encodeBase64Url(), alg = "HS384")

            val token = Jwt.builder()
                .subject("jwk-hs384")
                .signWith(SigningAlgorithm.HS384, jwk)
                .compact()

            val jws = Jwt.parser()
                .verifyWith(SigningAlgorithm.HS384, jwk)
                .build()
                .parseSigned(token)

            assertEquals("HS384", jws.header.algorithm)
            assertEquals("jwk-hs384", jws.payload.subjectOrNull)
        }

        test("sign with Hs512 JWK round trip") {
            val jwk = Jwk.Oct(k = hs512Secret.encodeBase64Url(), alg = "HS512")

            val token = Jwt.builder()
                .subject("jwk-hs512")
                .signWith(SigningAlgorithm.HS512, jwk)
                .compact()

            val jws = Jwt.parser()
                .verifyWith(SigningAlgorithm.HS512, jwk)
                .build()
                .parseSigned(token)

            assertEquals("HS512", jws.header.algorithm)
            assertEquals("jwk-hs512", jws.payload.subjectOrNull)
        }

        test("sign with Hs256 JWK cross verify with native key") {
            // Sign via JWK, verify via the same raw bytes loaded as a native HMAC key —
            // confirms JWK-derived and natively-loaded keys produce identical results.
            val jwk = Jwk.Oct(k = hs256Secret.encodeBase64Url())

            val token = Jwt.builder()
                .subject("jwk-cross-verify")
                .signWith(SigningAlgorithm.HS256, jwk)
                .compact()

            val nativeKey = dev.whyoleg.cryptography.CryptographyProvider.Default
                .get(dev.whyoleg.cryptography.algorithms.HMAC)
                .keyDecoder(dev.whyoleg.cryptography.algorithms.SHA256)
                .decodeFromByteArray(dev.whyoleg.cryptography.algorithms.HMAC.Key.Format.RAW, hs256Secret)

            val jws = Jwt.parser()
                .verifyWith(SigningAlgorithm.HS256, nativeKey)
                .build()
                .parseSigned(token)

            assertEquals("jwk-cross-verify", jws.payload.subjectOrNull)
        }
    }
})
