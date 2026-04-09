package co.touchlab.kjwt.hardware

import co.touchlab.kjwt.hardware.model.SecureHardwarePreference
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import co.touchlab.kjwt.processor.JwsProcessor
import io.kotest.core.spec.style.FunSpec
import io.kotest.runner.junit4.KotestTestRunner
import org.junit.runner.RunWith
import java.security.KeyStore
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@RunWith(KotestTestRunner::class)
class SecureHardwareSigningKeyTest : FunSpec({
    val testKeyIds = listOf(
        "__kjwt_test_hs256",
        "__kjwt_test_hs384",
        "__kjwt_test_hs512",
        "__kjwt_test_rs256",
        "__kjwt_test_ps256",
        "__kjwt_test_es256",
        "__kjwt_test_es384",
        "__kjwt_test_es512",
        "__kjwt_test_sb_preferred",
        "__kjwt_test_sb_none",
        "__kjwt_test_tamper",
        "__kjwt_test_corrupt",
    )

    afterTest {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        testKeyIds.forEach { runCatching { ks.deleteEntry(it) } }
    }

    // -------------------------------------------------------------------------
    // JWS — HMAC
    // -------------------------------------------------------------------------

    context("JWS HMAC") {
        test("HS256 sign and verify") {
            assertJwsRoundTrip(SigningAlgorithm.HS256, keyId = "__kjwt_test_hs256")
        }

        test("HS384 sign and verify") {
            assertJwsRoundTrip(SigningAlgorithm.HS384, keyId = "__kjwt_test_hs384")
        }

        test("HS512 sign and verify") {
            assertJwsRoundTrip(SigningAlgorithm.HS512, keyId = "__kjwt_test_hs512")
        }
    }

    // -------------------------------------------------------------------------
    // JWS — RSA PKCS#1 v1.5  (one variant — key generation is slow on simulators)
    // -------------------------------------------------------------------------

    context("JWS RSA PKCS#1 v1.5") {
        test("RS256 sign and verify") {
            assertJwsRoundTrip(SigningAlgorithm.RS256, keyId = "__kjwt_test_rs256")
        }
    }

    // -------------------------------------------------------------------------
    // JWS — RSA PSS
    // -------------------------------------------------------------------------

    context("JWS RSA PSS") {
        test("PS256 sign and verify") {
            assertJwsRoundTrip(SigningAlgorithm.PS256, keyId = "__kjwt_test_ps256")
        }
    }

    // -------------------------------------------------------------------------
    // JWS — ECDSA  (validates DER↔P1363 conversion for all three curves)
    // -------------------------------------------------------------------------

    context("JWS ECDSA") {
        test("ES256 sign and verify") {
            assertJwsRoundTrip(SigningAlgorithm.ES256, keyId = "__kjwt_test_es256")
        }

        test("ES384 sign and verify") {
            assertJwsRoundTrip(SigningAlgorithm.ES384, keyId = "__kjwt_test_es384")
        }

        test("ES512 sign and verify") {
            assertJwsRoundTrip(SigningAlgorithm.ES512, keyId = "__kjwt_test_es512")
        }
    }

    // -------------------------------------------------------------------------
    // Secure Hardware Preference
    // -------------------------------------------------------------------------

    context("secure hardware preference") {
        // Preferred must never throw — on devices without dedicated secure hardware it
        // silently falls back to the default storage.
        test("Preferred falls back gracefully") {
            val processor = SecureKeyFactory.getOrCreateSecureSigningKey(
                algorithm = SigningAlgorithm.ES256,
                keyId = "__kjwt_test_sb_preferred",
                secureHardwarePreference = SecureHardwarePreference.Preferred,
            )
            assertIs<JwsProcessor>(processor)

            val data = "secure-hardware-fallback-test".encodeToByteArray()
            val sig = processor.sign(data)
            assertTrue(processor.verify(data, sig))
        }

        // None must behave identically to the default.
        test("None works normally") {
            assertJwsRoundTrip(
                algorithm = SigningAlgorithm.ES256,
                keyId = "__kjwt_test_sb_none",
                secureHardwarePreference = SecureHardwarePreference.None,
            )
        }
    }

    // -------------------------------------------------------------------------
    // Edge cases
    // -------------------------------------------------------------------------

    context("edge cases") {
        // A tampered payload must not verify successfully.
        test("tampered data fails verification") {
            val processor = SecureKeyFactory.getOrCreateSecureSigningKey(
                algorithm = SigningAlgorithm.ES256,
                keyId = "__kjwt_test_tamper",
            )

            val original = "header.payload".encodeToByteArray()
            val signature = processor.sign(original)

            assertFalse(
                processor.verify("header.modified".encodeToByteArray(), signature),
                "Tampered data must not pass signature verification",
            )
        }

        // A truncated or corrupted signature must not verify successfully.
        test("corrupted signature fails verification") {
            val processor = SecureKeyFactory.getOrCreateSecureSigningKey(
                algorithm = SigningAlgorithm.HS256,
                keyId = "__kjwt_test_corrupt",
            )

            val data = "header.payload".encodeToByteArray()
            val signature = processor.sign(data)
            val corrupted = signature.copyOf(signature.size - 1)

            assertFalse(
                processor.verify(data, corrupted),
                "Corrupted signature must not pass verification",
            )
        }
    }
})

private suspend fun assertJwsRoundTrip(
    algorithm: SigningAlgorithm,
    keyId: String,
    secureHardwarePreference: SecureHardwarePreference = SecureHardwarePreference.None,
) {
    val processor = SecureKeyFactory.getOrCreateSecureSigningKey(
        algorithm = algorithm,
        keyId = keyId,
        secureHardwarePreference = secureHardwarePreference,
    )
    assertNotNull(processor)
    assertIs<JwsProcessor>(processor)

    val data = "header.payload".encodeToByteArray()
    val signature = processor.sign(data)

    assertTrue(
        processor.verify(data, signature),
        "Valid signature for ${algorithm.id} should verify successfully",
    )
    assertFalse(
        processor.verify("header.other".encodeToByteArray(), signature),
        "Signature for ${algorithm.id} should not verify against different data",
    )
}
