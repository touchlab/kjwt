package co.touchlab.kjwt.hardware

import co.touchlab.kjwt.hardware.model.SecureHardwarePreference
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import co.touchlab.kjwt.processor.JwsProcessor
import androidx.test.filters.SdkSuppress
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Test
import java.security.KeyStore
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class SecureHardwareSigningKeyTest {

    @After
    fun cleanup() {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        listOf(
            "__kjwt_test_hs256", "__kjwt_test_hs384", "__kjwt_test_hs512",
            "__kjwt_test_rs256", "__kjwt_test_ps256",
            "__kjwt_test_es256", "__kjwt_test_es384", "__kjwt_test_es512",
            "__kjwt_test_sb_preferred", "__kjwt_test_sb_none",
            "__kjwt_test_tamper", "__kjwt_test_corrupt",
        ).forEach { runCatching { ks.deleteEntry(it) } }
    }

    // -------------------------------------------------------------------------
    // JWS — HMAC
    // -------------------------------------------------------------------------

    @Test fun hs256SignAndVerify() = runBlocking { assertJwsRoundTrip(SigningAlgorithm.HS256, "__kjwt_test_hs256") }

    @Test fun hs384SignAndVerify() = runBlocking { assertJwsRoundTrip(SigningAlgorithm.HS384, "__kjwt_test_hs384") }

    @Test fun hs512SignAndVerify() = runBlocking { assertJwsRoundTrip(SigningAlgorithm.HS512, "__kjwt_test_hs512") }

    // -------------------------------------------------------------------------
    // JWS — RSA PKCS#1 v1.5  (one variant — key generation is slow on simulators)
    // -------------------------------------------------------------------------

    @Test fun rs256SignAndVerify() = runBlocking { assertJwsRoundTrip(SigningAlgorithm.RS256, "__kjwt_test_rs256") }

    // -------------------------------------------------------------------------
    // JWS — RSA PSS
    // -------------------------------------------------------------------------

    @Test
    @SdkSuppress(minSdkVersion = 28) // Android Keystore PSS parameter configuration requires API 28+
    fun ps256SignAndVerify() = runBlocking { assertJwsRoundTrip(SigningAlgorithm.PS256, "__kjwt_test_ps256") }

    // -------------------------------------------------------------------------
    // JWS — ECDSA  (validates DER↔P1363 conversion for all three curves)
    // -------------------------------------------------------------------------

    @Test fun es256SignAndVerify() = runBlocking { assertJwsRoundTrip(SigningAlgorithm.ES256, "__kjwt_test_es256") }

    @Test fun es384SignAndVerify() = runBlocking { assertJwsRoundTrip(SigningAlgorithm.ES384, "__kjwt_test_es384") }

    @Test fun es512SignAndVerify() = runBlocking { assertJwsRoundTrip(SigningAlgorithm.ES512, "__kjwt_test_es512") }

    // -------------------------------------------------------------------------
    // Secure Hardware Preference
    // -------------------------------------------------------------------------

    // Preferred must never throw — on devices without dedicated secure hardware it
    // silently falls back to the default storage.
    @Test fun preferredFallsBackGracefully() = runBlocking {
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
    @Test fun noneWorksNormally() = runBlocking {
        assertJwsRoundTrip(
            algorithm = SigningAlgorithm.ES256,
            keyId = "__kjwt_test_sb_none",
            secureHardwarePreference = SecureHardwarePreference.None,
        )
    }

    // -------------------------------------------------------------------------
    // Edge cases
    // -------------------------------------------------------------------------

    // A tampered payload must not verify successfully.
    @Test fun tamperedDataFailsVerification() = runBlocking {
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
    @Test fun corruptedSignatureFailsVerification() = runBlocking {
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
