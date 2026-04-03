package co.touchlab.kjwt.hardware

import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.EncryptionContentAlgorithm
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import co.touchlab.kjwt.processor.JweProcessor
import co.touchlab.kjwt.processor.JwsProcessor
import kotlinx.coroutines.test.runTest
import java.security.KeyStore
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AndroidKeystoreJwtProcessorRegistryTest {

    private val registry = AndroidKeystoreJwtProcessorRegistry()

    // Removes every key written by these tests from the Android Keystore.
    // Each test uses a keyId that starts with "__kjwt_test_" so cleanup is safe.
    @AfterTest
    fun cleanupKeystore() {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        ks.aliases().toList()
            .filter { it.startsWith("__kjwt_test_") }
            .forEach { ks.deleteEntry(it) }
    }

    // -------------------------------------------------------------------------
    // JWS — HMAC
    // -------------------------------------------------------------------------

    @Test
    fun jwsHs256SignAndVerify() = runTest {
        assertJwsRoundTrip(SigningAlgorithm.HS256, keyId = "__kjwt_test_hs256")
    }

    @Test
    fun jwsHs384SignAndVerify() = runTest {
        assertJwsRoundTrip(SigningAlgorithm.HS384, keyId = "__kjwt_test_hs384")
    }

    @Test
    fun jwsHs512SignAndVerify() = runTest {
        assertJwsRoundTrip(SigningAlgorithm.HS512, keyId = "__kjwt_test_hs512")
    }

    // -------------------------------------------------------------------------
    // JWS — RSA PKCS#1 v1.5  (one variant — key generation is slow on emulators)
    // -------------------------------------------------------------------------

    @Test
    fun jwsRs256SignAndVerify() = runTest {
        assertJwsRoundTrip(SigningAlgorithm.RS256, keyId = "__kjwt_test_rs256")
    }

    // -------------------------------------------------------------------------
    // JWS — RSA PSS  (requires API 23+, which is this module's minSdk)
    // -------------------------------------------------------------------------

    @Test
    fun jwsPs256SignAndVerify() = runTest {
        assertJwsRoundTrip(SigningAlgorithm.PS256, keyId = "__kjwt_test_ps256")
    }

    // -------------------------------------------------------------------------
    // JWS — ECDSA  (validates DER↔P1363 conversion for all three curves)
    // -------------------------------------------------------------------------

    @Test
    fun jwsEs256SignAndVerify() = runTest {
        assertJwsRoundTrip(SigningAlgorithm.ES256, keyId = "__kjwt_test_es256")
    }

    @Test
    fun jwsEs384SignAndVerify() = runTest {
        assertJwsRoundTrip(SigningAlgorithm.ES384, keyId = "__kjwt_test_es384")
    }

    @Test
    fun jwsEs512SignAndVerify() = runTest {
        assertJwsRoundTrip(SigningAlgorithm.ES512, keyId = "__kjwt_test_es512")
    }

    // -------------------------------------------------------------------------
    // JWE — RSA-OAEP with several content algorithms
    // -------------------------------------------------------------------------

    @Test
    fun jweRsaOaepA256GcmRoundTrip() = runTest {
        assertJweRoundTrip(
            algorithm = EncryptionAlgorithm.RsaOaep,
            contentAlgorithm = EncryptionContentAlgorithm.A256GCM,
            keyId = "__kjwt_test_oaep",
        )
    }

    @Test
    fun jweRsaOaepA128CbcHs256RoundTrip() = runTest {
        assertJweRoundTrip(
            algorithm = EncryptionAlgorithm.RsaOaep,
            contentAlgorithm = EncryptionContentAlgorithm.A128CbcHs256,
            keyId = "__kjwt_test_oaep_cbc",
        )
    }

    @Test
    fun jweRsaOaep256A256GcmRoundTrip() = runTest {
        assertJweRoundTrip(
            algorithm = EncryptionAlgorithm.RsaOaep256,
            contentAlgorithm = EncryptionContentAlgorithm.A256GCM,
            keyId = "__kjwt_test_oaep256",
        )
    }

    @Test
    fun jweRsaOaep256A256CbcHs512RoundTrip() = runTest {
        assertJweRoundTrip(
            algorithm = EncryptionAlgorithm.RsaOaep256,
            contentAlgorithm = EncryptionContentAlgorithm.A256CbcHs512,
            keyId = "__kjwt_test_oaep256_cbc",
        )
    }

    // -------------------------------------------------------------------------
    // StrongBox
    // -------------------------------------------------------------------------

    // StrongBox.Preferred must never throw — on devices without StrongBox it
    // silently falls back to the default TEE-backed keystore.
    @Test
    fun strongBoxPreferredFallsBackGracefully() = runTest {
        val preferredRegistry = AndroidKeystoreJwtProcessorRegistry(
            keyGenerationArguments = AndroidKeystoreJwtProcessorRegistry.KeyGenerationArguments(
                strongBoxMode = AndroidKeystoreJwtProcessorRegistry.StrongBoxMode.Preferred,
            ),
        )
        val processor = preferredRegistry.findBestJwsProcessor(
            algorithm = SigningAlgorithm.ES256,
            keyId = "__kjwt_test_sb_preferred",
        )
        assertNotNull(processor)
        assertIs<JwsProcessor>(processor)

        val data = "strongbox-fallback-test".encodeToByteArray()
        val sig = processor.sign(data)
        assertTrue(processor.verify(data, sig))
    }

    // StrongBox.None must behave identically to the default.
    @Test
    fun strongBoxNoneWorksNormally() = runTest {
        val noneRegistry = AndroidKeystoreJwtProcessorRegistry(
            keyGenerationArguments = AndroidKeystoreJwtProcessorRegistry.KeyGenerationArguments(
                strongBoxMode = AndroidKeystoreJwtProcessorRegistry.StrongBoxMode.None,
            ),
        )
        assertJwsRoundTripWith(noneRegistry, SigningAlgorithm.ES256, keyId = "__kjwt_test_sb_none")
    }

    // -------------------------------------------------------------------------
    // Edge cases
    // -------------------------------------------------------------------------

    // alg=none must never return a processor from a hardware-backed registry.
    @Test
    fun noneAlgorithmReturnsNull() = runTest {
        assertNull(registry.findBestJwsProcessor(SigningAlgorithm.None, keyId = null))
    }

    // When auto-generation is disabled and no key exists the result is null.
    @Test
    fun noAutoGenerationReturnsNull() = runTest {
        val noGenRegistry = AndroidKeystoreJwtProcessorRegistry(keyGenerationArguments = null)
        assertNull(
            noGenRegistry.findBestJwsProcessor(SigningAlgorithm.ES256, keyId = "__kjwt_test_missing"),
        )
    }

    // Dir uses a pre-shared symmetric key, which doesn't fit the hardware-backed
    // model — the registry must return null (or forward to a delegate).
    @Test
    fun dirAlgorithmReturnsNull() = runTest {
        assertNull(registry.findBestJweProcessor(EncryptionAlgorithm.Dir, keyId = null))
    }

    // A tampered payload must not verify successfully.
    @Test
    fun tamperedDataFailsVerification() = runTest {
        val processor = registry.findBestJwsProcessor(SigningAlgorithm.ES256, "__kjwt_test_tamper")
        assertNotNull(processor)
        assertIs<JwsProcessor>(processor)

        val original = "header.payload".encodeToByteArray()
        val signature = processor.sign(original)

        assertFalse(
            processor.verify("header.modified".encodeToByteArray(), signature),
            "Tampered data must not pass signature verification",
        )
    }

    // A truncated or corrupted signature must not verify successfully.
    @Test
    fun corruptedSignatureFailsVerification() = runTest {
        val processor = registry.findBestJwsProcessor(SigningAlgorithm.HS256, "__kjwt_test_corrupt")
        assertNotNull(processor)
        assertIs<JwsProcessor>(processor)

        val data = "header.payload".encodeToByteArray()
        val signature = processor.sign(data)
        val corrupted = signature.copyOf(signature.size - 1) // truncate last byte

        assertFalse(
            processor.verify(data, corrupted),
            "Corrupted signature must not pass verification",
        )
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private suspend fun assertJwsRoundTrip(algorithm: SigningAlgorithm, keyId: String) {
        assertJwsRoundTripWith(registry, algorithm, keyId)
    }

    private suspend fun assertJwsRoundTripWith(
        reg: AndroidKeystoreJwtProcessorRegistry,
        algorithm: SigningAlgorithm,
        keyId: String,
    ) {
        val processor = reg.findBestJwsProcessor(algorithm, keyId)
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

    private suspend fun assertJweRoundTrip(
        algorithm: EncryptionAlgorithm,
        contentAlgorithm: EncryptionContentAlgorithm,
        keyId: String,
    ) {
        val processor = registry.findBestJweProcessor(algorithm, keyId)
        assertNotNull(processor)
        assertIs<JweProcessor>(processor)

        val plaintext = "secret payload content".encodeToByteArray()
        val aad = "protected.header".encodeToByteArray()

        val result = processor.encrypt(plaintext, aad, contentAlgorithm)
        val decrypted = processor.decrypt(
            aad,
            result.encryptedKey,
            result.iv,
            result.ciphertext,
            result.tag,
            contentAlgorithm,
        )

        assertTrue(
            plaintext.contentEquals(decrypted),
            "Decrypted content must match original plaintext for ${algorithm.id}/${contentAlgorithm.id}",
        )
    }
}
