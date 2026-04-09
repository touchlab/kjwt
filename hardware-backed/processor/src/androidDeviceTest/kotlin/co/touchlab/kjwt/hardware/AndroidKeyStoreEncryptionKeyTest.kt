package co.touchlab.kjwt.hardware

import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.EncryptionContentAlgorithm
import co.touchlab.kjwt.processor.JweProcessor
import io.kotest.core.spec.style.FunSpec
import io.kotest.runner.junit4.KotestTestRunner
import org.junit.runner.RunWith
import java.security.KeyStore
import kotlin.test.assertIs
import kotlin.test.assertTrue

@RunWith(KotestTestRunner::class)
class AndroidKeyStoreEncryptionKeyTest : FunSpec({
    // Removes every key written by these tests from the Android Keystore.
    // Each test uses a keyId that starts with "__kjwt_test_" so cleanup is safe.
    afterTest {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        ks.aliases().toList()
            .filter { it.startsWith("__kjwt_test_") }
            .forEach { ks.deleteEntry(it) }
    }

    // -------------------------------------------------------------------------
    // JWE — RSA-OAEP with several content algorithms
    // -------------------------------------------------------------------------

    context("JWE RSA-OAEP round trips") {
        test("RSA-OAEP with A256GCM") {
            assertJweRoundTrip(
                algorithm = EncryptionAlgorithm.RsaOaep,
                contentAlgorithm = EncryptionContentAlgorithm.A256GCM,
                keyId = "__kjwt_test_oaep",
            )
        }

        test("RSA-OAEP with A128CbcHs256") {
            assertJweRoundTrip(
                algorithm = EncryptionAlgorithm.RsaOaep,
                contentAlgorithm = EncryptionContentAlgorithm.A128CbcHs256,
                keyId = "__kjwt_test_oaep_cbc",
            )
        }

        test("RSA-OAEP-256 with A256GCM") {
            assertJweRoundTrip(
                algorithm = EncryptionAlgorithm.RsaOaep256,
                contentAlgorithm = EncryptionContentAlgorithm.A256GCM,
                keyId = "__kjwt_test_oaep256",
            )
        }

        test("RSA-OAEP-256 with A256CbcHs512") {
            assertJweRoundTrip(
                algorithm = EncryptionAlgorithm.RsaOaep256,
                contentAlgorithm = EncryptionContentAlgorithm.A256CbcHs512,
                keyId = "__kjwt_test_oaep256_cbc",
            )
        }
    }
})

private suspend fun assertJweRoundTrip(
    algorithm: EncryptionAlgorithm,
    contentAlgorithm: EncryptionContentAlgorithm,
    keyId: String,
) {
    val processor = AndroidKeyStoreEncryptionKey.getOrCreateInstance(
        algorithm = algorithm,
        keyId = keyId,
    )
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
