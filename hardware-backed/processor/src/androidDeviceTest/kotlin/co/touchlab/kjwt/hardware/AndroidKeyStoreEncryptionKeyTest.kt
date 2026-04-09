package co.touchlab.kjwt.hardware

import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.EncryptionContentAlgorithm
import co.touchlab.kjwt.processor.JweProcessor
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Test
import java.security.KeyStore
import kotlin.test.assertIs
import kotlin.test.assertTrue

class AndroidKeyStoreEncryptionKeyTest {

    @After
    fun cleanup() {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        ks.aliases().toList()
            .filter { it.startsWith("__kjwt_test_") }
            .forEach { ks.deleteEntry(it) }
    }

    // -------------------------------------------------------------------------
    // JWE — RSA-OAEP with several content algorithms
    // -------------------------------------------------------------------------

    @Test fun rsaOaepWithA256GCM() = runBlocking {
        assertJweRoundTrip(EncryptionAlgorithm.RsaOaep, EncryptionContentAlgorithm.A256GCM, "__kjwt_test_oaep")
    }

    @Test fun rsaOaepWithA128CbcHs256() = runBlocking {
        assertJweRoundTrip(EncryptionAlgorithm.RsaOaep, EncryptionContentAlgorithm.A128CbcHs256, "__kjwt_test_oaep_cbc")
    }

    @Test fun rsaOaep256WithA256GCM() = runBlocking {
        assertJweRoundTrip(EncryptionAlgorithm.RsaOaep256, EncryptionContentAlgorithm.A256GCM, "__kjwt_test_oaep256")
    }

    @Test fun rsaOaep256WithA256CbcHs512() = runBlocking {
        assertJweRoundTrip(EncryptionAlgorithm.RsaOaep256, EncryptionContentAlgorithm.A256CbcHs512, "__kjwt_test_oaep256_cbc")
    }
}

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
