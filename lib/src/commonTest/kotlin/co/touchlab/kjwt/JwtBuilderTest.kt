package co.touchlab.kjwt

import co.touchlab.kjwt.algorithm.JwsAlgorithm
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.SHA256
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Instant
import kotlinx.coroutines.test.runTest

class JwtBuilderTest {

    @Test
    fun test() = runTest {
        val password = "a-string-secret-at-least-256-bits-long"

        val key = CryptographyProvider.Default
            .get(HMAC)
            .keyDecoder(SHA256)
            .decodeFromByteArray(HMAC.Key.Format.RAW, password.encodeToByteArray())

        val result = Jwt.builder()
            .subject("1234567890")
            .claim("name", "John Doe")
            .claim("admin", true)
            .issuedAt(Instant.fromEpochSeconds(1516239022))
            .signWith(JwsAlgorithm.HS256, key)

        assertEquals(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyLCJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZX0._-A3B6dTUb8NrJi2SlUH_9jxmaU3plM2sxf-OyXnWiw",
            result
        )
    }
}