package co.touchlab.kjwt

import co.touchlab.kjwt.algorithm.JwsAlgorithm
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.SHA256
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Instant
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonPrimitive

class JwtParserTest {

    @Test
    fun test() = runTest {
        val password = "a-string-secret-at-least-256-bits-long"

        val key = CryptographyProvider.Default
            .get(HMAC)
            .keyDecoder(SHA256)
            .decodeFromByteArray(HMAC.Key.Format.RAW, password.encodeToByteArray())

        val result = Jwt.parser()
            .verifyWith(JwsAlgorithm.HS256, key)
            .build()
            .parseSignedClaims("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyLCJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZX0._-A3B6dTUb8NrJi2SlUH_9jxmaU3plM2sxf-OyXnWiw")

        assertEquals("HS256", result.header.algorithm)
        assertEquals("JWT", result.header.type)

        assertEquals("1234567890", result.payload.subject)
        assertEquals(Instant.fromEpochSeconds(1516239022), result.payload.issuedAt)

        assertEquals("John Doe", result.payload["name"]?.jsonPrimitive?.content)
        assertEquals(true, result.payload["admin"]?.jsonPrimitive?.boolean)
    }
}