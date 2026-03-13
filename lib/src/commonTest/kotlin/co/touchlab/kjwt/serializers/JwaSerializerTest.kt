package co.touchlab.kjwt.serializers

import co.touchlab.kjwt.internal.JwtJson
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.Jwa
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import io.kotest.core.spec.style.FunSpec
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class JwaSerializerTest : FunSpec({

    context("serialize") {

        test("serialize HS256 encodes id") {
            val result = JwtJson.encodeToString(JwaSerializer, SigningAlgorithm.HS256)
            assertEquals("\"HS256\"", result)
        }

        test("serialize RS256 encodes id") {
            val result = JwtJson.encodeToString(JwaSerializer, SigningAlgorithm.RS256)
            assertEquals("\"RS256\"", result)
        }

        test("serialize ES256 encodes id") {
            val result = JwtJson.encodeToString(JwaSerializer, SigningAlgorithm.ES256)
            assertEquals("\"ES256\"", result)
        }

        test("serialize none encodes id") {
            val result = JwtJson.encodeToString(JwaSerializer, SigningAlgorithm.None)
            assertEquals("\"none\"", result)
        }

        test("serialize RsaOaep encodes id") {
            val result = JwtJson.encodeToString(JwaSerializer, EncryptionAlgorithm.RsaOaep)
            assertEquals("\"RSA-OAEP\"", result)
        }

        test("serialize RsaOaep256 encodes id") {
            val result = JwtJson.encodeToString(JwaSerializer, EncryptionAlgorithm.RsaOaep256)
            assertEquals("\"RSA-OAEP-256\"", result)
        }

        test("serialize Dir encodes id") {
            val result = JwtJson.encodeToString(JwaSerializer, EncryptionAlgorithm.Dir)
            assertEquals("\"dir\"", result)
        }

        test("serialize all signing algorithms use id as value") {
            val expectedIds = listOf(
                "HS256", "HS384", "HS512",
                "RS256", "RS384", "RS512",
                "PS256", "PS384", "PS512",
                "ES256", "ES384", "ES512",
                "none",
            )
            val actualIds = SigningAlgorithm.entries.map { alg ->
                JwtJson.encodeToString(JwaSerializer, alg).removeSurrounding("\"")
            }
            assertEquals(expectedIds, actualIds)
        }

        test("serialize all encryption algorithms use id as value") {
            val expectedIds = listOf("dir", "RSA-OAEP", "RSA-OAEP-256")
            val actualIds = EncryptionAlgorithm.entries.map { alg ->
                JwtJson.encodeToString(JwaSerializer, alg).removeSurrounding("\"")
            }
            assertEquals(expectedIds, actualIds)
        }
    }

    context("deserialize") {

        test("deserialize HS256 returns correct algorithm") {
            val result = JwtJson.decodeFromString(JwaSerializer, "\"HS256\"")
            assertEquals(SigningAlgorithm.HS256, result)
        }

        test("deserialize RS512 returns correct algorithm") {
            val result = JwtJson.decodeFromString(JwaSerializer, "\"RS512\"")
            assertEquals(SigningAlgorithm.RS512, result)
        }

        test("deserialize ES384 returns correct algorithm") {
            val result = JwtJson.decodeFromString(JwaSerializer, "\"ES384\"")
            assertEquals(SigningAlgorithm.ES384, result)
        }

        test("deserialize none returns correct algorithm") {
            val result = JwtJson.decodeFromString(JwaSerializer, "\"none\"")
            assertEquals(SigningAlgorithm.None, result)
        }

        test("deserialize RsaOaep returns correct algorithm") {
            val result = JwtJson.decodeFromString(JwaSerializer, "\"RSA-OAEP\"")
            assertEquals(EncryptionAlgorithm.RsaOaep, result)
        }

        test("deserialize RsaOaep256 returns correct algorithm") {
            val result = JwtJson.decodeFromString(JwaSerializer, "\"RSA-OAEP-256\"")
            assertEquals(EncryptionAlgorithm.RsaOaep256, result)
        }

        test("deserialize Dir returns correct algorithm") {
            val result = JwtJson.decodeFromString(JwaSerializer, "\"dir\"")
            assertEquals(EncryptionAlgorithm.Dir, result)
        }

        test("deserialize unknown id throws IllegalArgumentException") {
            assertFailsWith<IllegalArgumentException> {
                JwtJson.decodeFromString(JwaSerializer, "\"UNKNOWN\"")
            }
        }

        test("deserialize empty string throws IllegalArgumentException") {
            assertFailsWith<IllegalArgumentException> {
                JwtJson.decodeFromString(JwaSerializer, "\"\"")
            }
        }

        test("deserialize case mismatch throws IllegalArgumentException") {
            // Algorithm IDs are case-sensitive
            assertFailsWith<IllegalArgumentException> {
                JwtJson.decodeFromString(JwaSerializer, "\"hs256\"")
            }
        }
    }

    context("round-trip") {

        test("round trip all signing algorithms preserves identity") {
            for (alg in SigningAlgorithm.entries) {
                val encoded = JwtJson.encodeToString(JwaSerializer, alg)
                val decoded = JwtJson.decodeFromString(JwaSerializer, encoded)
                assertEquals(alg, decoded, "Round-trip failed for ${alg.id}")
            }
        }

        test("round trip all encryption algorithms preserves identity") {
            for (alg in EncryptionAlgorithm.entries) {
                val encoded = JwtJson.encodeToString(JwaSerializer, alg)
                val decoded = JwtJson.decodeFromString(JwaSerializer, encoded)
                assertEquals(alg, decoded, "Round-trip failed for ${alg.id}")
            }
        }
    }

    context("fromId delegation") {

        test("fromId delegates to both entry lists") {
            // Signing algorithms should be resolvable via Jwa.fromId
            assertEquals(SigningAlgorithm.PS256, Jwa.fromId("PS256"))
            // Encryption algorithms should be resolvable via Jwa.fromId
            assertEquals(EncryptionAlgorithm.RsaOaep256, Jwa.fromId("RSA-OAEP-256"))
        }
    }
})
