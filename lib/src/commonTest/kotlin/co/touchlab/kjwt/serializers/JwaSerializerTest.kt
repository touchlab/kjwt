package co.touchlab.kjwt.serializers

import co.touchlab.kjwt.internal.JwtJson
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.Jwa
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class JwaSerializerTest {

    // ---- Serialize ----

    @Test
    fun serialize_HS256_encodesId() {
        val result = JwtJson.encodeToString(JwaSerializer, SigningAlgorithm.HS256)
        assertEquals("\"HS256\"", result)
    }

    @Test
    fun serialize_RS256_encodesId() {
        val result = JwtJson.encodeToString(JwaSerializer, SigningAlgorithm.RS256)
        assertEquals("\"RS256\"", result)
    }

    @Test
    fun serialize_ES256_encodesId() {
        val result = JwtJson.encodeToString(JwaSerializer, SigningAlgorithm.ES256)
        assertEquals("\"ES256\"", result)
    }

    @Test
    fun serialize_none_encodesId() {
        val result = JwtJson.encodeToString(JwaSerializer, SigningAlgorithm.None)
        assertEquals("\"none\"", result)
    }

    @Test
    fun serialize_RsaOaep_encodesId() {
        val result = JwtJson.encodeToString(JwaSerializer, EncryptionAlgorithm.RsaOaep)
        assertEquals("\"RSA-OAEP\"", result)
    }

    @Test
    fun serialize_RsaOaep256_encodesId() {
        val result = JwtJson.encodeToString(JwaSerializer, EncryptionAlgorithm.RsaOaep256)
        assertEquals("\"RSA-OAEP-256\"", result)
    }

    @Test
    fun serialize_Dir_encodesId() {
        val result = JwtJson.encodeToString(JwaSerializer, EncryptionAlgorithm.Dir)
        assertEquals("\"dir\"", result)
    }

    @Test
    fun serialize_allSigningAlgorithms_useIdAsValue() {
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

    @Test
    fun serialize_allEncryptionAlgorithms_useIdAsValue() {
        val expectedIds = listOf("dir", "RSA-OAEP", "RSA-OAEP-256")
        val actualIds = EncryptionAlgorithm.entries.map { alg ->
            JwtJson.encodeToString(JwaSerializer, alg).removeSurrounding("\"")
        }
        assertEquals(expectedIds, actualIds)
    }

    // ---- Deserialize ----

    @Test
    fun deserialize_HS256_returnsCorrectAlgorithm() {
        val result = JwtJson.decodeFromString(JwaSerializer, "\"HS256\"")
        assertEquals(SigningAlgorithm.HS256, result)
    }

    @Test
    fun deserialize_RS512_returnsCorrectAlgorithm() {
        val result = JwtJson.decodeFromString(JwaSerializer, "\"RS512\"")
        assertEquals(SigningAlgorithm.RS512, result)
    }

    @Test
    fun deserialize_ES384_returnsCorrectAlgorithm() {
        val result = JwtJson.decodeFromString(JwaSerializer, "\"ES384\"")
        assertEquals(SigningAlgorithm.ES384, result)
    }

    @Test
    fun deserialize_none_returnsCorrectAlgorithm() {
        val result = JwtJson.decodeFromString(JwaSerializer, "\"none\"")
        assertEquals(SigningAlgorithm.None, result)
    }

    @Test
    fun deserialize_RsaOaep_returnsCorrectAlgorithm() {
        val result = JwtJson.decodeFromString(JwaSerializer, "\"RSA-OAEP\"")
        assertEquals(EncryptionAlgorithm.RsaOaep, result)
    }

    @Test
    fun deserialize_RsaOaep256_returnsCorrectAlgorithm() {
        val result = JwtJson.decodeFromString(JwaSerializer, "\"RSA-OAEP-256\"")
        assertEquals(EncryptionAlgorithm.RsaOaep256, result)
    }

    @Test
    fun deserialize_Dir_returnsCorrectAlgorithm() {
        val result = JwtJson.decodeFromString(JwaSerializer, "\"dir\"")
        assertEquals(EncryptionAlgorithm.Dir, result)
    }

    @Test
    fun deserialize_unknownId_throwsIllegalArgumentException() {
        assertFailsWith<IllegalArgumentException> {
            JwtJson.decodeFromString(JwaSerializer, "\"UNKNOWN\"")
        }
    }

    @Test
    fun deserialize_emptyString_throwsIllegalArgumentException() {
        assertFailsWith<IllegalArgumentException> {
            JwtJson.decodeFromString(JwaSerializer, "\"\"")
        }
    }

    @Test
    fun deserialize_caseMismatch_throwsIllegalArgumentException() {
        // Algorithm IDs are case-sensitive
        assertFailsWith<IllegalArgumentException> {
            JwtJson.decodeFromString(JwaSerializer, "\"hs256\"")
        }
    }

    // ---- Round-trip ----

    @Test
    fun roundTrip_allSigningAlgorithms_preservesIdentity() {
        for (alg in SigningAlgorithm.entries) {
            val encoded = JwtJson.encodeToString(JwaSerializer, alg)
            val decoded = JwtJson.decodeFromString(JwaSerializer, encoded)
            assertEquals(alg, decoded, "Round-trip failed for ${alg.id}")
        }
    }

    @Test
    fun roundTrip_allEncryptionAlgorithms_preservesIdentity() {
        for (alg in EncryptionAlgorithm.entries) {
            val encoded = JwtJson.encodeToString(JwaSerializer, alg)
            val decoded = JwtJson.decodeFromString(JwaSerializer, encoded)
            assertEquals(alg, decoded, "Round-trip failed for ${alg.id}")
        }
    }

    // ---- fromId delegation ----

    @Test
    fun fromId_delegatesToBothEntryLists() {
        // Signing algorithms should be resolvable via Jwa.fromId
        assertEquals(SigningAlgorithm.PS256, Jwa.fromId("PS256"))
        // Encryption algorithms should be resolvable via Jwa.fromId
        assertEquals(EncryptionAlgorithm.RsaOaep256, Jwa.fromId("RSA-OAEP-256"))
    }
}