@file:OptIn(dev.whyoleg.cryptography.DelicateCryptographyApi::class)

package co.touchlab.kjwt

import co.touchlab.kjwt.algorithm.JweContentAlgorithm
import co.touchlab.kjwt.algorithm.JweKeyAlgorithm
import co.touchlab.kjwt.algorithm.JwsAlgorithm
import co.touchlab.kjwt.exception.MissingClaimException
import co.touchlab.kjwt.ext.expirationOrNull
import co.touchlab.kjwt.ext.parse
import co.touchlab.kjwt.ext.parseEncryptedJwt
import co.touchlab.kjwt.ext.parseSignedJwt
import co.touchlab.kjwt.ext.subjectOrNull
import co.touchlab.kjwt.internal.JwtJson
import co.touchlab.kjwt.model.JwtInstance
import co.touchlab.kjwt.model.JwtPayload
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

// ---- Custom payload type used in all tests in this file ----

@Serializable
data class UserClaims(
    @SerialName(JwtPayload.SUB) val subject: String? = null,
    @SerialName("role") val role: String? = null,
    @SerialName("level") val level: Int? = null,
    @SerialName("exp") val expSeconds: Long? = null,
    private val jsonData: JsonObject = JsonObject(emptyMap()),
) : JwtPayload {
    override fun hasClaim(name: String): Boolean =
        jsonData.containsKey(name)

    override fun <T> getClaim(serializer: DeserializationStrategy<T>, name: String): T =
        getClaimOrNull(serializer, name) ?: throw MissingClaimException(name)

    override fun <T> getClaimOrNull(serializer: DeserializationStrategy<T>, name: String): T? {
        val element = jsonData[name] ?: return null
        return JwtJson.decodeFromJsonElement(serializer, element)
    }
}

class CustomPayloadTest {

    // ---- JWS ----

    @Test
    fun parseSignedJwt_customType_directPropertyAccess() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .subject("user-42")
            .claim("role", "admin")
            .claim("level", 7)
            .signWith(JwsAlgorithm.HS256, key)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.HS256, key)
            .build()
            .parseSignedJwt(UserClaims.serializer(), token)

        assertEquals("user-42", jws.payload.subject)
        assertEquals("admin", jws.payload.role)
        assertEquals(7, jws.payload.level)
    }

    @Test
    fun parseSignedJwt_customType_reifiedExtension() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .subject("user-ext")
            .claim("role", "viewer")
            .signWith(JwsAlgorithm.HS256, key)

        val jws: JwtInstance.Jws<UserClaims> = Jwt.parser()
            .verifyWith(JwsAlgorithm.HS256, key)
            .build()
            .parseSignedJwt<UserClaims>(token)

        assertEquals("user-ext", jws.payload.subject)
        assertEquals("viewer", jws.payload.role)
    }

    @Test
    fun parseSignedJwt_customType_missingOptionalFieldIsNull() = runTest {
        val key = hs256Key()
        // Token has no "role" or "level" claims
        val token = Jwt.builder()
            .subject("minimal-user")
            .signWith(JwsAlgorithm.HS256, key)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.HS256, key)
            .build()
            .parseSignedJwt<UserClaims>(token)

        assertEquals("minimal-user", jws.payload.subject)
        assertNull(jws.payload.role)
        assertNull(jws.payload.level)
    }

    @Test
    fun parseSignedJwt_customType_getClaim_worksForStandardClaims() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .subject("claim-user")
            .signWith(JwsAlgorithm.HS256, key)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.HS256, key)
            .build()
            .parseSignedJwt<UserClaims>(token)

        // subjectOrNull delegates to getClaimOrNull via the JwtPayload interface
        assertEquals("claim-user", jws.payload.subjectOrNull)
    }

    @Test
    fun parseSignedJwt_customType_expirationValidation_notExpired() = runTest {
        val key = hs256Key()
        val expiry = Clock.System.now() + 1.hours
        val token = Jwt.builder()
            .subject("timed-user")
            .expiration(expiry)
            .signWith(JwsAlgorithm.HS256, key)

        val jws = Jwt.parser()
            .verifyWith(JwsAlgorithm.HS256, key)
            .build()
            .parseSignedJwt<UserClaims>(token)

        // expirationOrNull delegates to getClaim on the custom type
        assertNotNull(jws.payload.expirationOrNull)
        assertEquals(expiry.epochSeconds, jws.payload.expSeconds)
    }

    @Test
    fun parse_autoDetect_jws_customType() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .subject("auto-user")
            .claim("role", "superadmin")
            .signWith(JwsAlgorithm.HS256, key)

        val result: JwtInstance<UserClaims> = Jwt.parser()
            .verifyWith(JwsAlgorithm.HS256, key)
            .build()
            .parse<UserClaims>(token)

        assertIs<JwtInstance.Jws<UserClaims>>(result)
        assertEquals("auto-user", result.payload.subject)
        assertEquals("superadmin", result.payload.role)
    }

    // ---- JWE ----

    @Test
    fun parseEncryptedJwt_customType_directPropertyAccess() = runTest {
        val cek = aesSimpleKey(128)
        val token = Jwt.builder()
            .subject("enc-user")
            .claim("role", "operator")
            .claim("level", 3)
            .encryptWith(cek, JweKeyAlgorithm.Dir, JweContentAlgorithm.A128GCM)

        val jwe = Jwt.parser()
            .decryptWith(JweKeyAlgorithm.Dir, cek)
            .build()
            .parseEncryptedJwt(UserClaims.serializer(), token)

        assertEquals("enc-user", jwe.payload.subject)
        assertEquals("operator", jwe.payload.role)
        assertEquals(3, jwe.payload.level)
    }

    @Test
    fun parseEncryptedJwt_customType_reifiedExtension() = runTest {
        val cek = aesSimpleKey(256)
        val token = Jwt.builder()
            .subject("enc-ext-user")
            .claim("role", "reader")
            .encryptWith(cek, JweKeyAlgorithm.Dir, JweContentAlgorithm.A256GCM)

        val jwe: JwtInstance.Jwe<UserClaims> = Jwt.parser()
            .decryptWith(JweKeyAlgorithm.Dir, cek)
            .build()
            .parseEncryptedJwt<UserClaims>(token)

        assertEquals("enc-ext-user", jwe.payload.subject)
        assertEquals("reader", jwe.payload.role)
    }

    @Test
    fun parse_autoDetect_jwe_customType() = runTest {
        val cek = aesSimpleKey(192)
        val token = Jwt.builder()
            .subject("enc-auto-user")
            .claim("role", "admin")
            .encryptWith(cek, JweKeyAlgorithm.Dir, JweContentAlgorithm.A192GCM)

        val result: JwtInstance<UserClaims> = Jwt.parser()
            .decryptWith(JweKeyAlgorithm.Dir, cek)
            .build()
            .parse<UserClaims>(token)

        assertIs<JwtInstance.Jwe<UserClaims>>(result)
        assertEquals("enc-auto-user", result.payload.subject)
        assertEquals("admin", result.payload.role)
    }

    @Test
    fun parseEncryptedJwt_customType_expirationValidation_notExpired() = runTest {
        val cek = aesSimpleKey(128)
        val expiry = Clock.System.now() + 1.hours
        val token = Jwt.builder()
            .subject("enc-timed-user")
            .expiration(expiry)
            .encryptWith(cek, JweKeyAlgorithm.Dir, JweContentAlgorithm.A128GCM)

        val jwe = Jwt.parser()
            .decryptWith(JweKeyAlgorithm.Dir, cek)
            .build()
            .parseEncryptedJwt<UserClaims>(token)

        assertNotNull(jwe.payload.expirationOrNull)
        assertEquals(expiry.epochSeconds, jwe.payload.expSeconds)
    }
}
