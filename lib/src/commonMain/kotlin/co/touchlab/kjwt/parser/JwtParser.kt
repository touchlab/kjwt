package co.touchlab.kjwt.parser

import co.touchlab.kjwt.algorithm.JweContentAlgorithm
import co.touchlab.kjwt.algorithm.JweKeyAlgorithm
import co.touchlab.kjwt.algorithm.JwsAlgorithm
import co.touchlab.kjwt.exception.ExpiredJwtException
import co.touchlab.kjwt.exception.IncorrectClaimException
import co.touchlab.kjwt.exception.MalformedJwtException
import co.touchlab.kjwt.exception.MissingClaimException
import co.touchlab.kjwt.exception.PrematureJwtException
import co.touchlab.kjwt.exception.SignatureException
import co.touchlab.kjwt.exception.UnsupportedJwtException
import co.touchlab.kjwt.ext.expirationOrNull
import co.touchlab.kjwt.ext.notBeforeOrNull
import co.touchlab.kjwt.internal.JwtJson
import co.touchlab.kjwt.internal.decodeBase64Url
import co.touchlab.kjwt.model.JwtHeader
import co.touchlab.kjwt.model.JwtInstance
import co.touchlab.kjwt.model.JwtPayload
import co.touchlab.kjwt.serializers.ClaimsSerializer
import kotlin.time.Clock
import kotlinx.serialization.DeserializationStrategy

/**
 * Thread-safe JWT parser. Obtain via [JwtParserBuilder.build].
 */
class JwtParser internal constructor(private val config: JwtParserBuilder) {
    suspend fun parseSignedClaims(token: String): JwtInstance.Jws<JwtPayload> =
        parseSignedJwt(ClaimsSerializer, token)

    /**
     * Parses and validates a JWS compact token, returning the signed JwtInstance.
     *
     * @throws MalformedJwtException if the token is not a valid 3-part JWT
     * @throws UnsupportedJwtException if `alg=none` and unsecured tokens are not allowed
     * @throws SignatureException if the signature does not verify
     * @throws ExpiredJwtException if the token is past its expiration
     * @throws PrematureJwtException if the token is not yet valid
     * @throws MissingClaimException if a required claim is absent
     * @throws IncorrectClaimException if a required claim has an unexpected value
     */
    suspend fun <T : JwtPayload> parseSignedJwt(
        serializer: DeserializationStrategy<T>,
        token: String
    ): JwtInstance.Jws<T> {
        val parts = token.split('.')
        if (parts.size != 3) throw MalformedJwtException("JWS token must have exactly 3 parts, got ${parts.size}")

        val header = decodeJsonObjectFromBase64Url<JwtHeader.Jws>(parts[0], "header")

        val algorithm: JwsAlgorithm<*, *> = try {
            JwsAlgorithm.fromId(header.algorithm)
        } catch (e: IllegalArgumentException) {
            throw UnsupportedJwtException("Unsupported algorithm: '${header.algorithm}'", e)
        }

        if (algorithm == JwsAlgorithm.None && !config.allowUnsecured) {
            throw UnsupportedJwtException(
                "JWTs with 'alg=none' are rejected by default. Use allowUnsecured(true) to permit them.",
            )
        }

        val claims = decodeJsonObjectFromBase64Url(serializer, parts[1], "payload")

        if (algorithm != JwsAlgorithm.None) {
            val verifier =
                config.jwsKeyVerifier
                    ?.takeIf { it.algorithm == algorithm || it.algorithm == JwsAlgorithm.None && config.allowUnsecured }
                    ?: throw IllegalStateException("No verification key configured. Call verifyWith() or noVerify() on the parser builder.")
            val signingInput = "${parts[0]}.${parts[1]}".encodeToByteArray()
            val signature = parts[2].decodeBase64Url()

            val valid = verifier.verify(signingInput, signature)
            if (!valid) throw SignatureException("JWT signature verification failed")
        }

        validateTimeClaims(claims, header)
        validateRequiredClaims(claims)

        return JwtInstance.Jws(header, claims, parts[2].decodeBase64Url())
    }

    /**
     * Parses and validates a JWE compact token, returning the decrypted claims.
     *
     * @throws MalformedJwtException if the token is not a valid 5-part JWE
     * @throws SignatureException if decryption or authentication tag verification fails
     */
    suspend fun parseEncryptedClaims(token: String): JwtInstance.Jwe<JwtPayload> =
        parseEncryptedJwt(ClaimsSerializer, token)

    suspend fun <T : JwtPayload> parseEncryptedJwt(
        serializer: DeserializationStrategy<T>,
        token: String
    ): JwtInstance.Jwe<T> {
        val parts = token.split('.')
        if (parts.size != 5) throw MalformedJwtException("JWE token must have exactly 5 parts, got ${parts.size}")

        val header = decodeJsonObjectFromBase64Url<JwtHeader.Jwe>(parts[0], "header")

        val keyAlgorithm = try {
            JweKeyAlgorithm.fromId(header.algorithm)
        } catch (e: IllegalArgumentException) {
            throw UnsupportedJwtException("Unsupported JWE key algorithm: '${header.algorithm}'", e)
        }
        val contentAlgorithm = try {
            JweContentAlgorithm.fromId(header.encryption)
        } catch (e: IllegalArgumentException) {
            throw UnsupportedJwtException("Unsupported JWE content algorithm: '${header.encryption}'", e)
        }

        val decryptor = config.jweKeyDecryptor?.takeIf { it.algorithm == keyAlgorithm }
            ?: throw IllegalStateException("No decryption key configured. Call decryptWith() on the parser builder.")

        // AAD is the ASCII bytes of the raw base64url header string (part[0])
        val aad = parts[0].encodeToByteArray()

        val plaintext = try {
            val encryptedKey = parts[1].decodeBase64Url()
            val iv = parts[2].decodeBase64Url()
            val ciphertext = parts[3].decodeBase64Url()
            val tag = parts[4].decodeBase64Url()
            decryptor.decrypt(contentAlgorithm, encryptedKey, iv, ciphertext, tag, aad)
        } catch (e: Exception) {
            throw SignatureException("JWE decryption or authentication tag verification failed", e)
        }

        val claims = decodeJsonObjectFromString(serializer, plaintext.decodeToString(), "payload")

        // For JWE time-claim validation we create a synthetic JwsHeader for the exception type
        val syntheticJwsHeader = JwtHeader.Jws(algorithm = header.algorithm)
        validateTimeClaims(claims, syntheticJwsHeader)
        validateRequiredClaims(claims)

        return JwtInstance.Jwe(header, claims)
    }

    /**
     * Auto-detects JWS (3 parts) or JWE (5 parts) and delegates accordingly.
     */
    suspend fun parseClaims(token: String): JwtInstance<JwtPayload> =
        parse(ClaimsSerializer, token)

    suspend fun <T : JwtPayload> parse(
        deserializer: DeserializationStrategy<T>,
        token: String
    ): JwtInstance<T> {
        val partCount = token.count { it == '.' } + 1
        return when (partCount) {
            3 -> parseSignedJwt(deserializer, token)
            5 -> parseEncryptedJwt(deserializer, token)
            else -> throw MalformedJwtException("Cannot determine JWT type: expected 3 or 5 parts, got $partCount")
        }
    }

    // ---- Private helpers ----

    private inline fun <reified T> decodeJsonObjectFromBase64Url(base64UrlPart: String, name: String): T =
        decodeJsonObjectFromBase64Url(kotlinx.serialization.serializer<T>(), base64UrlPart, name)

    private fun <T> decodeJsonObjectFromBase64Url(
        deserializer: DeserializationStrategy<T>,
        base64UrlPart: String,
        name: String
    ): T {
        val bytes = try {
            base64UrlPart.decodeBase64Url()
        } catch (e: Exception) {
            throw MalformedJwtException("Invalid base64url encoding in JWT $name", e)
        }
        return decodeJsonObjectFromString(deserializer, bytes.decodeToString(), name)
    }

    private inline fun <reified T> decodeJsonObjectFromString(json: String, name: String): T =
        decodeJsonObjectFromString(kotlinx.serialization.serializer<T>(), json, name)

    private fun <T> decodeJsonObjectFromString(
        deserializer: DeserializationStrategy<T>,
        json: String,
        name: String
    ): T = try {
        JwtJson.decodeFromString(deserializer, json)
    } catch (e: Exception) {
        throw MalformedJwtException("JWT $name is not valid JSON", e)
    }

    private fun validateTimeClaims(claims: JwtPayload, header: JwtHeader) {
        val now = Clock.System.now()
        val skew = config.clockSkewSeconds

        claims.expirationOrNull?.let { exp ->
            if (now.epochSeconds > exp.epochSeconds + skew) {
                throw ExpiredJwtException(header, claims, "JWT expired at $exp (now=$now)")
            }
        }

        claims.notBeforeOrNull?.let { nbf ->
            if (now.epochSeconds < nbf.epochSeconds - skew) {
                throw PrematureJwtException(header, claims, "JWT not valid before $nbf (now=$now)")
            }
        }
    }

    private fun validateRequiredClaims(claims: JwtPayload) {
        config.validators.forEach { validate -> validate(claims) }
    }
}
