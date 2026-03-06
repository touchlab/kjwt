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
import co.touchlab.kjwt.internal.JwtJson
import co.touchlab.kjwt.internal.decodeBase64Url
import co.touchlab.kjwt.internal.jweDecrypt
import co.touchlab.kjwt.internal.jwsVerify
import co.touchlab.kjwt.model.Claims
import co.touchlab.kjwt.model.Jwe
import co.touchlab.kjwt.model.JweHeader
import co.touchlab.kjwt.model.Jws
import co.touchlab.kjwt.model.JwsHeader
import kotlin.time.Clock
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Thread-safe JWT parser. Obtain via [JwtParserBuilder.build].
 */
class JwtParser internal constructor(private val config: JwtParserBuilder) {

    /**
     * Parses and validates a JWS compact token, returning the signed claims.
     *
     * @throws MalformedJwtException if the token is not a valid 3-part JWT
     * @throws UnsupportedJwtException if `alg=none` and unsecured tokens are not allowed
     * @throws SignatureException if the signature does not verify
     * @throws ExpiredJwtException if the token is past its expiration
     * @throws PrematureJwtException if the token is not yet valid
     * @throws MissingClaimException if a required claim is absent
     * @throws IncorrectClaimException if a required claim has an unexpected value
     */
    suspend fun parseSignedClaims(token: String): Jws<Claims> {
        val parts = token.split('.')
        if (parts.size != 3) throw MalformedJwtException("JWS token must have exactly 3 parts, got ${parts.size}")

        val headerJson = decodeJsonObjectFromBase64Url(parts[0], "header")
        val header = JwsHeader.fromJsonObject(headerJson)

        val algorithm: JwsAlgorithm<*> = try {
            JwsAlgorithm.fromId(header.algorithm)
        } catch (e: IllegalArgumentException) {
            throw UnsupportedJwtException("Unsupported algorithm: '${header.algorithm}'", e)
        }

        if (algorithm == JwsAlgorithm.None && !config.allowUnsecured) {
            throw UnsupportedJwtException(
                "JWTs with 'alg=none' are rejected by default. Use allowUnsecured(true) to permit them.",
            )
        }

        val payloadJson = decodeJsonObjectFromBase64Url(parts[1], "payload")
        val claims = Claims(payloadJson)

        if (algorithm != JwsAlgorithm.None) {
            val verifyKey = config.definedKeyForAlgorithm(algorithm)
                ?: throw IllegalStateException("No verification key configured. Call verifyWith() on the parser builder.")
            val signingInput = "${parts[0]}.${parts[1]}".encodeToByteArray()
            val signature = parts[2].decodeBase64Url()

            val valid = jwsVerify(algorithm, verifyKey, signingInput, signature)
            if (!valid) throw SignatureException("JWT signature verification failed")
        }

        validateTimeClaims(claims, header)
        validateRequiredClaims(claims)

        return Jws(header, claims, parts[2].decodeBase64Url())
    }

    /**
     * Parses and validates a JWE compact token, returning the decrypted claims.
     *
     * @throws MalformedJwtException if the token is not a valid 5-part JWE
     * @throws SignatureException if decryption or authentication tag verification fails
     */
    suspend fun parseEncryptedClaims(token: String): Jwe<Claims> {
        val parts = token.split('.')
        if (parts.size != 5) throw MalformedJwtException("JWE token must have exactly 5 parts, got ${parts.size}")

        val headerJson = decodeJsonObjectFromBase64Url(parts[0], "header")
        val header = JweHeader.fromJsonObject(headerJson)

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

        val decryptKey = config.definedKeyForAlgorithm(keyAlgorithm)
            ?: throw IllegalStateException("No decryption key configured. Call decryptWith() on the parser builder.")

        // AAD is the ASCII bytes of the raw base64url header string (part[0])
        val aad = parts[0].encodeToByteArray()

        val plaintext = try {
            val encryptedKey = parts[1].decodeBase64Url()
            val iv = parts[2].decodeBase64Url()
            val ciphertext = parts[3].decodeBase64Url()
            val tag = parts[4].decodeBase64Url()
            jweDecrypt(decryptKey, keyAlgorithm, contentAlgorithm, encryptedKey, iv, ciphertext, tag, aad)
        } catch (e: Exception) {
            throw SignatureException("JWE decryption or authentication tag verification failed", e)
        }

        val payloadJson = decodeJsonObjectFromString(plaintext.decodeToString(), "payload")
        val claims = Claims(payloadJson)

        // For JWE time-claim validation we create a synthetic JwsHeader for the exception type
        val syntheticJwsHeader = JwsHeader(algorithm = header.algorithm)
        validateTimeClaims(claims, syntheticJwsHeader)
        validateRequiredClaims(claims)

        return Jwe(header, claims)
    }

    /**
     * Auto-detects JWS (3 parts) or JWE (5 parts) and delegates accordingly.
     */
    suspend fun parse(token: String): Any {
        val partCount = token.count { it == '.' } + 1
        return when (partCount) {
            3 -> parseSignedClaims(token)
            5 -> parseEncryptedClaims(token)
            else -> throw MalformedJwtException("Cannot determine JWT type: expected 3 or 5 parts, got $partCount")
        }
    }

    // ---- Private helpers ----

    private fun decodeJsonObjectFromBase64Url(base64UrlPart: String, name: String): JsonObject {
        val bytes = try {
            base64UrlPart.decodeBase64Url()
        } catch (e: Exception) {
            throw MalformedJwtException("Invalid base64url encoding in JWT $name", e)
        }
        return decodeJsonObjectFromString(bytes.decodeToString(), name)
    }

    private fun decodeJsonObjectFromString(json: String, name: String): JsonObject =
        try {
            JwtJson.decodeFromString(JsonObject.serializer(), json)
        } catch (e: Exception) {
            throw MalformedJwtException("JWT $name is not valid JSON", e)
        }

    private fun validateTimeClaims(claims: Claims, header: JwsHeader) {
        val now = Clock.System.now()
        val skew = config.clockSkewSeconds

        claims.expiration?.let { exp ->
            if (now.epochSeconds > exp.epochSeconds + skew) {
                throw ExpiredJwtException(header, claims, "JWT expired at $exp (now=$now)")
            }
        }

        claims.notBefore?.let { nbf ->
            if (now.epochSeconds < nbf.epochSeconds - skew) {
                throw PrematureJwtException(header, claims, "JWT not valid before $nbf (now=$now)")
            }
        }
    }

    private fun validateRequiredClaims(claims: Claims) {
        for ((name, expected) in config.requiredClaims) {
            when (name) {
                Claims.AUD -> {
                    val aud = claims.audience ?: throw MissingClaimException(name)
                    if (expected.toString() !in aud) {
                        throw IncorrectClaimException(name, expected, aud)
                    }
                }

                else -> {
                    val actual: String? = when (name) {
                        Claims.ISS -> claims.issuer
                        Claims.SUB -> claims.subject
                        Claims.JTI -> claims.jwtId
                        else -> {
                            val element = claims[name] ?: throw MissingClaimException(name)
                            (element as? JsonPrimitive)?.content ?: element.toString()
                        }
                    }
                    if (actual == null) throw MissingClaimException(name)
                    if (actual != expected.toString()) throw IncorrectClaimException(name, expected, actual)
                }
            }
        }
    }
}
