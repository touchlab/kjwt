package co.touchlab.kjwt.parser

import co.touchlab.kjwt.exception.ExpiredJwtException
import co.touchlab.kjwt.exception.IncorrectClaimException
import co.touchlab.kjwt.exception.MalformedJwtException
import co.touchlab.kjwt.exception.MissingClaimException
import co.touchlab.kjwt.exception.PrematureJwtException
import co.touchlab.kjwt.exception.SignatureException
import co.touchlab.kjwt.exception.UnsupportedJwtException
import co.touchlab.kjwt.ext.encryption
import co.touchlab.kjwt.ext.expirationOrNull
import co.touchlab.kjwt.ext.keyIdOrNull
import co.touchlab.kjwt.ext.notBeforeOrNull
import co.touchlab.kjwt.internal.decodeBase64Url
import co.touchlab.kjwt.internal.encodeBase64Url
import co.touchlab.kjwt.model.JwtHeader
import co.touchlab.kjwt.model.JwtInstance
import co.touchlab.kjwt.model.JwtPayload
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.EncryptionContentAlgorithm
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import co.touchlab.kjwt.processor.JweDecryptor
import co.touchlab.kjwt.processor.JwsVerifier
import kotlin.time.Clock

/**
 * Thread-safe JWT parser that parses, verifies, and validates JWS and JWE compact tokens.
 *
 * Obtain an instance via [JwtParserBuilder.build] after configuring verification keys, decryption
 * keys, and claim validators on the builder. Once built, a [JwtParser] instance is immutable and
 * safe for concurrent use.
 *
 * The parser enforces the following lifecycle for each token:
 * 1. Structural validation — correct number of parts (3 for JWS, 5 for JWE per RFC 7515/7516).
 * 2. Algorithm resolution — the `alg` (and `enc`) header values are mapped to known algorithms.
 * 3. Signature/decryption — the token is cryptographically verified or decrypted.
 * 4. Time-claim validation — `exp` and `nbf` claims are checked against the current clock.
 * 5. Custom claim validation — any validators registered on the builder are applied.
 *
 * @see JwtParserBuilder
 * @see co.touchlab.kjwt.Jwt.parser
 */
public class JwtParser internal constructor(
    private val config: JwtParserBuilder,
) {
    /**
     * Parses and validates a JWS compact token, returning the signed [JwtInstance.Jws].
     *
     * Tokens with `alg=none` (unsecured) are rejected unless [JwtParserBuilder.allowUnsecured]
     * was set to `true` on the builder (RFC 7515).
     *
     * @param token the JWS compact serialization to parse (must be exactly 3 dot-separated parts)
     * @return the parsed and verified [JwtInstance.Jws]
     * @throws MalformedJwtException if the token is not a valid 3-part JWT
     * @throws UnsupportedJwtException if the algorithm is unrecognised, or if `alg=none` and unsecured tokens are not
     *  allowed
     * @throws SignatureException if the signature does not verify
     * @throws ExpiredJwtException if the token is past its expiration
     * @throws PrematureJwtException if the token is not yet valid
     * @throws MissingClaimException if a required claim is absent
     * @throws IncorrectClaimException if a required claim has an unexpected value
     * @see JwtParserBuilder.allowUnsecured
     */
    public suspend fun parseSigned(token: String): JwtInstance.Jws {
        val parts = token.split('.')
        if (parts.size != 3) throw MalformedJwtException("JWS token must have exactly 3 parts, got ${parts.size}")

        val header = JwtHeader(parts[0], config.jsonInstance)

        val algorithm: SigningAlgorithm =
            try {
                SigningAlgorithm.fromId(header.algorithm)
            } catch (e: IllegalArgumentException) {
                throw UnsupportedJwtException("Unsupported algorithm: '${header.algorithm}'", e)
            }

        if (algorithm == SigningAlgorithm.None && !config.allowUnsecured) {
            throw UnsupportedJwtException(
                "JWTs with 'alg=none' are rejected by default. Use allowUnsecured(true) to permit them.",
            )
        }

        val claims = JwtPayload(parts[1], config.jsonInstance)
        val signature = parts[2]

        if (algorithm != SigningAlgorithm.None && !config.skipVerification) {
            val integrityProcessor =
                checkNotNull(
                    config.processorRegistry.findBestJwsProcessor(algorithm, header.keyIdOrNull),
                ) { "No verification key configured. Call verifyWith() or noVerify() on the parser builder." }

            val signingInput = "${parts[0]}.${parts[1]}".encodeToByteArray()
            val signature = signature.decodeBase64Url()

            val verifier = integrityProcessor as? JwsVerifier
                ?: error("Registered processor for ${algorithm.id} does not support verification.")
            val valid = runCatching { verifier.verify(signingInput, signature) }
            if (!valid.getOrDefault(false)) throw SignatureException("JWT signature verification failed")
        }

        validateTimeClaims(claims, header)
        validateJwtClaimsAndHeader(claims, header)

        return JwtInstance.Jws(header, claims, signature)
    }

    /**
     * Parses and validates a JWE compact token, returning the decrypted [JwtInstance.Jwe].
     *
     * The token is decrypted using the key registered via [JwtParserBuilder.decryptWith], and the
     * decrypted payload is then subjected to time-claim and custom-claim validation (RFC 7516).
     *
     * @param token the JWE compact serialization to parse (must be exactly 5 dot-separated parts)
     * @return the parsed and decrypted [JwtInstance.Jwe]
     * @throws MalformedJwtException if the token is not a valid 5-part JWE
     * @throws UnsupportedJwtException if the key algorithm or content algorithm is unrecognised
     * @throws SignatureException if decryption or authentication tag verification fails
     * @throws ExpiredJwtException if the token is past its expiration
     * @throws PrematureJwtException if the token is not yet valid
     * @throws MissingClaimException if a required claim is absent
     * @throws IncorrectClaimException if a required claim has an unexpected value
     * @see JwtParserBuilder.decryptWith
     */
    public suspend fun parseEncrypted(token: String): JwtInstance.Jwe {
        val parts = token.split('.')
        if (parts.size != 5) throw MalformedJwtException("JWE token must have exactly 5 parts, got ${parts.size}")

        val header = JwtHeader(parts[0], config.jsonInstance)

        val keyAlgorithm =
            try {
                EncryptionAlgorithm.fromId(header.algorithm)
            } catch (e: IllegalArgumentException) {
                throw UnsupportedJwtException("Unsupported JWE key algorithm: '${header.algorithm}'", e)
            }
        val contentAlgorithm =
            try {
                EncryptionContentAlgorithm.fromId(header.encryption)
            } catch (e: IllegalArgumentException) {
                throw UnsupportedJwtException("Unsupported JWE content algorithm: '${header.encryption}'", e)
            }

        val decryptor =
            requireNotNull(config.processorRegistry.findBestJweProcessor(keyAlgorithm, header.keyIdOrNull)) {
                "No decryption key configured. Call decryptWith() on the parser builder."
            }

        // AAD is the ASCII bytes of the raw base64url header string (part[0])
        val aad = parts[0].encodeToByteArray()
        val encryptedKey = parts[1]
        val iv = parts[2]
        val ciphertext = parts[3]
        val tag = parts[4]

        val plaintext =
            try {
                val jweDecryptor = decryptor as? JweDecryptor
                    ?: error("Registered processor for ${keyAlgorithm.id} does not support decryption.")
                jweDecryptor.decrypt(
                    aad = aad,
                    encryptedKey = encryptedKey.decodeBase64Url(),
                    iv = iv.decodeBase64Url(),
                    data = ciphertext.decodeBase64Url(),
                    tag = tag.decodeBase64Url(),
                    contentAlgorithm = contentAlgorithm,
                )
            } catch (e: Throwable) {
                throw SignatureException("JWE decryption or authentication tag verification failed", e)
            }

        val claims = JwtPayload(plaintext.encodeBase64Url(), config.jsonInstance)

        validateTimeClaims(claims, header)
        validateJwtClaimsAndHeader(claims, header)

        return JwtInstance.Jwe(
            header = header,
            payload = claims,
            encryptedKey = encryptedKey,
            iv = iv,
            cipherText = ciphertext,
            tag = tag,
        )
    }

    /**
     * Auto-detects the token type and delegates to [parseSigned] (3 parts) or [parseEncrypted] (5 parts).
     *
     * @param token the compact JWT serialization to parse
     * @return the parsed [JwtInstance], either a [JwtInstance.Jws] or [JwtInstance.Jwe]
     * @throws MalformedJwtException if the token does not have 3 or 5 dot-separated parts
     * @throws UnsupportedJwtException if the algorithm is unrecognised, or if `alg=none` and unsecured tokens are not
     *  allowed
     * @throws SignatureException if the signature does not verify or decryption fails
     * @throws ExpiredJwtException if the token is past its expiration
     * @throws PrematureJwtException if the token is not yet valid
     * @throws MissingClaimException if a required claim is absent
     * @throws IncorrectClaimException if a required claim has an unexpected value
     * @see parseSigned
     * @see parseEncrypted
     */
    public suspend fun parse(token: String): JwtInstance {
        val partCount = token.count { it == '.' } + 1
        return when (partCount) {
            3 -> parseSigned(token)
            5 -> parseEncrypted(token)
            else -> throw MalformedJwtException("Cannot determine JWT type: expected 3 or 5 parts, got $partCount")
        }
    }

    // ---- Private helpers ----
    private fun validateTimeClaims(
        claims: JwtPayload,
        header: JwtHeader,
    ) {
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

    private fun validateJwtClaimsAndHeader(
        claims: JwtPayload,
        header: JwtHeader,
    ) {
        config.validators.forEach { validate -> validate(claims, header) }
    }
}
