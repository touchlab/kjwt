package co.touchlab.kjwt.exception

import co.touchlab.kjwt.model.JwtHeader
import co.touchlab.kjwt.model.JwtPayload

/** Base class for all exceptions thrown by the KJWT library. */
public open class JwtException(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause)

/**
 * Thrown when a JWT string is structurally invalid, such as having the wrong number of parts, containing invalid
 * Base64URL encoding, or being unparseable as JSON.
 */
public class MalformedJwtException(
    message: String,
    cause: Throwable? = null,
) : JwtException(message, cause)

/**
 * Thrown when a JWK JSON object is structurally invalid or is missing one or more required fields needed to
 * reconstruct the key.
 */
public class MalformedJwkException(
    message: String,
    cause: Throwable? = null,
) : JwtException(message, cause)

/**
 * Thrown when signature verification of a JWS token fails or when decryption of a JWE token fails, indicating the
 * token may have been tampered with or was encrypted with a different key.
 */
public class SignatureException(
    message: String,
    cause: Throwable? = null,
) : JwtException(message, cause)

/** Thrown when a token uses an algorithm, key type, or feature that is not supported by this library. */
public class UnsupportedJwtException(
    message: String,
    cause: Throwable? = null,
) : JwtException(message, cause)

/** Thrown when a JWT's `exp` (expiration time) claim indicates the token has already expired. */
public class ExpiredJwtException(
    /** The header of the expired token. */
    public val header: JwtHeader,
    /** The claims of the expired token whose `exp` value has passed. */
    public val claims: JwtPayload,
    message: String,
) : JwtException(message)

/** Thrown when a JWT's `nbf` (not-before) claim indicates the token is not yet valid. */
public class PrematureJwtException(
    /** The header of the premature token. */
    public val header: JwtHeader,
    /** The claims of the premature token whose `nbf` value has not yet been reached. */
    public val claims: JwtPayload,
    message: String,
) : JwtException(message)

/** Thrown when a required claim is absent from the token's payload. */
public class MissingClaimException(
    /** The name of the required claim that was absent from the token. */
    public val claimName: String,
) : JwtException("Missing required claim: '$claimName'")

/** Thrown when a required header parameter is absent from the token's header. */
public class MissingHeaderException(
    /** The name of the required header parameter that was absent from the token. */
    public val headerName: String,
) : JwtException("Missing required header: '$headerName'")

/** Thrown when a claim is present in the token but its value does not match the expected value. */
public class IncorrectClaimException(
    /** The name of the claim whose value did not match. */
    public val claimName: String,
    /** The expected value that the claim should have had. */
    public val expected: Any?,
    /** The actual value found in the token for this claim. */
    public val actual: Any?,
) : JwtException("Claim '$claimName' expected '$expected' but was '$actual'")
