package co.touchlab.kjwt.exception

import co.touchlab.kjwt.model.JwtHeader
import co.touchlab.kjwt.model.JwtPayload

open class JwtException(message: String, cause: Throwable? = null) : Exception(message, cause)

class MalformedJwtException(message: String, cause: Throwable? = null) : JwtException(message, cause)

class MalformedJwkException(message: String, cause: Throwable? = null) : JwtException(message, cause)

class SignatureException(message: String, cause: Throwable? = null) : JwtException(message, cause)

class UnsupportedJwtException(message: String, cause: Throwable? = null) : JwtException(message, cause)

class ExpiredJwtException(
    val header: JwtHeader,
    val claims: JwtPayload,
    message: String,
) : JwtException(message)

class PrematureJwtException(
    val header: JwtHeader,
    val claims: JwtPayload,
    message: String,
) : JwtException(message)

class MissingClaimException(
    val claimName: String,
) : JwtException("Missing required claim: '$claimName'")

class MissingHeaderException(
    val headerName: String,
) : JwtException("Missing required header: '$headerName'")

class IncorrectClaimException(
    val claimName: String,
    val expected: Any?,
    val actual: Any?,
) : JwtException("Claim '$claimName' expected '$expected' but was '$actual'")
