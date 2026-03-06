package co.touchlab.kjwt.exception

import co.touchlab.kjwt.model.Claims
import co.touchlab.kjwt.model.JwsHeader

open class JwtException(message: String, cause: Throwable? = null) : Exception(message, cause)

class MalformedJwtException(message: String, cause: Throwable? = null) : JwtException(message, cause)

class SignatureException(message: String, cause: Throwable? = null) : JwtException(message, cause)

class UnsupportedJwtException(message: String, cause: Throwable? = null) : JwtException(message, cause)

class ExpiredJwtException(
    val header: JwsHeader,
    val claims: Claims,
    message: String,
) : JwtException(message)

class PrematureJwtException(
    val header: JwsHeader,
    val claims: Claims,
    message: String,
) : JwtException(message)

class MissingClaimException(
    val claimName: String,
) : JwtException("Missing required claim: '$claimName'")

class IncorrectClaimException(
    val claimName: String,
    val expected: Any?,
    val actual: Any?,
) : JwtException("Claim '$claimName' expected '$expected' but was '$actual'")