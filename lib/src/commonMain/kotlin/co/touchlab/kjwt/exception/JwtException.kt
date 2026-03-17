package co.touchlab.kjwt.exception

import co.touchlab.kjwt.model.JwtHeader
import co.touchlab.kjwt.model.JwtPayload

public open class JwtException(message: String, cause: Throwable? = null) : Exception(message, cause)

public class MalformedJwtException(message: String, cause: Throwable? = null) : JwtException(message, cause)

public class MalformedJwkException(message: String, cause: Throwable? = null) : JwtException(message, cause)

public class SignatureException(message: String, cause: Throwable? = null) : JwtException(message, cause)

public class UnsupportedJwtException(message: String, cause: Throwable? = null) : JwtException(message, cause)

public class ExpiredJwtException(
    public val header: JwtHeader,
    public val claims: JwtPayload,
    message: String,
) : JwtException(message)

public class PrematureJwtException(
    public val header: JwtHeader,
    public val claims: JwtPayload,
    message: String,
) : JwtException(message)

public class MissingClaimException(
    public val claimName: String,
) : JwtException("Missing required claim: '$claimName'")

public class MissingHeaderException(
    public val headerName: String,
) : JwtException("Missing required header: '$headerName'")

public class IncorrectClaimException(
    public val claimName: String,
    public val expected: Any?,
    public val actual: Any?,
) : JwtException("Claim '$claimName' expected '$expected' but was '$actual'")
