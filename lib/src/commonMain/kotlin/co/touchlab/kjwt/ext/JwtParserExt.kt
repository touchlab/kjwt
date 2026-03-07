package co.touchlab.kjwt.ext

import co.touchlab.kjwt.exception.MalformedJwtException
import co.touchlab.kjwt.model.JwtInstance
import co.touchlab.kjwt.model.JwtPayload
import co.touchlab.kjwt.parser.JwtParser
import co.touchlab.kjwt.serializers.asJwtPayloadSerializer


suspend inline fun <reified T : JwtPayload> JwtParser.parseSignedJwt(token: String): JwtInstance.Jws<T> =
    parseSignedJwt(kotlinx.serialization.serializer<T>().asJwtPayloadSerializer(), token)

suspend inline fun <reified T : JwtPayload> JwtParser.parseEncryptedJwt(token: String): JwtInstance.Jwe<T> =
    parseEncryptedJwt(kotlinx.serialization.serializer<T>().asJwtPayloadSerializer(), token)

/**
 * Auto-detects JWS (3 parts) or JWE (5 parts) and delegates accordingly.
 */
suspend inline fun <reified T : JwtPayload> JwtParser.parse(token: String): JwtInstance<T> {
    val partCount = token.count { it == '.' } + 1
    return when (partCount) {
        3 -> parseSignedJwt(token)
        5 -> parseEncryptedJwt(token)
        else -> throw MalformedJwtException("Cannot determine JWT type: expected 3 or 5 parts, got $partCount")
    }
}