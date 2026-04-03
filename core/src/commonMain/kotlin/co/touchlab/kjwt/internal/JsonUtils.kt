package co.touchlab.kjwt.internal

import co.touchlab.kjwt.exception.MalformedJwtException
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.json.Json

internal fun <T> Json.decodeBase64Url(
    deserializer: DeserializationStrategy<T>,
    base64UrlString: String,
    name: String? = null,
): T {
    val bytes =
        try {
            base64UrlString.decodeBase64Url()
        } catch (e: Throwable) {
            throw MalformedJwtException(
                "Invalid base64url encoding in JWT" + (if (name != null) " $name" else ""),
                e,
            )
        }

    return try {
        decodeFromString(deserializer, bytes.decodeToString())
    } catch (e: Throwable) {
        throw MalformedJwtException("JWT $name is not valid JSON", e)
    }
}

internal inline fun <reified T> Json.encodeToBase64Url(value: T): String =
    encodeToString(value)
        .encodeToByteArray()
        .encodeBase64Url()
