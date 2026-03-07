package co.touchlab.kjwt.internal

import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json

@PublishedApi
internal val JwtJson = Json {
    ignoreUnknownKeys = true
    explicitNulls = false
}

fun <T> Json.encodeToBase64Url(serializer: KSerializer<T>, value: T): String =
    encodeToString(serializer, value)
        .encodeToByteArray()
        .encodeBase64Url()

inline fun <reified T> Json.encodeToBase64Url(value: T): String =
    encodeToString(value)
        .encodeToByteArray()
        .encodeBase64Url()
