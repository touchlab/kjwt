package co.touchlab.kjwt.internal

import kotlinx.serialization.json.Json

@PublishedApi
internal val JwtJson = Json {
    ignoreUnknownKeys = true
    explicitNulls = false
}

inline fun <reified T> Json.encodeToBase64Url(value: T): String =
    encodeToString(value)
        .encodeToByteArray()
        .encodeBase64Url()
