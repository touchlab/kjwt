package co.touchlab.kjwt.internal

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

@PublishedApi
internal val JwtJson = Json {
    ignoreUnknownKeys = true
    explicitNulls = false
}

internal fun JsonObject.encodeToBase64Url(): String =
    JwtJson.encodeToString(JsonObject.serializer(), this)
        .encodeToByteArray()
        .encodeBase64Url()