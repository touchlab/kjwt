package co.touchlab.kjwt.model

import co.touchlab.kjwt.exception.MissingClaimException
import co.touchlab.kjwt.internal.JwtJson
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

@Serializable
internal class Claims(@PublishedApi internal val jsonData: JsonObject = JsonObject(emptyMap())) : JwtPayload {
    override fun <T> getClaim(serializer: DeserializationStrategy<T>, name: String): T =
        getClaimOrNull(serializer, name) ?: throw MissingClaimException(name)

    override fun <T> getClaimOrNull(serializer: DeserializationStrategy<T>, name: String): T? {
        val element = jsonData[name] ?: return null
        return JwtJson.decodeFromJsonElement(serializer, element)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Claims

        return jsonData == other.jsonData
    }

    override fun hashCode(): Int = jsonData.hashCode()
    override fun toString(): String = "Claims(data=$jsonData)"
}