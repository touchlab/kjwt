package co.touchlab.kjwt.model

import co.touchlab.kjwt.internal.JwtJson
import co.touchlab.kjwt.serializers.InstantEpochSecondsSerializer
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Instant
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

interface JwtPayload {
    fun hasClaim(name: String): Boolean
    fun <T> getClaim(serializer: DeserializationStrategy<T>, name: String): T
    fun <T> getClaimOrNull(serializer: DeserializationStrategy<T>, name: String): T?

    class Builder {
        var issuer: String? = null
            set(value) {
                field = value
                claim(ISS, value)
            }

        var subject: String? = null
            set(value) {
                field = value
                claim(SUB, value)
            }

        var audience: Set<String>? = null
            set(value) {
                field = value
                if (value != null && value.size == 1) {
                    claim(AUD, value.first())
                } else {
                    claim(AUD, value)
                }
            }

        var expiration: Instant? = null
            set(value) {
                field = value
                claim(EXP, InstantEpochSecondsSerializer, value)
            }

        var notBefore: Instant? = null
            set(value) {
                field = value
                claim(NBF, InstantEpochSecondsSerializer, value)
            }

        var issuedAt: Instant? = null
            set(value) {
                field = value
                claim(IAT, InstantEpochSecondsSerializer, value)
            }

        var id: String? = null
            set(value) {
                field = value
                claim(JTI, value)
            }

        @PublishedApi
        internal val content: MutableMap<String, JsonElement> = mutableMapOf()

        fun claim(name: String, value: JsonElement) {
            content[name] = value
        }

        fun <T> claim(name: String, serializer: SerializationStrategy<T>, value: T?) {
            if (value != null) {
                claim(name, JwtJson.encodeToJsonElement(serializer, value))
            } else {
                content.remove(name)
            }
        }

        fun expiresIn(duration: Duration) {
            expiration = Clock.System.now() + duration
        }

        fun notBeforeNow() {
            notBefore = Clock.System.now()
        }

        @ExperimentalUuidApi
        fun randomId() {
            id = Uuid.random().toString()
        }

        inline fun <reified T> claim(name: String, value: T) {
            claim(name, kotlinx.serialization.serializer<T>(), value)
        }

        internal fun build(): Claims = Claims(JsonObject(content))
    }

    companion object {
        const val ISS = "iss"
        const val SUB = "sub"
        const val AUD = "aud"
        const val EXP = "exp"
        const val NBF = "nbf"
        const val IAT = "iat"
        const val JTI = "jti"
    }
}

