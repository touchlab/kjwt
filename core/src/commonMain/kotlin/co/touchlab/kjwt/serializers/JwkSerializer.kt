package co.touchlab.kjwt.serializers

import co.touchlab.kjwt.exception.MalformedJwkException
import co.touchlab.kjwt.exception.UnsupportedJwtException
import co.touchlab.kjwt.model.jwk.Jwk
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject

private fun JsonObject.requireString(key: String): String =
    (this[key] as? JsonPrimitive)?.content
        ?: throw MalformedJwkException("Missing required JWK field: '$key'")

private fun JsonObject.optString(key: String): String? = (this[key] as? JsonPrimitive)?.content

private fun JsonObject.optStringList(key: String): List<String>? = (this[key] as? JsonArray)?.map {
    (it as JsonPrimitive).content
}

// ---------------------------------------------------------------------------
// RSA
// ---------------------------------------------------------------------------

/**
 * Serializer for [Jwk.Rsa] values to and from their JSON Web Key representation per RFC 7517.
 *
 * Encodes all present RSA key parameters (`n`, `e`, `d`, `p`, `q`, `dp`, `dq`, `qi`) as
 * Base64URL strings, along with optional metadata fields (`use`, `key_ops`, `alg`, `kid`).
 * Throws [co.touchlab.kjwt.exception.MalformedJwkException] during deserialization if a required
 * field is missing.
 */
public object JwkRsaSerializer : KSerializer<Jwk.Rsa> {
    private val delegate = JsonObject.serializer()
    override val descriptor: SerialDescriptor = delegate.descriptor

    override fun serialize(
        encoder: Encoder,
        value: Jwk.Rsa,
    ) {
        encoder.encodeSerializableValue(
            delegate,
            buildJsonObject {
                put("kty", JsonPrimitive(Jwk.Rsa.KTY))
                put("n", JsonPrimitive(value.n))
                put("e", JsonPrimitive(value.e))
                value.d?.let { put("d", JsonPrimitive(it)) }
                value.p?.let { put("p", JsonPrimitive(it)) }
                value.q?.let { put("q", JsonPrimitive(it)) }
                value.dp?.let { put("dp", JsonPrimitive(it)) }
                value.dq?.let { put("dq", JsonPrimitive(it)) }
                value.qi?.let { put("qi", JsonPrimitive(it)) }
                value.use?.let { put("use", JsonPrimitive(it)) }
                value.keyOps?.let { ops -> put("key_ops", JsonArray(ops.map { JsonPrimitive(it) })) }
                value.alg?.let { put("alg", JsonPrimitive(it)) }
                value.kid?.let { put("kid", JsonPrimitive(it)) }
            },
        )
    }

    override fun deserialize(decoder: Decoder): Jwk.Rsa {
        val obj = decoder.decodeSerializableValue(delegate)
        return Jwk.Rsa(
            n = obj.requireString("n"),
            e = obj.requireString("e"),
            d = obj.optString("d"),
            p = obj.optString("p"),
            q = obj.optString("q"),
            dp = obj.optString("dp"),
            dq = obj.optString("dq"),
            qi = obj.optString("qi"),
            use = obj.optString("use"),
            keyOps = obj.optStringList("key_ops"),
            alg = obj.optString("alg"),
            kid = obj.optString("kid"),
        )
    }
}

// ---------------------------------------------------------------------------
// EC
// ---------------------------------------------------------------------------

/**
 * Serializer for [Jwk.Ec] values to and from their JSON Web Key representation per RFC 7517.
 *
 * Encodes the required EC parameters (`crv`, `x`, `y`) and optional private key parameter (`d`)
 * as Base64URL strings, along with optional metadata fields (`use`, `key_ops`, `alg`, `kid`).
 * Throws [co.touchlab.kjwt.exception.MalformedJwkException] during deserialization if a required
 * field is missing.
 */
public object JwkEcSerializer : KSerializer<Jwk.Ec> {
    private val delegate = JsonObject.serializer()
    override val descriptor: SerialDescriptor = delegate.descriptor

    override fun serialize(
        encoder: Encoder,
        value: Jwk.Ec,
    ) {
        encoder.encodeSerializableValue(
            delegate,
            buildJsonObject {
                put("kty", JsonPrimitive(Jwk.Ec.KTY))
                put("crv", JsonPrimitive(value.crv))
                put("x", JsonPrimitive(value.x))
                put("y", JsonPrimitive(value.y))
                value.d?.let { put("d", JsonPrimitive(it)) }
                value.use?.let { put("use", JsonPrimitive(it)) }
                value.keyOps?.let { ops -> put("key_ops", JsonArray(ops.map { JsonPrimitive(it) })) }
                value.alg?.let { put("alg", JsonPrimitive(it)) }
                value.kid?.let { put("kid", JsonPrimitive(it)) }
            },
        )
    }

    override fun deserialize(decoder: Decoder): Jwk.Ec {
        val obj = decoder.decodeSerializableValue(delegate)
        return Jwk.Ec(
            crv = obj.requireString("crv"),
            x = obj.requireString("x"),
            y = obj.requireString("y"),
            d = obj.optString("d"),
            use = obj.optString("use"),
            keyOps = obj.optStringList("key_ops"),
            alg = obj.optString("alg"),
            kid = obj.optString("kid"),
        )
    }
}

// ---------------------------------------------------------------------------
// Oct
// ---------------------------------------------------------------------------

/**
 * Serializer for [Jwk.Oct] values to and from their JSON Web Key representation per RFC 7517.
 *
 * Encodes the symmetric key material (`k`) as a Base64URL string, along with optional metadata
 * fields (`use`, `key_ops`, `alg`, `kid`). Throws
 * [co.touchlab.kjwt.exception.MalformedJwkException] during deserialization if the required `k`
 * field is missing.
 */
public object JwkOctSerializer : KSerializer<Jwk.Oct> {
    private val delegate = JsonObject.serializer()
    override val descriptor: SerialDescriptor = delegate.descriptor

    override fun serialize(
        encoder: Encoder,
        value: Jwk.Oct,
    ) {
        encoder.encodeSerializableValue(
            delegate,
            buildJsonObject {
                put("kty", JsonPrimitive(Jwk.Oct.KTY))
                put("k", JsonPrimitive(value.k))
                value.use?.let { put("use", JsonPrimitive(it)) }
                value.keyOps?.let { ops -> put("key_ops", JsonArray(ops.map { JsonPrimitive(it) })) }
                value.alg?.let { put("alg", JsonPrimitive(it)) }
                value.kid?.let { put("kid", JsonPrimitive(it)) }
            },
        )
    }

    override fun deserialize(decoder: Decoder): Jwk.Oct {
        val obj = decoder.decodeSerializableValue(delegate)
        return Jwk.Oct(
            k = obj.requireString("k"),
            use = obj.optString("use"),
            keyOps = obj.optStringList("key_ops"),
            alg = obj.optString("alg"),
            kid = obj.optString("kid"),
        )
    }
}

// ---------------------------------------------------------------------------
// OKP
// ---------------------------------------------------------------------------

/**
 * Serializer for [Jwk.Okp] values to and from their JSON Web Key representation per RFC 8037.
 *
 * Encodes the required OKP parameters (`crv`, `x`) and optional private key parameter (`d`)
 * as Base64URL strings, along with optional metadata fields (`use`, `key_ops`, `alg`, `kid`).
 * Throws [co.touchlab.kjwt.exception.MalformedJwkException] during deserialization if a required
 * field is missing.
 */
public object JwkOkpSerializer : KSerializer<Jwk.Okp> {
    private val delegate = JsonObject.serializer()
    override val descriptor: SerialDescriptor = delegate.descriptor

    override fun serialize(
        encoder: Encoder,
        value: Jwk.Okp,
    ) {
        encoder.encodeSerializableValue(
            delegate,
            buildJsonObject {
                put("kty", JsonPrimitive(Jwk.Okp.KTY))
                put("crv", JsonPrimitive(value.crv))
                put("x", JsonPrimitive(value.x))
                value.d?.let { put("d", JsonPrimitive(it)) }
                value.use?.let { put("use", JsonPrimitive(it)) }
                value.keyOps?.let { ops -> put("key_ops", JsonArray(ops.map { JsonPrimitive(it) })) }
                value.alg?.let { put("alg", JsonPrimitive(it)) }
                value.kid?.let { put("kid", JsonPrimitive(it)) }
            },
        )
    }

    override fun deserialize(decoder: Decoder): Jwk.Okp {
        val obj = decoder.decodeSerializableValue(delegate)
        return Jwk.Okp(
            crv = obj.requireString("crv"),
            x = obj.requireString("x"),
            d = obj.optString("d"),
            use = obj.optString("use"),
            keyOps = obj.optStringList("key_ops"),
            alg = obj.optString("alg"),
            kid = obj.optString("kid"),
        )
    }
}

// ---------------------------------------------------------------------------
// Jwk (polymorphic dispatcher)
// ---------------------------------------------------------------------------

/**
 * Polymorphic serializer for [Jwk] values, dispatching to the appropriate concrete serializer
 * based on the `kty` field in the JSON object.
 *
 * Supports `"RSA"` ([JwkRsaSerializer]), `"EC"` ([JwkEcSerializer]), `"oct"` ([JwkOctSerializer]),
 * and `"OKP"` ([JwkOkpSerializer]) key types. Throws
 * [co.touchlab.kjwt.exception.MalformedJwkException] if `kty` is absent, and
 * [co.touchlab.kjwt.exception.UnsupportedJwtException] if the key type is not recognised.
 */
public object JwkSerializer : KSerializer<Jwk> {
    private val delegate = JsonObject.serializer()
    override val descriptor: SerialDescriptor = delegate.descriptor

    override fun serialize(
        encoder: Encoder,
        value: Jwk,
    ) {
        when (value) {
            is Jwk.Rsa -> encoder.encodeSerializableValue(JwkRsaSerializer, value)
            is Jwk.Ec -> encoder.encodeSerializableValue(JwkEcSerializer, value)
            is Jwk.Oct -> encoder.encodeSerializableValue(JwkOctSerializer, value)
            is Jwk.Okp -> encoder.encodeSerializableValue(JwkOkpSerializer, value)
        }
    }

    override fun deserialize(decoder: Decoder): Jwk {
        val input =
            decoder as? JsonDecoder
                ?: throw SerializationException("JwkSerializer requires JSON input")
        val obj = input.decodeJsonElement().jsonObject
        return when (
            val kty =
                (obj["kty"] as? JsonPrimitive)?.content
                    ?: throw MalformedJwkException("Missing 'kty' in JWK")
        ) {
            Jwk.Rsa.KTY -> input.json.decodeFromJsonElement(JwkRsaSerializer, obj)
            Jwk.Ec.KTY -> input.json.decodeFromJsonElement(JwkEcSerializer, obj)
            Jwk.Oct.KTY -> input.json.decodeFromJsonElement(JwkOctSerializer, obj)
            Jwk.Okp.KTY -> input.json.decodeFromJsonElement(JwkOkpSerializer, obj)
            else -> throw UnsupportedJwtException("Unsupported JWK key type: '$kty'")
        }
    }
}

// ---------------------------------------------------------------------------
// RSAThumbprint
// ---------------------------------------------------------------------------

/**
 * Serializer for [Jwk.Rsa.RSAThumbprint] values to and from their canonical JSON representation.
 *
 * Encodes only the required members (`e`, `kty`, `n`) in lexicographic key order as defined by
 * RFC 7638 for computing JWK Thumbprints.
 */
public object JwkRsaThumbprintSerializer : KSerializer<Jwk.Rsa.RSAThumbprint> {
    private val delegate = JsonObject.serializer()
    override val descriptor: SerialDescriptor = delegate.descriptor

    override fun serialize(
        encoder: Encoder,
        value: Jwk.Rsa.RSAThumbprint,
    ) {
        encoder.encodeSerializableValue(
            delegate,
            buildJsonObject {
                put("e", JsonPrimitive(value.e))
                put("kty", JsonPrimitive(Jwk.Rsa.KTY))
                put("n", JsonPrimitive(value.n))
            },
        )
    }

    override fun deserialize(decoder: Decoder): Jwk.Rsa.RSAThumbprint {
        val obj = decoder.decodeSerializableValue(delegate)
        return Jwk.Rsa.RSAThumbprint(
            e = obj.requireString("e"),
            n = obj.requireString("n"),
        )
    }
}

// ---------------------------------------------------------------------------
// ECThumbprint
// ---------------------------------------------------------------------------

/**
 * Serializer for [Jwk.Ec.ECThumbprint] values to and from their canonical JSON representation.
 *
 * Encodes only the required members (`crv`, `kty`, `x`, `y`) in lexicographic key order as
 * defined by RFC 7638 for computing JWK Thumbprints.
 */
public object JwkEcThumbprintSerializer : KSerializer<Jwk.Ec.ECThumbprint> {
    private val delegate = JsonObject.serializer()
    override val descriptor: SerialDescriptor = delegate.descriptor

    override fun serialize(
        encoder: Encoder,
        value: Jwk.Ec.ECThumbprint,
    ) {
        encoder.encodeSerializableValue(
            delegate,
            buildJsonObject {
                put("crv", JsonPrimitive(value.crv))
                put("kty", JsonPrimitive(Jwk.Ec.KTY))
                put("x", JsonPrimitive(value.x))
                put("y", JsonPrimitive(value.y))
            },
        )
    }

    override fun deserialize(decoder: Decoder): Jwk.Ec.ECThumbprint {
        val obj = decoder.decodeSerializableValue(delegate)
        return Jwk.Ec.ECThumbprint(
            crv = obj.requireString("crv"),
            x = obj.requireString("x"),
            y = obj.requireString("y"),
        )
    }
}

// ---------------------------------------------------------------------------
// OctThumbprint
// ---------------------------------------------------------------------------

/**
 * Serializer for [Jwk.Oct.OctThumbprint] values to and from their canonical JSON representation.
 *
 * Encodes only the required members (`k`, `kty`) in lexicographic key order as defined by RFC 7638
 * for computing JWK Thumbprints.
 */
public object JwkOctThumbprintSerializer : KSerializer<Jwk.Oct.OctThumbprint> {
    private val delegate = JsonObject.serializer()
    override val descriptor: SerialDescriptor = delegate.descriptor

    override fun serialize(
        encoder: Encoder,
        value: Jwk.Oct.OctThumbprint,
    ) {
        encoder.encodeSerializableValue(
            delegate,
            buildJsonObject {
                put("k", JsonPrimitive(value.k))
                put("kty", JsonPrimitive(Jwk.Oct.KTY))
            },
        )
    }

    override fun deserialize(decoder: Decoder): Jwk.Oct.OctThumbprint {
        val obj = decoder.decodeSerializableValue(delegate)
        return Jwk.Oct.OctThumbprint(
            k = obj.requireString("k"),
        )
    }
}

// ---------------------------------------------------------------------------
// OkpThumbprint
// ---------------------------------------------------------------------------

/**
 * Serializer for [Jwk.Okp.OkpThumbprint] values to and from their canonical JSON representation.
 *
 * Encodes only the required members (`crv`, `kty`, `x`) in lexicographic key order as defined by
 * RFC 7638 for computing JWK Thumbprints.
 */
public object JwkOkpThumbprintSerializer : KSerializer<Jwk.Okp.OkpThumbprint> {
    private val delegate = JsonObject.serializer()
    override val descriptor: SerialDescriptor = delegate.descriptor

    override fun serialize(
        encoder: Encoder,
        value: Jwk.Okp.OkpThumbprint,
    ) {
        encoder.encodeSerializableValue(
            delegate,
            buildJsonObject {
                put("crv", JsonPrimitive(value.crv))
                put("kty", JsonPrimitive(Jwk.Okp.KTY))
                put("x", JsonPrimitive(value.x))
            },
        )
    }

    override fun deserialize(decoder: Decoder): Jwk.Okp.OkpThumbprint {
        val obj = decoder.decodeSerializableValue(delegate)
        return Jwk.Okp.OkpThumbprint(
            crv = obj.requireString("crv"),
            x = obj.requireString("x"),
        )
    }
}

// ---------------------------------------------------------------------------
// Jwk.Thumbprint (polymorphic dispatcher)
// ---------------------------------------------------------------------------

/**
 * Polymorphic serializer for [Jwk.Thumbprint] values, dispatching to the appropriate concrete
 * thumbprint serializer based on the `kty` field in the JSON object.
 *
 * Supports `"RSA"` ([JwkRsaThumbprintSerializer]), `"EC"` ([JwkEcThumbprintSerializer]),
 * `"oct"` ([JwkOctThumbprintSerializer]), and `"OKP"` ([JwkOkpThumbprintSerializer]) key types.
 * Throws [co.touchlab.kjwt.exception.MalformedJwkException] if `kty` is absent, and
 * [co.touchlab.kjwt.exception.UnsupportedJwtException] if the key type is not recognised.
 */
public object JwkThumbprintSerializer : KSerializer<Jwk.Thumbprint> {
    private val delegate = JsonObject.serializer()
    override val descriptor: SerialDescriptor = delegate.descriptor

    override fun serialize(
        encoder: Encoder,
        value: Jwk.Thumbprint,
    ) {
        when (value) {
            is Jwk.Rsa.RSAThumbprint -> encoder.encodeSerializableValue(JwkRsaThumbprintSerializer, value)
            is Jwk.Ec.ECThumbprint -> encoder.encodeSerializableValue(JwkEcThumbprintSerializer, value)
            is Jwk.Oct.OctThumbprint -> encoder.encodeSerializableValue(JwkOctThumbprintSerializer, value)
            is Jwk.Okp.OkpThumbprint -> encoder.encodeSerializableValue(JwkOkpThumbprintSerializer, value)
        }
    }

    override fun deserialize(decoder: Decoder): Jwk.Thumbprint {
        val input =
            decoder as? JsonDecoder
                ?: throw SerializationException("JwkThumbprintSerializer requires JSON input")
        val obj = input.decodeJsonElement().jsonObject
        return when (
            val kty =
                (obj["kty"] as? JsonPrimitive)?.content
                    ?: throw MalformedJwkException("Missing 'kty' in JWK thumbprint")
        ) {
            Jwk.Rsa.KTY -> input.json.decodeFromJsonElement(JwkRsaThumbprintSerializer, obj)
            Jwk.Ec.KTY -> input.json.decodeFromJsonElement(JwkEcThumbprintSerializer, obj)
            Jwk.Oct.KTY -> input.json.decodeFromJsonElement(JwkOctThumbprintSerializer, obj)
            Jwk.Okp.KTY -> input.json.decodeFromJsonElement(JwkOkpThumbprintSerializer, obj)
            else -> throw UnsupportedJwtException("Unsupported JWK key type: '$kty'")
        }
    }
}
