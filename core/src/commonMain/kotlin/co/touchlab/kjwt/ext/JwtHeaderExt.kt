package co.touchlab.kjwt.ext

import co.touchlab.kjwt.Jwt
import co.touchlab.kjwt.model.JwtHeader
import kotlinx.serialization.json.Json

/**
 * Returns the value of the named header, deserializing it to type [T] using a reified serializer.
 *
 * @param name the name of the header to retrieve.
 * @param jsonInstance the [Json] instance to use for deserialization; defaults to the library's
 *   [Jwt.defaultJsonParser] configuration (`ignoreUnknownKeys = true`, `explicitNulls = false`)
 * @return the header value deserialized as [T].
 * @throws co.touchlab.kjwt.exception.MissingHeaderException if the header is absent.
 * @see getHeaderOrNull
 */
public inline fun <reified T> JwtHeader.getHeader(
    name: String,
    jsonInstance: Json = Jwt.defaultJsonParser,
): T = getHeader(kotlinx.serialization.serializer<T>(), name, jsonInstance)

/**
 * Returns the value of the named header deserialized to type [T], or `null` if the header is absent.
 *
 * @param name the name of the header to retrieve.
 * @param jsonInstance the [Json] instance to use for deserialization; defaults to the library's
 *   [Jwt.defaultJsonParser] configuration (`ignoreUnknownKeys = true`, `explicitNulls = false`)
 * @return the header value deserialized as [T], or `null` if absent.
 * @see getHeader
 */
public inline fun <reified T> JwtHeader.getHeaderOrNull(
    name: String,
    jsonInstance: Json = Jwt.defaultJsonParser,
): T? = getHeaderOrNull(kotlinx.serialization.serializer<T>(), name, jsonInstance)

/**
 * Returns the `enc` (encryption algorithm) header value.
 *
 * @throws co.touchlab.kjwt.exception.MissingHeaderException if the `enc` header is absent.
 * @see encryptionOrNull
 */
public val JwtHeader.encryption: String get() = getHeader(JwtHeader.ENC)

/**
 * Returns the `enc` (encryption algorithm) header value, or `null` if the header is absent.
 *
 * @see encryption
 */
public val JwtHeader.encryptionOrNull: String? get() = getHeaderOrNull(JwtHeader.ENC)

/**
 * Returns the `typ` (token type) header value.
 *
 * @throws co.touchlab.kjwt.exception.MissingHeaderException if the `typ` header is absent.
 * @see typeOrNull
 */
public val JwtHeader.type: String get() = getHeader(JwtHeader.TYP)

/**
 * Returns the `typ` (token type) header value, or `null` if the header is absent.
 *
 * @see type
 */
public val JwtHeader.typeOrNull: String? get() = getHeaderOrNull(JwtHeader.TYP)

/**
 * Returns the `cty` (content type) header value.
 *
 * @throws co.touchlab.kjwt.exception.MissingHeaderException if the `cty` header is absent.
 * @see contentTypeOrNull
 */
public val JwtHeader.contentType: String get() = getHeader(JwtHeader.CTY)

/**
 * Returns the `cty` (content type) header value, or `null` if the header is absent.
 *
 * @see contentType
 */
public val JwtHeader.contentTypeOrNull: String? get() = getHeaderOrNull(JwtHeader.CTY)

/**
 * Returns the `kid` (key ID) header value.
 *
 * @throws co.touchlab.kjwt.exception.MissingHeaderException if the `kid` header is absent.
 * @see keyIdOrNull
 */
public val JwtHeader.keyId: String get() = getHeader(JwtHeader.KID)

/**
 * Returns the `kid` (key ID) header value, or `null` if the header is absent.
 *
 * @see keyId
 */
public val JwtHeader.keyIdOrNull: String? get() = getHeaderOrNull(JwtHeader.KID)
