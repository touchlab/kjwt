package co.touchlab.kjwt.ext

import co.touchlab.kjwt.model.JwtHeader

public inline fun <reified T> JwtHeader.getHeader(name: String): T =
    getHeader(kotlinx.serialization.serializer<T>(), name)

public inline fun <reified T> JwtHeader.getHeaderOrNull(name: String): T? =
    getHeaderOrNull(kotlinx.serialization.serializer<T>(), name)

public val JwtHeader.encryption: String get() = getHeader(JwtHeader.ENC)
public val JwtHeader.encryptionOrNull: String? get() = getHeaderOrNull(JwtHeader.ENC)

public val JwtHeader.type: String get() = getHeader(JwtHeader.TYP)
public val JwtHeader.typeOrNull: String? get() = getHeaderOrNull(JwtHeader.TYP)

public val JwtHeader.contentType: String get() = getHeader(JwtHeader.CTY)
public val JwtHeader.contentTypeOrNull: String? get() = getHeaderOrNull(JwtHeader.CTY)

public val JwtHeader.keyId: String get() = getHeader(JwtHeader.KID)
public val JwtHeader.keyIdOrNull: String? get() = getHeaderOrNull(JwtHeader.KID)
