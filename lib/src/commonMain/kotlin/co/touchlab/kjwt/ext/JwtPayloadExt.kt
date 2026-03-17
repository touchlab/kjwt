package co.touchlab.kjwt.ext

import co.touchlab.kjwt.model.JwtPayload
import co.touchlab.kjwt.model.JwtPayload.Companion.AUD
import co.touchlab.kjwt.model.JwtPayload.Companion.EXP
import co.touchlab.kjwt.model.JwtPayload.Companion.IAT
import co.touchlab.kjwt.model.JwtPayload.Companion.ISS
import co.touchlab.kjwt.model.JwtPayload.Companion.JTI
import co.touchlab.kjwt.model.JwtPayload.Companion.NBF
import co.touchlab.kjwt.model.JwtPayload.Companion.SUB
import co.touchlab.kjwt.serializers.AudienceDeserializer
import co.touchlab.kjwt.serializers.InstantEpochSecondsSerializer
import kotlin.time.Instant

public inline fun <reified T> JwtPayload.getClaim(name: String): T =
    getClaim(kotlinx.serialization.serializer<T>(), name)

public inline fun <reified T> JwtPayload.getClaimOrNull(name: String): T? =
    getClaimOrNull(kotlinx.serialization.serializer<T>(), name)

public val JwtPayload.issuer: String get() = getClaim(ISS)
public val JwtPayload.issuerOrNull: String? get() = getClaimOrNull(ISS)

public val JwtPayload.subject: String get() = getClaim(SUB)
public val JwtPayload.subjectOrNull: String? get() = getClaimOrNull(SUB)

public val JwtPayload.audience: Set<String> get() = getClaim(AudienceDeserializer, AUD)
public val JwtPayload.audienceOrNull: Set<String>? get() = getClaimOrNull(AudienceDeserializer, AUD)

public val JwtPayload.expiration: Instant get() = getClaim(InstantEpochSecondsSerializer, EXP)
public val JwtPayload.expirationOrNull: Instant? get() = getClaimOrNull(InstantEpochSecondsSerializer, EXP)

public val JwtPayload.notBefore: Instant get() = getClaim(InstantEpochSecondsSerializer, NBF)
public val JwtPayload.notBeforeOrNull: Instant? get() = getClaimOrNull(InstantEpochSecondsSerializer, NBF)

public val JwtPayload.issuedAt: Instant get() = getClaim(InstantEpochSecondsSerializer, IAT)
public val JwtPayload.issuedAtOrNull: Instant? get() = getClaimOrNull(InstantEpochSecondsSerializer, IAT)

public val JwtPayload.jwtId: String get() = getClaim(JTI)
public val JwtPayload.jwtIdOrNull: String? get() = getClaimOrNull(JTI)
