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

inline fun <reified T> JwtPayload.getClaim(name: String): T =
    getClaim(kotlinx.serialization.serializer<T>(), name)

inline fun <reified T> JwtPayload.getClaimOrNull(name: String): T? =
    getClaimOrNull(kotlinx.serialization.serializer<T>(), name)

val JwtPayload.issuer: String get() = getClaim(ISS)
val JwtPayload.issuerOrNull: String? get() = getClaimOrNull(ISS)

val JwtPayload.subject: String get() = getClaim(SUB)
val JwtPayload.subjectOrNull: String? get() = getClaimOrNull(SUB)

val JwtPayload.audience: Set<String> get() = getClaim(AudienceDeserializer, AUD)
val JwtPayload.audienceOrNull: Set<String>? get() = getClaimOrNull(AudienceDeserializer, AUD)

val JwtPayload.expiration: Instant get() = getClaim(InstantEpochSecondsSerializer, EXP)
val JwtPayload.expirationOrNull: Instant? get() = getClaimOrNull(InstantEpochSecondsSerializer, EXP)

val JwtPayload.notBefore: Instant get() = getClaim(InstantEpochSecondsSerializer, NBF)
val JwtPayload.notBeforeOrNull: Instant? get() = getClaimOrNull(InstantEpochSecondsSerializer, NBF)

val JwtPayload.issuedAt: Instant get() = getClaim(InstantEpochSecondsSerializer, IAT)
val JwtPayload.issuedAtOrNull: Instant? get() = getClaimOrNull(InstantEpochSecondsSerializer, IAT)

val JwtPayload.jwtId: String get() = getClaim(JTI)
val JwtPayload.jwtIdOrNull: String? get() = getClaimOrNull(JTI)
