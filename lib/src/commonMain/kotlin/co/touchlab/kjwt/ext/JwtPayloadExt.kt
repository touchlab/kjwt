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

/**
 * Returns the value of the named claim, deserializing it to type [T] using a reified serializer.
 *
 * @param name the name of the claim to retrieve.
 * @return the claim value deserialized as [T].
 * @throws co.touchlab.kjwt.exception.MissingClaimException if the claim is absent.
 * @see getClaimOrNull
 */
public inline fun <reified T> JwtPayload.getClaim(name: String): T =
    getClaim(kotlinx.serialization.serializer<T>(), name)

/**
 * Returns the value of the named claim deserialized to type [T], or `null` if the claim is absent.
 *
 * @param name the name of the claim to retrieve.
 * @return the claim value deserialized as [T], or `null` if absent.
 * @see getClaim
 */
public inline fun <reified T> JwtPayload.getClaimOrNull(name: String): T? =
    getClaimOrNull(kotlinx.serialization.serializer<T>(), name)

/**
 * Returns the `iss` (issuer) claim value.
 *
 * @throws co.touchlab.kjwt.exception.MissingClaimException if the `iss` claim is absent.
 * @see issuerOrNull
 */
public val JwtPayload.issuer: String get() = getClaim(ISS)

/**
 * Returns the `iss` (issuer) claim value, or `null` if the claim is absent.
 *
 * @see issuer
 */
public val JwtPayload.issuerOrNull: String? get() = getClaimOrNull(ISS)

/**
 * Returns the `sub` (subject) claim value.
 *
 * @throws co.touchlab.kjwt.exception.MissingClaimException if the `sub` claim is absent.
 * @see subjectOrNull
 */
public val JwtPayload.subject: String get() = getClaim(SUB)

/**
 * Returns the `sub` (subject) claim value, or `null` if the claim is absent.
 *
 * @see subject
 */
public val JwtPayload.subjectOrNull: String? get() = getClaimOrNull(SUB)

/**
 * Returns the `aud` (audience) claim value as a set of strings.
 *
 * @throws co.touchlab.kjwt.exception.MissingClaimException if the `aud` claim is absent.
 * @see audienceOrNull
 */
public val JwtPayload.audience: Set<String> get() = getClaim(AudienceDeserializer, AUD)

/**
 * Returns the `aud` (audience) claim value as a set of strings, or `null` if the claim is absent.
 *
 * @see audience
 */
public val JwtPayload.audienceOrNull: Set<String>? get() = getClaimOrNull(AudienceDeserializer, AUD)

/**
 * Returns the `exp` (expiration time) claim value as an [Instant].
 *
 * @throws co.touchlab.kjwt.exception.MissingClaimException if the `exp` claim is absent.
 * @see expirationOrNull
 */
public val JwtPayload.expiration: Instant get() = getClaim(InstantEpochSecondsSerializer, EXP)

/**
 * Returns the `exp` (expiration time) claim value as an [Instant], or `null` if the claim is absent.
 *
 * @see expiration
 */
public val JwtPayload.expirationOrNull: Instant? get() = getClaimOrNull(InstantEpochSecondsSerializer, EXP)

/**
 * Returns the `nbf` (not before) claim value as an [Instant].
 *
 * @throws co.touchlab.kjwt.exception.MissingClaimException if the `nbf` claim is absent.
 * @see notBeforeOrNull
 */
public val JwtPayload.notBefore: Instant get() = getClaim(InstantEpochSecondsSerializer, NBF)

/**
 * Returns the `nbf` (not before) claim value as an [Instant], or `null` if the claim is absent.
 *
 * @see notBefore
 */
public val JwtPayload.notBeforeOrNull: Instant? get() = getClaimOrNull(InstantEpochSecondsSerializer, NBF)

/**
 * Returns the `iat` (issued at) claim value as an [Instant].
 *
 * @throws co.touchlab.kjwt.exception.MissingClaimException if the `iat` claim is absent.
 * @see issuedAtOrNull
 */
public val JwtPayload.issuedAt: Instant get() = getClaim(InstantEpochSecondsSerializer, IAT)

/**
 * Returns the `iat` (issued at) claim value as an [Instant], or `null` if the claim is absent.
 *
 * @see issuedAt
 */
public val JwtPayload.issuedAtOrNull: Instant? get() = getClaimOrNull(InstantEpochSecondsSerializer, IAT)

/**
 * Returns the `jti` (JWT ID) claim value.
 *
 * @throws co.touchlab.kjwt.exception.MissingClaimException if the `jti` claim is absent.
 * @see jwtIdOrNull
 */
public val JwtPayload.jwtId: String get() = getClaim(JTI)

/**
 * Returns the `jti` (JWT ID) claim value, or `null` if the claim is absent.
 *
 * @see jwtId
 */
public val JwtPayload.jwtIdOrNull: String? get() = getClaimOrNull(JTI)
