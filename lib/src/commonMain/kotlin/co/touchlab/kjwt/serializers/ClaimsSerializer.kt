package co.touchlab.kjwt.serializers

import co.touchlab.kjwt.model.Claims
import kotlinx.serialization.KSerializer

internal val ClaimsSerializer: KSerializer<Claims> = JwtPayloadSerializer(Claims.serializer())
