package co.touchlab.kjwt.internal

import co.touchlab.kjwt.annotations.InternalKJWTApi
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

@OptIn(ExperimentalEncodingApi::class)
@InternalKJWTApi
public fun ByteArray.encodeBase64Url(): String = Base64.UrlSafe.encode(this).trimEnd('=')

@OptIn(ExperimentalEncodingApi::class)
@InternalKJWTApi
public fun String.decodeBase64Url(): ByteArray {
    val padded =
        when (val rem = length % 4) {
            0 -> this
            else -> this + "=".repeat(4 - rem)
        }
    return Base64.UrlSafe.decode(padded)
}
