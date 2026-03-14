package co.touchlab.kjwt.cryptography

import dev.whyoleg.cryptography.CryptographyProviderApi
import dev.whyoleg.cryptography.materials.key.Key

@OptIn(CryptographyProviderApi::class)
class SimpleKey(val value: ByteArray) : Key {
    companion object {
        val Empty = SimpleKey(ByteArray(0))
    }
}
