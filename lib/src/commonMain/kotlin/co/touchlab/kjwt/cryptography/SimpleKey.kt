package co.touchlab.kjwt.cryptography

import dev.whyoleg.cryptography.CryptographyProviderApi
import dev.whyoleg.cryptography.materials.key.Key

@OptIn(CryptographyProviderApi::class)
public class SimpleKey(public val value: ByteArray) : Key {
    public companion object {
        public val Empty: SimpleKey = SimpleKey(ByteArray(0))
    }
}
