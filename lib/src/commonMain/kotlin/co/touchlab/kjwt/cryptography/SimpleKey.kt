package co.touchlab.kjwt.cryptography

import dev.whyoleg.cryptography.CryptographyProviderApi
import dev.whyoleg.cryptography.materials.key.Key

@OptIn(CryptographyProviderApi::class)
public class SimpleKey(
    /** The raw key bytes that back this key material. */
    public val value: ByteArray,
) : Key {
    public companion object {
        /**
         * An empty (zero-length) key singleton, used as a placeholder for direct-key (`dir`) JWE encryption where no
         * wrapping key is needed.
         */
        public val Empty: SimpleKey = SimpleKey(ByteArray(0))
    }
}
