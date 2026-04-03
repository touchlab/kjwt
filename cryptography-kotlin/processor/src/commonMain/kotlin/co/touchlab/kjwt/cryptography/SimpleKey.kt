package co.touchlab.kjwt.cryptography

import dev.whyoleg.cryptography.CryptographyProviderApi
import dev.whyoleg.cryptography.materials.key.Key

/**
 * A minimal [Key] implementation that wraps a raw [ByteArray] of key material.
 *
 * Used as the key type for direct-key (`dir`) JWE encryption, where the content encryption key is
 * supplied directly as bytes rather than being wrapped by an asymmetric algorithm.
 *
 * @see EncryptionKey
 */
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
