import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.providers.webcrypto.WebCrypto

// IDK Why, but KotlinJS needs the ref in advance to ensure it can be found in tests later
public val webCryptoInstance = CryptographyProvider.WebCrypto