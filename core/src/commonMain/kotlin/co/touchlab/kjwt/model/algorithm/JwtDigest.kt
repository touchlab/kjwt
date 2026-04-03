package co.touchlab.kjwt.model.algorithm

/** Digest (hash) algorithm used within a JWA algorithm descriptor. */
public enum class JwtDigest {
    /** SHA-1 digest, used with [EncryptionAlgorithm.RsaOaep]. */
    SHA1,

    /**
     * SHA-256 digest, used with [SigningAlgorithm.HS256], [SigningAlgorithm.RS256], [SigningAlgorithm.PS256],
     * [SigningAlgorithm.ES256], and [EncryptionAlgorithm.RsaOaep256].
     */
    SHA256,

    /**
     * SHA-384 digest, used with [SigningAlgorithm.HS384], [SigningAlgorithm.RS384], [SigningAlgorithm.PS384], and
     * [SigningAlgorithm.ES384].
     */
    SHA384,

    /**
     * SHA-512 digest, used with [SigningAlgorithm.HS512], [SigningAlgorithm.RS512], [SigningAlgorithm.PS512], and
     * [SigningAlgorithm.ES512].
     */
    SHA512,
}
