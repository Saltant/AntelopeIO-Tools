namespace Saltant.AntelopeIO.Tools
{
    /// <summary>
    /// Provides cryptographic and format-related constants used throughout the AntelopeIO ecosystem.
    /// </summary>
    /// <remarks>
    /// Contains prefixes, algorithms, and encoding standards specific to EOSIO-based blockchains.
    /// </remarks>
    public abstract class Constants
    {
        /// <summary>
        /// Character set for Base32 encoding of the first 12 characters in EOSIO account names.
        /// </summary>
        /// <remarks>
        /// Valid characters: . (dot), 1-5, a-z. The dot represents empty padding.
        /// </remarks>
        public const string NameCharset = ".12345abcdefghijklmnopqrstuvwxyz";

        /// <summary>
        /// Restricted character set for the 13th character in EOSIO account names (Base16 variant).
        /// </summary>
        /// <remarks>
        /// Limited to . (dot), 1-5, a-p to provide namespace partitioning capability.
        /// </remarks>
        public const string NameCharset13 = ".12345abcdefghij";

        /// <summary>
        /// Standard Base58 alphabet as defined for Bitcoin-style encoding.
        /// </summary>
        /// <remarks>
        /// Excludes visually similar characters (0, O, I, l).
        /// </remarks>
        public const string Base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

        /// <summary>
        /// Byte length of a compressed ECC public key (33 bytes for compressed format).
        /// </summary>
        public const int PublicKeyDataSize = 33;

        /// <summary>
        /// Prefix for secp256k1 public keys in EOSIO format.
        /// </summary>
        /// <example>PUB_K1_6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5BoDq63</example>
        public const string PREFIX_PUB_K1 = "PUB_K1_";

        /// <summary>
        /// Algorithm identifier for secp256k1 keys in checksum calculations.
        /// </summary>
        public const string KEY_TYPE_K1 = "K1";

        /// <summary>
        /// Legacy prefix for EOS mainnet compatible secp256k1 public keys.
        /// </summary>
        /// <remarks>
        /// Used for backward compatibility with early EOSIO implementations.
        /// </remarks>
        public const string KEY_TYPE_LEGACY = "EOS";

        /// <summary>
        /// Prefix for secp256k1 signatures in EOSIO format.
        /// </summary>
        /// <example>SIG_K1_KhyBkPjQ3aM7h5gU5jGKZJr7B8JdJtI3ZrWbY7LmJ5J5vHJ5J5</example>
        public const string PREFIX_SIG_K1 = "SIG_K1_";

        /// <summary>
        /// Prefix for WebAuthn (secp256r1/P-256) signatures in EOSIO format.
        /// </summary>
        public const string PREFIX_SIG_WA = "SIG_WA_";

        /// <summary>
        /// Standard name for the secp256k1 elliptic curve (Koblitz curve).
        /// </summary>
        public const string ALGORITHM_SECP256K1 = "secp256k1";

        /// <summary>
        /// Standard name for the secp256r1 elliptic curve (P-256/NIST curve).
        /// </summary>
        /// <remarks>
        /// Also known as prime256v1 in OpenSSL. Used for WebAuthn signatures.
        /// </remarks>
        public const string ALGORITHM_SECP256R1 = "secp256r1";

        /// <summary>
        /// JSON field name for WebAuthn challenge parameter.
        /// </summary>
        public const string CHALLENGE = "challenge";

        /// <summary>
        /// JSON field name for WebAuthn type parameter.
        /// </summary>
        public const string TYPE = "type";

        /// <summary>
        /// JSON field name for WebAuthn origin parameter.
        /// </summary>
        public const string ORIGIN = "origin";

        /// <summary>
        /// Expected value for WebAuthn type parameter in authentication assertions.
        /// </summary>
        public const string WEBAUTHN_GET = "webauthn.get";

        /// <summary>
        /// Required prefix for valid WebAuthn origins.
        /// </summary>
        public const string HTTPS = "https://";
    }
}
