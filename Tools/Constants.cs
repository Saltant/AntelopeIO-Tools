namespace Saltant.AntelopeIO.Tools
{
    /// <summary>
    /// Contains all necessary constants
    /// </summary>
    public abstract class Constants
    {
        /// <summary>
        /// Base32 character set for encoding the first 12 characters of EOSIO names.
        /// </summary>
        public const string NameCharset = ".12345abcdefghijklmnopqrstuvwxyz";

        /// <summary>
        /// Base16 character set for encoding the 13th character of EOSIO names.
        /// </summary>
        public const string NameCharset13 = ".12345abcdefghij";

        /// <summary>
        /// Default Base58 alphabet
        /// </summary>
        public const string Base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

        /// <summary>
        /// EOS public key data size
        /// </summary>
        public const int PublicKeyDataSize = 33;

        /// <summary>
        /// Prefix for EOSIO public keys with secp256k1 curve
        /// </summary>
        public const string PREFIX_PUB_K1 = "PUB_K1_";

        /// <summary>
        /// Indicates the cryptographic algorithm (K1 = secp256k1)
        /// </summary>
        public const string KEY_TYPE_K1 = "K1";

        /// <summary>
        /// This is an EOSIO legacy key type using the secp256k1 algorithm (similar to PUB_K1_)
        /// </summary>
        public const string KEY_TYPE_LEGACY = "EOS";

        /// <summary>
        /// Prefix for EOSIO signature with secp256k1 curve
        /// </summary>
        public const string PREFIX_SIG_K1 = "SIG_K1_";

        /// <summary>
        /// Cryptographic algorithm secp256k1
        /// </summary>
        public const string ALGORITHM_SECP256K1 = "secp256k1";
    }
}
