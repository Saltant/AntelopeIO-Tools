using Org.BouncyCastle.Crypto.Digests;
using System.Text;

namespace Saltant.AntelopeIO.Tools.Converters
{
    /// <summary>
    /// Provides conversion utilities between legacy EOS and modern PUB_K1 public key formats.
    /// </summary>
    /// <remarks>
    /// Handles Base58 encoding/decoding and RIPEMD-160 checksum validation for AntelopeIO blockchain keys.
    /// </remarks>
    public abstract class EosPublicKeyConverter
    {
        /// <summary>
        /// Converts a legacy EOS public key to the modern PUB_K1_ format.
        /// </summary>
        /// <param name="eosKey">The legacy EOS public key (starting with "EOS").</param>
        /// <returns>
        /// The converted public key in PUB_K1_ format.
        /// </returns>
        /// <exception cref="ArgumentException">
        /// Thrown when:
        /// <list type="bullet">
        ///   <item><description>Input key doesn't start with "EOS"</description></item>
        ///   <item><description>Key has invalid length or checksum</description></item>
        /// </list>
        /// </exception>
        /// <example>
        /// <code>
        /// string pubK1Key = EosPublicKeyConverter.ConvertEosToPubK1("EOS6MRyAjQq...");
        /// // Returns "PUB_K1_6MRyAjQq..."
        /// </code>
        /// </example>
        public static string ConvertEosToPubK1(string eosKey)
        {
            byte[] keyData = ParseEosPublicKey(eosKey);
            return PublicKeyToPubK1String(keyData);
        }

        /// <summary>
        /// Validates and decodes a legacy EOS public key into raw key data.
        /// </summary>
        /// <param name="eosKey">The legacy EOS public key to parse.</param>
        /// <returns>
        /// 33-byte array containing the compressed public key data.
        /// </returns>
        /// <exception cref="ArgumentException">
        /// Thrown for invalid key format, length, or checksum mismatch.
        /// </exception>
        /// <remarks>
        /// Performs:
        /// <list type="bullet">
        ///   <item><description>Base58 decoding</description></item>
        ///   <item><description>Length validation (37 bytes total)</description></item>
        ///   <item><description>RIPEMD-160 checksum verification</description></item>
        /// </list>
        /// </remarks>
        static byte[] ParseEosPublicKey(string eosKey)
        {
            if (string.IsNullOrEmpty(eosKey) || !eosKey.StartsWith(Constants.KEY_TYPE_LEGACY))
            {
                throw new ArgumentException("Invalid EOS key: must start with 'EOS'");
            }

            string keyPart = eosKey[3..];
            byte[] whole = Base58Converter.Decode(keyPart);
            if (whole.Length != Constants.PublicKeyDataSize + 4)
            {
                throw new ArgumentException("Invalid EOS key: wrong length");
            }

            byte[] keyData = new byte[Constants.PublicKeyDataSize];
            Array.Copy(whole, 0, keyData, 0, Constants.PublicKeyDataSize);
            byte[] checksum = new byte[4];
            Array.Copy(whole, Constants.PublicKeyDataSize, checksum, 0, 4);

            var digest = new RipeMD160Digest();
            digest.BlockUpdate(keyData, 0, keyData.Length);
            byte[] hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);
            byte[] calculatedChecksum = new byte[4];
            Array.Copy(hash, 0, calculatedChecksum, 0, 4);

            if (!calculatedChecksum.SequenceEqual(checksum))
            {
                throw new ArgumentException("Invalid EOS key: checksum does not match");
            }

            return keyData;
        }

        /// <summary>
        /// Converts raw public key data to a PUB_K1_ formatted string.
        /// </summary>
        /// <param name="keyData">33-byte compressed public key data.</param>
        /// <returns>
        /// Base58-encoded public key with "PUB_K1_" prefix and checksum.
        /// </returns>
        /// <exception cref="ArgumentException">
        /// Thrown when keyData length is not 33 bytes.
        /// </exception>
        /// <remarks>
        /// The conversion process:
        /// <list type="number">
        ///   <item><description>Appends "K1" suffix to key data</description></item>
        ///   <item><description>Computes RIPEMD-160 checksum</description></item>
        ///   <item><description>Base58 encodes key+checksum</description></item>
        ///   <item><description>Adds "PUB_K1_" prefix</description></item>
        /// </list>
        /// </remarks>
        static string PublicKeyToPubK1String(byte[] keyData)
        {
            if (keyData == null || keyData.Length != Constants.PublicKeyDataSize)
            {
                throw new ArgumentException("Invalid key data size");
            }

            byte[] suffix = Encoding.ASCII.GetBytes(Constants.KEY_TYPE_K1);
            byte[] dataWithSuffix = new byte[keyData.Length + suffix.Length];
            Array.Copy(keyData, 0, dataWithSuffix, 0, keyData.Length);
            Array.Copy(suffix, 0, dataWithSuffix, keyData.Length, suffix.Length);

            var digest = new RipeMD160Digest();
            digest.BlockUpdate(dataWithSuffix, 0, dataWithSuffix.Length);
            byte[] hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);
            byte[] checksum = new byte[4];
            Array.Copy(hash, 0, checksum, 0, 4);

            byte[] toEncode = new byte[keyData.Length + checksum.Length];
            Array.Copy(keyData, 0, toEncode, 0, keyData.Length);
            Array.Copy(checksum, 0, toEncode, keyData.Length, checksum.Length);

            string encoded = Base58Converter.EncodeWithLeadingZeros(toEncode);
            return Constants.PREFIX_PUB_K1 + encoded;
        }
    }
}
