using Org.BouncyCastle.Math;
using System.Text;

namespace Saltant.AntelopeIO.Tools
{
    /// <summary>
    /// Provides extension methods for common data conversion operations in AntelopeIO blockchain operations.
    /// </summary>
    public static class Extensions
    {
        /// <summary>
        /// Converts a byte array to its lowercase hexadecimal string representation.
        /// </summary>
        /// <param name="bytes">The byte array to convert.</param>
        /// <returns>
        /// A lowercase hexadecimal string without separators.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="bytes"/> is null.</exception>
        /// <example>
        /// <code>
        /// byte[] data = { 0x00, 0x6E };
        /// string hex = data.ToHex(); // Returns "006e"
        /// </code>
        /// </example>
        public static string ToHex(this byte[] bytes) => Convert.ToHexStringLower(bytes);

        /// <summary>
        /// Decodes a byte array as a UTF-8 encoded string.
        /// </summary>
        /// <param name="bytes">The UTF-8 encoded byte array.</param>
        /// <returns>
        /// The decoded string representation.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="bytes"/> is null.</exception>
        /// <exception cref="DecoderFallbackException">Thrown when invalid UTF-8 sequences are encountered.</exception>
        public static string ToUtf8String(this byte[] bytes) => Encoding.UTF8.GetString(bytes);

        /// <summary>
        /// Parses a hexadecimal string into its byte array representation.
        /// </summary>
        /// <param name="hex">The hexadecimal string to convert (case-insensitive).</param>
        /// <returns>
        /// The converted byte array.
        /// </returns>
        /// <exception cref="ArgumentException">
        /// Thrown when:
        /// <list type="bullet">
        ///   <item><description>Input string length is odd</description></item>
        ///   <item><description>Contains non-hexadecimal characters</description></item>
        /// </list>
        /// </exception>
        /// <remarks>
        /// The input string should not contain any prefixes (like "0x") or separators.
        /// </remarks>
        public static byte[] HexStringToByteArray(this string hex) => [.. Enumerable.Range(0, hex.Length / 2).Select(i => Convert.ToByte(hex.Substring(i * 2, 2), 16))];

        /// <summary>
        /// Converts a BigInteger to an unsigned byte array in big-endian format.
        /// </summary>
        /// <param name="bigInt">The BigInteger value to convert.</param>
        /// <returns>
        /// Byte array representing the absolute value of the number without sign padding.
        /// </returns>
        /// <remarks>
        /// Removes the leading zero byte used for sign representation in BigInteger's native format.
        /// The returned array is suitable for cryptographic operations that require unsigned values.
        /// </remarks>
        public static byte[] ToByteArrayUnsigned(this BigInteger bigInt)
        {
            byte[] bytes = bigInt.ToByteArray();
            if (bytes.Length > 1 && bytes[0] == 0)
            {
                byte[] unsignedBytes = new byte[bytes.Length - 1];
                Array.Copy(bytes, 1, unsignedBytes, 0, unsignedBytes.Length);
                return unsignedBytes;
            }
            return bytes;
        }
    }
}
