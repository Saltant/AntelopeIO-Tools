using Org.BouncyCastle.Math;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Saltant.AntelopeIO.Tools
{
    public static class Extensions
    {
        /// <summary>
        /// Converts a byte array to a lowercase hexadecimal string without hyphens.
        /// </summary>
        /// <param name="bytes">The byte array to convert.</param>
        /// <returns>A lowercase hexadecimal string representing the byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="bytes"/> is null.</exception>
        /// <remarks>
        /// This method is used for debugging and logging serialized data in a human-readable format.
        /// Example: The byte array <c>[0x00, 0x6E]</c> is converted to <c>"006e"</c>.
        /// </remarks>
        public static string ToHex(this byte[] bytes) => Convert.ToHexStringLower(bytes);

        /// <summary>
        /// Converts a hexadecimal string to a byte array.
        /// </summary>
        public static byte[] HexStringToByteArray(this string hex) => [.. Enumerable.Range(0, hex.Length / 2).Select(i => Convert.ToByte(hex.Substring(i * 2, 2), 16))];

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
