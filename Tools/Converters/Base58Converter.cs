using Org.BouncyCastle.Math;
using System.Text;

namespace Saltant.AntelopeIO.Tools.Converters
{
    /// <summary>
    /// Provides methods for encoding and decoding data using the Base58 format, commonly used in blockchain systems
    /// such as <see href="https://xprnetwork.org">XPR Network</see> for encoding addresses and keys.
    /// </summary>
    /// <remarks>
    /// The Base58 encoding scheme uses a 58-character alphabet (excluding visually similar characters like 0, O, I, l)
    /// to represent binary data in a compact, human-readable format. This class leverages the <see cref="Org.BouncyCastle.Math.BigInteger"/>
    /// class for handling large numbers during conversion.
    /// </remarks>
    public abstract class Base58Converter
    {
        static readonly int[] Base58Map = new int[256];

        static Base58Converter()
        {
            Array.Fill(Base58Map, -1);
            for (int i = 0; i < Constants.Base58Alphabet.Length; i++)
            {
                Base58Map[Constants.Base58Alphabet[i]] = i;
            }
        }

        /// <summary>
        /// Decodes a Base58-encoded string into its equivalent byte array.
        /// </summary>
        /// <param name="input">The Base58-encoded string to decode.</param>
        /// <returns>A byte array representing the decoded data.</returns>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="input"/> is null.</exception>
        /// <exception cref="FormatException">Thrown if <paramref name="input"/> contains invalid Base58 characters.</exception>
        /// <remarks>
        /// This method converts a Base58 string to a <see cref="BigInteger"/> using the Base58 alphabet and then
        /// returns the unsigned byte array representation of the number.
        /// </remarks>
        public static byte[] Decode(string input)
        {
            var bigInt = Base58ToBigInteger(input);
            return bigInt.ToByteArrayUnsigned();
        }

        /// <summary>
        /// Encodes a byte array into a Base58-encoded string without preserving leading zeros.
        /// </summary>
        /// <param name="input">The byte array to encode.</param>
        /// <returns>A Base58-encoded string representing the input data.</returns>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="input"/> is null.</exception>
        /// <remarks>
        /// This method converts the input byte array to a <see cref="BigInteger"/> and then encodes it
        /// into a Base58 string using the alphabet defined in <see cref="Constants.Base58Alphabet"/>.
        /// Leading zeros in the input are not preserved in the output.
        /// </remarks>
        public static string Encode(byte[] input)
        {
            var bigInt = new BigInteger(1, input);
            return BigIntegerToBase58(bigInt);
        }

        /// <summary>
        /// Encodes a byte array into a Base58-encoded string, preserving leading zeros as '1' characters.
        /// </summary>
        /// <param name="input">The byte array to encode.</param>
        /// <returns>A Base58-encoded string with leading zeros represented as '1' characters.</returns>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="input"/> is null.</exception>
        /// <remarks>
        /// This method is similar to <see cref="Encode(byte[])"/> but preserves leading zeros in the input byte array
        /// by prepending the output string with '1' characters for each leading zero byte. This is particularly useful
        /// for encoding blockchain addresses where leading zeros are significant.
        /// </remarks>
        public static string EncodeWithLeadingZeros(byte[] input)
        {
            // leading zero count
            int leadingZeros = 0;
            while (leadingZeros < input.Length && input[leadingZeros] == 0)
            {
                leadingZeros++;
            }

            // Residue conversion in Base58
            var bigInt = new BigInteger(1, input);
            string base58 = BigIntegerToBase58(bigInt);

            // Adding '1' characters behind leading zeros
            return new string('1', leadingZeros) + base58;
        }


        /// <summary>
        /// Converts a Base58-encoded string to a <see cref="BigInteger"/>.
        /// </summary>
        /// <param name="input">The Base58-encoded string to convert.</param>
        /// <returns>A <see cref="BigInteger"/> representing the decoded value.</returns>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="input"/> is null.</exception>
        /// <exception cref="FormatException">Thrown if <paramref name="input"/> contains invalid Base58 characters.</exception>
        /// <remarks>
        /// This method uses a precomputed mapping (<see cref="Base58Map"/>) to convert each character in the input string
        /// to its corresponding value in the Base58 alphabet, accumulating the result into a <see cref="BigInteger"/>.
        /// </remarks>
        static BigInteger Base58ToBigInteger(string input)
        {
            BigInteger result = BigInteger.Zero;
            foreach (char c in input)
            {
                int digit = Base58Map[c];
                if (digit < 0)
                {
                    throw new FormatException($"Invalid character in Base58: {c}");
                }
                result = result.Multiply(BigInteger.ValueOf(58)).Add(BigInteger.ValueOf(digit));
            }
            return result;
        }

        /// <summary>
        /// Converts a <see cref="BigInteger"/> to a Base58-encoded string.
        /// </summary>
        /// <param name="value">The <see cref="BigInteger"/> value to encode.</param>
        /// <returns>A Base58-encoded string representing the input value.</returns>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="value"/> is null.</exception>
        /// <remarks>
        /// This method repeatedly divides the input value by 58, collecting remainders to construct
        /// the Base58 string using the alphabet defined in <see cref="Constants.Base58Alphabet"/>.
        /// If the input value is zero, the method returns the first character of the Base58 alphabet.
        /// </remarks>
        static string BigIntegerToBase58(BigInteger value)
        {
            List<char> result = [];
            while (value.CompareTo(BigInteger.Zero) > 0)
            {
                int remainder = value.Mod(BigInteger.ValueOf(58)).IntValue;
                result.Insert(0, Constants.Base58Alphabet[remainder]);
                value = value.Divide(BigInteger.ValueOf(58));
            }
            return result.Count > 0 ? new string([.. result]) : Constants.Base58Alphabet[0].ToString();
        }
    }
}
