using Org.BouncyCastle.Math;
using System.Text;

namespace Saltant.AntelopeIO.Tools.Converters
{
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

        public static byte[] Decode(string input)
        {
            var bigInt = Base58ToBigInteger(input);
            return bigInt.ToByteArrayUnsigned();
        }

        public static string Encode(byte[] input)
        {
            var bigInt = new BigInteger(1, input);
            return BigIntegerToBase58(bigInt);
        }

        // Base58 encoding with leading zeros
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

        // Converting Base58 string to BigInteger using Base58Map
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

        // Converting BigInteger to Base58
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
